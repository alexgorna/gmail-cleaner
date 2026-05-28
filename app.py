import os
import json
import time
import uuid
import httplib2
import redis as redis_lib
import google_auth_httplib2
import concurrent.futures
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, stream_with_context
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from tasks import run_inbox_scan, run_ai_suggestions

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_key_for_testing_only')

# --- CONFIGURATION & CONSTANTS ---
BATCH_SIZE = 500          # Gmail batchModify supports up to 1000; 500 is safe
BATCH_SLEEP_SECONDS = 0   # No sleep needed with larger batches
MAX_RETRIES = 3           # Fail faster; smart backoff handles rate limits
MAX_MESSAGES_PER_PAGE = 500

if os.environ.get('ENVIRONMENT') != 'production':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

if os.environ.get('REDIS_URL'):
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis_lib.from_url(os.environ.get('REDIS_URL'))
else:
    app.config['SESSION_TYPE'] = 'filesystem'

Session(app)
csrf = CSRFProtect(app)

CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.settings.basic',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid'
]

if os.environ.get('GOOGLE_CLIENT_SECRETS_JSON'):
    with open('client_secret.json', 'w') as f:
        f.write(os.environ.get('GOOGLE_CLIENT_SECRETS_JSON'))


# --- HELPER FUNCTIONS ---
def get_redis_client():
    return redis_lib.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))

def get_creds():
    if 'credentials' not in session: return None
    creds = Credentials(**session['credentials'])
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            session['credentials'] = {
                'token': creds.token, 'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri, 'client_id': creds.client_id,
                'client_secret': creds.client_secret, 'scopes': creds.scopes
            }
        except Exception as e:
            print(f"Token refresh failed: {e}")
            return None
    return creds

def get_service():
    creds = get_creds()
    if not creds: return None
    http = httplib2.Http(timeout=10)  # 30s was too long; 10s fails fast so retries kick in sooner
    authorized_http = google_auth_httplib2.AuthorizedHttp(creds, http=http)
    return build('gmail', 'v1', http=authorized_http)


# --- ROUTES ---
@app.route('/')
def index():
    if not get_creds(): return render_template('login.html')
    return render_template('dashboard.html')

@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=redirect_uri)
    auth_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    session['state'] = state
    session['code_verifier'] = flow.code_verifier  # Persist PKCE verifier for callback
    return redirect(auth_url)

@app.route('/callback')
def callback():
    if not session.get('state') or request.args.get('state') != session['state']:
        return "Invalid state parameter", 400

    # Railway terminates SSL at its proxy; force https so oauthlib accepts the URL.
    auth_response = request.url
    if auth_response.startswith('http://'):
        auth_response = 'https://' + auth_response[7:]

    redirect_uri = url_for('callback', _external=True)

    try:
        flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=redirect_uri, state=session['state'])
        flow.code_verifier = session.get('code_verifier')  # Restore PKCE verifier for token exchange
        flow.fetch_token(authorization_response=auth_response)
    except Exception as e:
        print(f"OAuth callback error: {type(e).__name__}: {e}")
        session['login_error'] = f"Login failed ({type(e).__name__}). Please try again."
        return redirect(url_for('index'))

    creds = flow.credentials
    session['credentials'] = {
        'token': creds.token, 'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri, 'client_id': creds.client_id,
        'client_secret': creds.client_secret, 'scopes': creds.scopes
    }
    try:
        user_service = build('oauth2', 'v2', credentials=creds)
        session['user_info'] = user_service.userinfo().get().execute()
    except: pass
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/user_info')
def api_user_info():
    data = session.get('user_info', {})
    if isinstance(data, dict):
        data['session_storage'] = app.config.get('SESSION_TYPE', 'unknown')
    return jsonify(data)

@app.route('/api/get_labels')
def get_labels():
    service = get_service()
    if not service: return jsonify([])
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        labels.sort(key=lambda x: x['name'].lower())
        return jsonify(labels)
    except: return jsonify([])

@app.route('/api/create_label', methods=['POST'])
def create_label():
    service = get_service()
    if not service: return jsonify({'error': 'Auth failed'}), 401

    data = request.json
    name = data.get('name')
    parent_id = data.get('parentId')

    if parent_id and data.get('parentName'):
        full_name = f"{data['parentName']}/{name}"
    else:
        full_name = name

    try:
        label_object = {'name': full_name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'}
        created = service.users().labels().create(userId='me', body=label_object).execute()
        return jsonify(created)
    except HttpError as error:
        if error.resp.status == 409:  # Already exists
            try:
                results = service.users().labels().list(userId='me').execute()
                for l in results.get('labels', []):
                    if l['name'].lower() == full_name.lower():
                        return jsonify(l)
            except: pass
        return jsonify({'error': str(error)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- SCAN ENDPOINTS (background job) ---
@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    if not get_creds():
        return jsonify({'error': 'Not logged in'}), 401
    job_id = str(uuid.uuid4())
    session['scan_job_id'] = job_id
    credentials_dict = session.get('credentials')
    run_inbox_scan.delay(job_id, credentials_dict)
    return jsonify({'job_id': job_id})

@app.route('/api/scan_status/<job_id>')
def scan_status(job_id):
    if session.get('scan_job_id') != job_id:
        return jsonify({'error': 'unauthorized'}), 403
    r = get_redis_client()
    progress_raw = r.get(f'scan:{job_id}:progress')
    if not progress_raw:
        return jsonify({'status': 'pending'})
    progress = json.loads(progress_raw)
    log_offset = int(request.args.get('log_offset', 0))
    logs_raw = r.lrange(f'scan:{job_id}:logs', log_offset, -1)
    logs = [json.loads(l) for l in logs_raw]
    progress['logs'] = logs
    progress['log_offset'] = log_offset + len(logs)
    return jsonify(progress)

@app.route('/api/scan_results/<job_id>')
def scan_results(job_id):
    if session.get('scan_job_id') != job_id:
        return jsonify({'error': 'unauthorized'}), 403
    r = get_redis_client()
    results_raw = r.get(f'scan:{job_id}:results')
    if not results_raw:
        return jsonify({'error': 'Results not found'}), 404
    return jsonify(json.loads(results_raw))


# --- AI LABEL SUGGESTIONS (async — runs in Celery worker) ---
@app.route('/api/suggest_labels', methods=['POST'])
def suggest_labels():
    if not get_creds():
        return jsonify({'error': 'Not logged in'}), 401

    # Always load scan results so we can enrich senders with subjects.
    r = get_redis_client()
    scan_data = None
    scan_job_id = session.get('scan_job_id')
    if scan_job_id:
        results_raw = r.get(f'scan:{scan_job_id}:results')
        if results_raw:
            scan_data = json.loads(results_raw)

    # Accept an explicit sender list (displayed rows) from the frontend,
    # falling back to the full scan results if none provided.
    body = request.json or {}
    senders = body.get('senders')

    if not senders:
        if not scan_data:
            return jsonify({'error': 'No scan results available — run a scan first.'}), 400
        senders = [item['email'] for item in scan_data]

    # Enrich each sender with up to 3 representative subjects for better AI context
    subjects_map = {item['email']: item.get('subjects', []) for item in (scan_data or [])}
    senders_with_subjects = [
        {'email': email, 'subjects': subjects_map.get(email, [])}
        for email in senders
    ]

    # Fetch the user's current label list from Gmail
    label_names = []
    try:
        service = get_service()
        if service:
            label_results = service.users().labels().list(userId='me').execute()
            label_names = [
                l['name'] for l in label_results.get('labels', [])
                if l.get('type') == 'user'
            ]
    except Exception as e:
        print(f"Label fetch for AI failed: {e}")

    ai_job_id = str(uuid.uuid4())
    session['ai_job_id'] = ai_job_id
    run_ai_suggestions.delay(ai_job_id, senders_with_subjects, label_names)
    print(f"[suggest_labels] Queued job {ai_job_id} — {len(senders_with_subjects)} senders, {len(label_names)} labels")
    return jsonify({'job_id': ai_job_id, 'senders_sent': len(senders_with_subjects)})


@app.route('/api/ai_status/<job_id>')
def ai_status(job_id):
    if session.get('ai_job_id') != job_id:
        return jsonify({'error': 'unauthorized'}), 403
    r = get_redis_client()
    raw = r.get(f'ai:{job_id}:status')
    if not raw:
        return jsonify({'status': 'pending'})
    return jsonify(json.loads(raw))


@app.route('/api/ai_results/<job_id>')
def ai_results(job_id):
    if session.get('ai_job_id') != job_id:
        return jsonify({'error': 'unauthorized'}), 403
    r = get_redis_client()
    raw = r.get(f'ai:{job_id}:result')
    if not raw:
        return jsonify({'error': 'Results not found'}), 404
    return jsonify(json.loads(raw))


# --- APPLY ACTIONS ---
PARALLEL_WORKERS = 5  # Process this many senders simultaneously

@app.route('/api/apply_actions', methods=['POST'])
def apply_actions():
    actions = request.json
    # Capture credentials before entering the generator — Flask session not available in threads
    creds_data = session.get('credentials')
    if not creds_data:
        return jsonify({'error': 'Not logged in'}), 401

    def generate_updates():

        def make_service():
            """Each worker thread gets its own HTTP connection and service object."""
            http = httplib2.Http(timeout=20)
            from google.oauth2.credentials import Credentials as OAuthCreds
            creds = OAuthCreds(**creds_data)
            authorized_http = google_auth_httplib2.AuthorizedHttp(creds, http=http)
            return build('gmail', 'v1', http=authorized_http)

        def exec_retry(service, req):
            for attempt in range(MAX_RETRIES):
                try:
                    return req.execute()
                except HttpError as e:
                    if e.resp.status in (429, 500, 503):
                        time.sleep(min(2 ** attempt, 8))
                    else:
                        raise
                except Exception:
                    time.sleep(min(2 ** attempt, 8))
            raise Exception(f"Gmail API call failed after {MAX_RETRIES} retries")

        def process_item(item):
            """Run in a worker thread — builds its own service to avoid shared-state issues."""
            service = make_service()
            email = item['email']
            action_type = item['action']

            try:
                if action_type == 'delete':
                    msgs = []
                    token = None
                    while True:
                        res = exec_retry(service, service.users().messages().list(
                            userId='me', q=f"from:{email}",
                            maxResults=MAX_MESSAGES_PER_PAGE, pageToken=token))
                        msgs.extend(res.get('messages', []))
                        token = res.get('nextPageToken')
                        if not token: break

                    if msgs:
                        all_ids = [m['id'] for m in msgs]
                        batches = [all_ids[i:i + BATCH_SIZE] for i in range(0, len(all_ids), BATCH_SIZE)]
                        for ids in batches:
                            try: exec_retry(service, service.users().messages().batchModify(
                                userId='me', body={'ids': ids, 'addLabelIds': ['TRASH']}))
                            except: pass

                    return {"status": "row_complete", "email": email, "action": "delete",
                            "msg": f"  - {email}: {len(msgs)} emails deleted."}

                elif action_type == 'label':
                    label_id = item['labelId']
                    skip_inbox = item.get('skipInbox', True)
                    auto_label = item.get('autoLabel', True)

                    if auto_label:
                        filter_action = {'addLabelIds': [label_id]}
                        if skip_inbox:
                            filter_action['removeLabelIds'] = ['INBOX']
                        filter_body = {'criteria': {'from': email}, 'action': filter_action}
                        try: exec_retry(service, service.users().settings().filters().create(
                            userId='me', body=filter_body))
                        except: pass

                    msgs = []
                    token = None
                    while True:
                        res = exec_retry(service, service.users().messages().list(
                            userId='me', q=f"in:inbox from:{email}",
                            maxResults=MAX_MESSAGES_PER_PAGE, pageToken=token))
                        msgs.extend(res.get('messages', []))
                        token = res.get('nextPageToken')
                        if not token: break

                    if msgs:
                        all_ids = [m['id'] for m in msgs]
                        modify_body = {'addLabelIds': [label_id]}
                        if skip_inbox:
                            modify_body['removeLabelIds'] = ['INBOX']
                        batches = [all_ids[i:i + BATCH_SIZE] for i in range(0, len(all_ids), BATCH_SIZE)]
                        for ids in batches:
                            try: exec_retry(service, service.users().messages().batchModify(
                                userId='me', body={**modify_body, 'ids': ids}))
                            except: pass

                    return {"status": "row_complete", "email": email,
                            "action": f"label:{label_id}",
                            "msg": f"  - {email}: labelled {len(msgs)} emails."}

                else:
                    return {"status": "row_complete", "email": email,
                            "action": action_type, "msg": f"  - {email}: skipped."}

            except Exception as e:
                return {"status": "row_complete", "email": email,
                        "action": "error", "msg": f"  - {email}: error — {str(e)}"}

        yield json.dumps({"msg": f"Starting {len(actions)} actions ({PARALLEL_WORKERS} parallel)..."}) + "\n"

        with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as executor:
            future_to_email = {executor.submit(process_item, item): item['email'] for item in actions}
            for future in concurrent.futures.as_completed(future_to_email):
                try:
                    result = future.result()
                except Exception as e:
                    email = future_to_email[future]
                    result = {"status": "row_complete", "email": email,
                              "action": "error", "msg": f"  - Error: {str(e)}"}
                yield json.dumps(result) + "\n"

        yield json.dumps({"status": "complete"}) + "\n"

    return Response(stream_with_context(generate_updates()), mimetype='application/json')


# ── LABEL MANAGER ─────────────────────────────────────────────────────────────

def build_label_tree(labels):
    """Build nested tree from flat Gmail label list using '/' as separator."""
    sorted_labels = sorted(labels, key=lambda x: x['name'].lower())
    nodes = {}
    roots = []
    for label in sorted_labels:
        name = label['name']
        parts = name.split('/')
        node = {
            'id': label['id'],
            'name': parts[-1],
            'fullName': name,
            'messagesTotal': label.get('messagesTotal', 0),
            'messagesUnread': label.get('messagesUnread', 0),
            'children': []
        }
        nodes[name] = node
        if len(parts) > 1:
            parent_name = '/'.join(parts[:-1])
            if parent_name in nodes:
                nodes[parent_name]['children'].append(node)
            else:
                roots.append(node)
        else:
            roots.append(node)
    return roots


@app.route('/labels')
def labels_page():
    if not get_creds():
        return redirect(url_for('index'))
    return render_template('labels.html')


@app.route('/api/labels_tree')
def api_labels_tree():
    service = get_service()
    if not service:
        return jsonify({'error': 'Not logged in'}), 401
    try:
        results = service.users().labels().list(userId='me').execute()
        user_labels = [l for l in results.get('labels', []) if l.get('type') == 'user']
        tree = build_label_tree(user_labels)
        flat = {l['id']: l for l in user_labels}
        return jsonify({'tree': tree, 'flat': flat})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/labels/rename', methods=['POST'])
def api_label_rename():
    data = request.json
    label_id = data['labelId']
    new_full_name = data['newFullName']
    service = get_service()
    if not service:
        return jsonify({'error': 'Not logged in'}), 401
    try:
        current = service.users().labels().get(userId='me', id=label_id).execute()
        old_full_name = current['name']

        all_labels = service.users().labels().list(userId='me').execute().get('labels', [])
        children = [l for l in all_labels if l.get('type') == 'user'
                    and l['name'].startswith(old_full_name + '/') and l['id'] != label_id]

        def rename_child(child):
            suffix = child['name'][len(old_full_name):]
            new_child_name = new_full_name + suffix
            return service.users().labels().patch(
                userId='me', id=child['id'], body={'name': new_child_name}
            ).execute()

        if children:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                list(executor.map(rename_child, children))

        updated = service.users().labels().patch(
            userId='me', id=label_id, body={'name': new_full_name}
        ).execute()
        return jsonify({'success': True, 'label': updated, 'childrenRenamed': len(children)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/labels/delete', methods=['POST'])
def api_label_delete():
    data = request.json
    label_id = data['labelId']
    cascade = data.get('cascade', False)
    service = get_service()
    if not service:
        return jsonify({'error': 'Not logged in'}), 401
    try:
        current = service.users().labels().get(userId='me', id=label_id).execute()
        old_full_name = current['name']

        if cascade:
            all_labels = service.users().labels().list(userId='me').execute().get('labels', [])
            children = [l for l in all_labels if l.get('type') == 'user'
                        and l['name'].startswith(old_full_name + '/')]
            for child in children:
                try:
                    service.users().labels().delete(userId='me', id=child['id']).execute()
                except Exception:
                    pass

        service.users().labels().delete(userId='me', id=label_id).execute()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/labels/ai_reorganize', methods=['POST'])
def api_ai_reorganize():
    service = get_service()
    if not service:
        return jsonify({'error': 'Not logged in'}), 401
    try:
        from openai import OpenAI
        results = service.users().labels().list(userId='me').execute()
        user_labels = [l for l in results.get('labels', []) if l.get('type') == 'user']
        label_names = sorted([l['name'] for l in user_labels])
        name_to_id = {l['name']: l['id'] for l in user_labels}

        label_list = '\n'.join(f'- {n}' for n in label_names)

        client = OpenAI(
            api_key=os.environ.get('DEEPSEEK_API_KEY'),
            base_url='https://api.deepseek.com'
        )
        response = client.chat.completions.create(
            model='deepseek-chat',
            temperature=0.3,
            max_tokens=2000,
            messages=[
                {'role': 'system', 'content': 'You are a Gmail label organizer. Return only valid JSON arrays, no markdown.'},
                {'role': 'user', 'content': f"""Analyze these Gmail labels and suggest up to 10 improvements:

{label_list}

Return a JSON array. Each element must be one of these shapes:

Merge duplicates:
{{"type":"merge","description":"short description","reason":"why","params":{{"sourceNames":["A","B"],"targetName":"C"}}}}

Rename for consistency:
{{"type":"rename","description":"short description","reason":"why","params":{{"oldName":"A","newName":"B"}}}}

Move to better parent:
{{"type":"move","description":"short description","reason":"why","params":{{"labelName":"A","newParentName":"B"}}}}

Group flat labels under new parent:
{{"type":"group","description":"short description","reason":"why","params":{{"newParentName":"A","childNames":["B","C","D"]}}}}

Rules:
- Only reference label names that appear in the list above exactly as written
- For merge: sourceNames are deleted and their messages moved to targetName
- For group: childNames are moved under newParentName (create it if it doesn't exist)
- Prioritize: 1) merge near-duplicates 2) language/case standardization 3) hierarchy improvements
- Return ONLY the JSON array"""}
            ]
        )

        raw = response.choices[0].message.content.strip()
        if '```' in raw:
            raw = raw.split('```')[1]
            if raw.startswith('json'):
                raw = raw[4:]
        raw = raw.strip()

        suggestions = json.loads(raw)

        # Attach IDs where we can resolve them upfront
        for sug in suggestions:
            p = sug.get('params', {})
            if sug['type'] == 'rename':
                p['labelId'] = name_to_id.get(p.get('oldName'))
            elif sug['type'] == 'move':
                p['labelId'] = name_to_id.get(p.get('labelName'))
            elif sug['type'] == 'merge':
                p['sourceIds'] = [name_to_id[n] for n in p.get('sourceNames', []) if n in name_to_id]
                p['targetId'] = name_to_id.get(p.get('targetName'))

        return jsonify({'suggestions': suggestions, 'totalLabels': len(user_labels)})
    except json.JSONDecodeError as e:
        return jsonify({'error': f'AI returned invalid JSON: {e}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/labels/apply_plan', methods=['POST'])
def api_labels_apply_plan():
    data = request.json
    operations = data.get('operations', [])
    if not operations:
        return jsonify({'error': 'No operations provided'}), 400

    def generate():
        service = get_service()
        if not service:
            yield json.dumps({'error': 'Not logged in'}) + '\n'
            return

        yield json.dumps({'msg': f'Starting {len(operations)} operation(s)…'}) + '\n'

        # Build live name→label map (refreshed after each op)
        def get_label_map():
            res = service.users().labels().list(userId='me').execute()
            all_l = [l for l in res.get('labels', []) if l.get('type') == 'user']
            return {l['name']: l for l in all_l}, {l['id']: l for l in all_l}

        name_map, id_map = get_label_map()

        for op in operations:
            op_type = op.get('type')
            p = op.get('params', {})
            try:
                if op_type == 'rename':
                    old_name = p.get('oldName')
                    new_name = p.get('newName')
                    label = name_map.get(old_name)
                    if not label:
                        yield json.dumps({'msg': f'  ⚠ Rename: "{old_name}" not found, skipping.'}) + '\n'
                        continue
                    # Cascade to children
                    children = [(n, l) for n, l in name_map.items() if n.startswith(old_name + '/')]
                    for child_name, child_label in children:
                        new_child = new_name + child_name[len(old_name):]
                        service.users().labels().patch(userId='me', id=child_label['id'], body={'name': new_child}).execute()
                    service.users().labels().patch(userId='me', id=label['id'], body={'name': new_name}).execute()
                    yield json.dumps({'status': 'op_complete', 'type': op_type,
                                      'msg': f'  ✓ Renamed "{old_name}" → "{new_name}"'}) + '\n'

                elif op_type == 'move':
                    label_name = p.get('labelName')
                    new_parent = p.get('newParentName', '')
                    label = name_map.get(label_name)
                    if not label:
                        yield json.dumps({'msg': f'  ⚠ Move: "{label_name}" not found, skipping.'}) + '\n'
                        continue
                    short = label_name.split('/')[-1]
                    new_full = f'{new_parent}/{short}' if new_parent else short
                    children = [(n, l) for n, l in name_map.items() if n.startswith(label_name + '/')]
                    for child_name, child_label in children:
                        new_child = new_full + child_name[len(label_name):]
                        service.users().labels().patch(userId='me', id=child_label['id'], body={'name': new_child}).execute()
                    service.users().labels().patch(userId='me', id=label['id'], body={'name': new_full}).execute()
                    yield json.dumps({'status': 'op_complete', 'type': op_type,
                                      'msg': f'  ✓ Moved "{label_name}" → "{new_full}"'}) + '\n'

                elif op_type == 'merge':
                    source_names = p.get('sourceNames', [])
                    target_name = p.get('targetName')
                    # Ensure target label exists
                    target_label = name_map.get(target_name)
                    if not target_label:
                        target_label = service.users().labels().create(
                            userId='me', body={'name': target_name,
                                               'labelListVisibility': 'labelShow',
                                               'messageListVisibility': 'show'}
                        ).execute()
                        yield json.dumps({'msg': f'  + Created label "{target_name}"'}) + '\n'

                    merged = 0
                    for src_name in source_names:
                        if src_name == target_name:
                            continue
                        src = name_map.get(src_name)
                        if not src:
                            continue
                        # Find all messages with source label
                        msgs = []
                        token = None
                        while True:
                            res = service.users().messages().list(
                                userId='me', labelIds=[src['id']], maxResults=MAX_MESSAGES_PER_PAGE, pageToken=token
                            ).execute()
                            msgs.extend(res.get('messages', []))
                            token = res.get('nextPageToken')
                            if not token:
                                break
                        if msgs:
                            all_ids = [m['id'] for m in msgs]
                            for i in range(0, len(all_ids), BATCH_SIZE):
                                batch = all_ids[i:i + BATCH_SIZE]
                                service.users().messages().batchModify(
                                    userId='me',
                                    body={'ids': batch,
                                          'addLabelIds': [target_label['id']],
                                          'removeLabelIds': [src['id']]}
                                ).execute()
                        service.users().labels().delete(userId='me', id=src['id']).execute()
                        merged += len(msgs)

                    yield json.dumps({'status': 'op_complete', 'type': op_type,
                                      'msg': f'  ✓ Merged {len(source_names)} label(s) into "{target_name}" ({merged} messages)'}) + '\n'

                elif op_type == 'group':
                    new_parent_name = p.get('newParentName')
                    child_names = p.get('childNames', [])
                    # Create parent if needed
                    if new_parent_name not in name_map:
                        service.users().labels().create(
                            userId='me', body={'name': new_parent_name,
                                               'labelListVisibility': 'labelShow',
                                               'messageListVisibility': 'show'}
                        ).execute()
                        yield json.dumps({'msg': f'  + Created parent "{new_parent_name}"'}) + '\n'
                    for child_name in child_names:
                        child = name_map.get(child_name)
                        if not child:
                            continue
                        short = child_name.split('/')[-1]
                        new_child_full = f'{new_parent_name}/{short}'
                        service.users().labels().patch(userId='me', id=child['id'], body={'name': new_child_full}).execute()
                    yield json.dumps({'status': 'op_complete', 'type': op_type,
                                      'msg': f'  ✓ Grouped {len(child_names)} label(s) under "{new_parent_name}"'}) + '\n'

                # Refresh label map after each op so subsequent ops see current state
                name_map, id_map = get_label_map()

            except Exception as e:
                yield json.dumps({'msg': f'  ✗ Error in {op_type}: {e}'}) + '\n'

        yield json.dumps({'status': 'complete', 'msg': 'Done.'}) + '\n'

    return Response(stream_with_context(generate()), mimetype='application/json')


if __name__ == '__main__':
    app.run(debug=True, port=5000)
