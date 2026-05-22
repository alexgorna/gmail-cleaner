import os
import json
import time
import uuid
import httplib2
import redis as redis_lib
import google_auth_httplib2
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, stream_with_context
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from tasks import run_inbox_scan
import ai_labeler

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_key_for_testing_only')

# --- CONFIGURATION & CONSTANTS ---
BATCH_SIZE = 18
BATCH_SLEEP_SECONDS = 0.2
MAX_RETRIES = 5
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
    http = httplib2.Http(timeout=30)
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


# --- AI LABEL SUGGESTIONS ---
@app.route('/api/suggest_labels', methods=['POST'])
def suggest_labels():
    if not ai_labeler.AI_LABELING_ENABLED:
        return jsonify({'error': 'AI labeling is disabled'}), 503

    if not get_creds():
        return jsonify({'error': 'Not logged in'}), 401

    job_id = session.get('scan_job_id')
    if not job_id:
        return jsonify({'error': 'No scan results available — run a scan first.'}), 400

    r = get_redis_client()
    results_raw = r.get(f'scan:{job_id}:results')
    if not results_raw:
        return jsonify({'error': 'Scan results expired — please scan again.'}), 400

    scan_data = json.loads(results_raw)
    senders = [item['email'] for item in scan_data]

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

    try:
        result = ai_labeler.suggest_labels(senders, label_names)
        return jsonify(result)
    except Exception as e:
        print(f"AI suggestion error: {e}")
        return jsonify({'error': str(e)}), 503


# --- APPLY ACTIONS ---
@app.route('/api/apply_actions', methods=['POST'])
def apply_actions():
    actions = request.json
    def generate_updates():
        service = get_service()
        if not service: return

        def execute_with_retry(req):
            for attempt in range(MAX_RETRIES):
                try: return req.execute()
                except: time.sleep(1 + attempt)
            raise Exception("Failed")

        yield json.dumps({"msg": "Starting actions..."}) + "\n"

        for item in actions:
            email = item['email']
            action_type = item['action']
            yield json.dumps({"msg": f"Processing: {email}..."}) + "\n"

            try:
                if action_type == 'delete':
                    msgs = []
                    token = None
                    while True:
                        res = execute_with_retry(service.users().messages().list(userId='me', q=f"from:{email}", maxResults=MAX_MESSAGES_PER_PAGE, pageToken=token))
                        msgs.extend(res.get('messages', []))
                        token = res.get('nextPageToken')
                        if not token: break

                    if msgs:
                        all_ids = [m['id'] for m in msgs]
                        for i in range(0, len(all_ids), BATCH_SIZE):
                            ids = all_ids[i:i + BATCH_SIZE]
                            try: execute_with_retry(service.users().messages().batchModify(userId='me', body={'ids': ids, 'addLabelIds': ['TRASH']}))
                            except: pass
                            time.sleep(BATCH_SLEEP_SECONDS)

                    yield json.dumps({"status": "row_complete", "email": email, "action": "delete", "msg": "  - Emails deleted."}) + "\n"

                elif action_type == 'label':
                    label_id = item['labelId']

                    filter_body = {'criteria': {'from': email}, 'action': {'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}}
                    try: execute_with_retry(service.users().settings().filters().create(userId='me', body=filter_body))
                    except: pass

                    msgs = []
                    token = None
                    while True:
                        res = execute_with_retry(service.users().messages().list(userId='me', q=f"in:inbox from:{email}", maxResults=MAX_MESSAGES_PER_PAGE, pageToken=token))
                        msgs.extend(res.get('messages', []))
                        token = res.get('nextPageToken')
                        if not token: break

                    if msgs:
                        all_ids = [m['id'] for m in msgs]
                        for i in range(0, len(all_ids), BATCH_SIZE):
                            ids = all_ids[i:i + BATCH_SIZE]
                            try: execute_with_retry(service.users().messages().batchModify(userId='me', body={'ids': ids, 'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}))
                            except: pass
                            time.sleep(BATCH_SLEEP_SECONDS)

                    yield json.dumps({"status": "row_complete", "email": email, "action": f"label:{label_id}", "msg": f"  - Moved {len(msgs)} emails."}) + "\n"
            except Exception as e:
                yield json.dumps({"msg": f"Error: {str(e)}"}) + "\n"

        yield json.dumps({"status": "complete"}) + "\n"

    return Response(stream_with_context(generate_updates()), mimetype='application/json')


if __name__ == '__main__':
    app.run(debug=True, port=5000)
