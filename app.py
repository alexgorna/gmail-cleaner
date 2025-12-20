import os
import json
import re
import time
import httplib2
import redis
import google_auth_httplib2
from collections import Counter
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, stream_with_context
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_key_for_testing_only')

# --- CONFIGURATION & CONSTANTS ---
BATCH_SIZE = 18              
BATCH_SLEEP_SECONDS = 0.2    
MAX_RETRIES = 5              
MAX_MESSAGES_PER_PAGE = 500  
MAX_INBOX_SCAN_LIMIT = 5000  

if os.environ.get('ENVIRONMENT') != 'production':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

if os.environ.get('REDIS_URL'):
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis.from_url(os.environ.get('REDIS_URL'))
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
    return redirect(auth_url)

@app.route('/callback')
def callback():
    if not session.get('state') or request.args.get('state') != session['state']:
        return "Invalid state parameter", 400
    redirect_uri = url_for('callback', _external=True)
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=redirect_uri, state=session['state'])
    flow.fetch_token(authorization_response=request.url)
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
        if error.resp.status == 409: # Already exists
            try:
                results = service.users().labels().list(userId='me').execute()
                for l in results.get('labels', []):
                    if l['name'].lower() == full_name.lower():
                        return jsonify(l)
            except: pass
        return jsonify({'error': str(error)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan_stream')
@csrf.exempt 
def scan_stream():
    if not get_creds(): 
        return Response("data: " + json.dumps({'error': 'Not logged in'}) + "\n\n", mimetype='text/event-stream')

    def generate():
        service = get_service()
        if not service:
            yield f"data: {json.dumps({'error': 'Authentication expired.'})}\n\n"
            return

        messages = []
        yield f"data: {json.dumps({'status': 'init', 'message': 'Connecting to Gmail...'})}\n\n"
        
        request = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=MAX_MESSAGES_PER_PAGE)
        
        page_num = 1
        while request is not None:
            page_success = False
            for attempt in range(MAX_RETRIES):
                try:
                    response = request.execute()
                    msgs = response.get('messages', [])
                    messages.extend(msgs)
                    yield f"data: {json.dumps({'status': 'counting', 'count': len(messages)})}\n\n"
                    
                    if len(messages) > MAX_INBOX_SCAN_LIMIT:
                        yield f"data: {json.dumps({'error': f'Inbox too large ({len(messages)}+). Limit is {MAX_INBOX_SCAN_LIMIT}.'})}\n\n"
                        return

                    request = service.users().messages().list_next(request, response)
                    page_success = True
                    break 
                except: time.sleep(2 ** attempt)
            
            if not page_success: return
            page_num += 1

        total_messages = len(messages)
        yield f"data: {json.dumps({'log': f'Found {total_messages} emails. Scanning...'})}\n\n"
        
        if total_messages == 0:
            yield f"data: {json.dumps({'status': 'complete', 'data': []})}\n\n"
            return

        senders = []
        total_batches = (total_messages // BATCH_SIZE) + (1 if total_messages % BATCH_SIZE > 0 else 0)
        
        for i in range(0, total_messages, BATCH_SIZE):
            chunk = messages[i:i + BATCH_SIZE]
            current_batch_num = (i // BATCH_SIZE) + 1
            batch = service.new_batch_http_request()
            
            def batch_callback(request_id, response, exception):
                if exception is None:
                    headers = response['payload']['headers']
                    from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                    match = re.search(r'<(.+?)>', from_header)
                    clean_email = match.group(1) if match else from_header
                    senders.append(clean_email.lower().strip())

            for msg in chunk:
                batch.add(service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From']), callback=batch_callback)
            
            try: batch.execute()
            except: pass
            
            if current_batch_num % 5 == 0:
                yield f"data: {json.dumps({'log': f'Batch {current_batch_num}/{total_batches} processed.'})}\n\n"

            progress = int((min(i + BATCH_SIZE, total_messages) / total_messages) * 100)
            yield f"data: {json.dumps({'status': 'progress', 'percent': progress})}\n\n"
            time.sleep(BATCH_SLEEP_SECONDS)

        if senders:
            counts = Counter(senders)
            result_data = [{'email': email, 'count': count} for email, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
        else:
            result_data = []
            
        yield f"data: {json.dumps({'status': 'complete', 'data': result_data})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

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
            time.sleep(BATCH_SLEEP_SECONDS) 

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
                    yield json.dumps({"msg": "  - Emails deleted."}) + "\n"

                elif action_type == 'label':
                    label_id = item['labelId']
                    
                    filter_body = {'criteria': {'from': email}, 'action': {'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}}
                    try: execute_with_retry(service.users().settings().filters().create(userId='me', body=filter_body))
                    except: pass

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
                            try: execute_with_retry(service.users().messages().batchModify(userId='me', body={'ids': ids, 'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}))
                            except: pass
                            time.sleep(BATCH_SLEEP_SECONDS)
                        yield json.dumps({"msg": f"  - Moved {len(msgs)} emails."}) + "\n"
            except Exception as e:
                yield json.dumps({"msg": f"Error: {str(e)}"}) + "\n"
        
        yield json.dumps({"status": "complete"}) + "\n"

    return Response(stream_with_context(generate_updates()), mimetype='application/json')

if __name__ == '__main__':
    app.run(debug=True, port=5000)