import os
import json
import pandas as pd
import re
import time
import httplib2
import redis
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

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_key_for_testing_only')

# --- CONFIGURATION & CONSTANTS ---

# API Rate Limiting & Pagination Constants
BATCH_SIZE = 18              # Safe limit for batch requests
BATCH_SLEEP_SECONDS = 0.2    # Rate limiting pause
MAX_RETRIES = 5              # Connection retry attempts
MAX_MESSAGES_PER_PAGE = 500  # Max Gmail IDs to fetch per list request

# OAuth Security Risk - Only enable insecure transport in dev
if os.environ.get('ENVIRONMENT') != 'production':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

# Session Storage Configuration
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

if os.environ.get('REDIS_URL'):
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis.from_url(os.environ.get('REDIS_URL'))
else:
    app.config['SESSION_TYPE'] = 'filesystem'

Session(app)

# FIX 1: Initialize CSRF but exempt specific endpoints
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

# --- AUTH HELPER FUNCTIONS ---

def get_creds():
    if 'credentials' not in session: 
        return None
    creds = Credentials(**session['credentials'])
    
    # Auto-refresh expired tokens
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            # Update session with new token
            session['credentials'] = {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
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
    # FIX 2: State Validation (CSRF Protection for OAuth)
    if not session.get('state') or request.args.get('state') != session['state']:
        return "Invalid state parameter (Possible CSRF attack)", 400

    redirect_uri = url_for('callback', _external=True)
    # Pass state to flow to ensure validation matches
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
        user_info = user_service.userinfo().get().execute()
        session['user_info'] = user_info
    except Exception as e:
        print(f"Could not fetch user info: {e}")
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
    except Exception as e:
        print(f"Error fetching labels: {e}")
        return jsonify([])

# --- CORE LOGIC STREAMS ---

@app.route('/api/scan_stream')
@csrf.exempt  # FIX 1: Exempt SSE endpoint
def scan_stream():
    if not get_creds(): 
        return Response("data: " + json.dumps({'error': 'Not logged in'}) + "\n\n", mimetype='text/event-stream')

    def generate():
        service = get_service()
        # FIX 3: Null Safety Check
        if not service:
            yield f"data: {json.dumps({'error': 'Authentication expired. Please log in again.'})}\n\n"
            return

        messages = []
        yield f"data: {json.dumps({'status': 'init', 'message': 'Connecting to Gmail...', 'log': 'Starting connection to Gmail API...'})}\n\n"
        
        # Phase 1: List Messages
        request = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=MAX_MESSAGES_PER_PAGE)
        
        page_num = 1
        while request is not None:
            page_success = False
            for attempt in range(MAX_RETRIES):
                try:
                    response = request.execute()
                    msgs = response.get('messages', [])
                    messages.extend(msgs)
                    yield f"data: {json.dumps({'status': 'counting', 'count': len(messages), 'log': f'Fetched page {page_num} ({len(msgs)} items). Total: {len(messages)}'})}\n\n"
                    request = service.users().messages().list_next(request, response)
                    page_success = True
                    break 
                except Exception as e:
                    yield f"data: {json.dumps({'log': f'Page {page_num} failed: {str(e)}. Retrying ({attempt+1}/{MAX_RETRIES})...', 'level': 'warn'})}\n\n"
                    time.sleep(2 ** attempt)
            
            if not page_success:
                yield f"data: {json.dumps({'error': 'CRITICAL: Failed to fetch full email list after retries.'})}\n\n"
                return
            page_num += 1

        total_messages = len(messages)
        yield f"data: {json.dumps({'log': f'List complete. Found {total_messages} emails. Starting Detail Scan...', 'level': 'success'})}\n\n"
        
        if total_messages == 0:
            yield f"data: {json.dumps({'status': 'complete', 'data': []})}\n\n"
            return

        # Phase 2: Fetch Details
        senders = []
        total_batches = (total_messages // BATCH_SIZE) + 1
        
        for i in range(0, total_messages, BATCH_SIZE):
            chunk = messages[i:i + BATCH_SIZE]
            current_batch_num = (i // BATCH_SIZE) + 1
            batch_failures = [] 
            first_error_msg = None
            
            batch = service.new_batch_http_request()
            
            def batch_callback(request_id, response, exception):
                nonlocal first_error_msg
                if exception is not None:
                    batch_failures.append(request_id)
                    if not first_error_msg: first_error_msg = str(exception)
                else:
                    headers = response['payload']['headers']
                    from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                    match = re.search(r'<(.+?)>', from_header)
                    clean_email = match.group(1) if match else from_header
                    senders.append(clean_email.lower().strip())

            for msg in chunk:
                batch.add(service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From']), 
                          callback=batch_callback,
                          request_id=msg['id'])
            
            batch_success = False
            for attempt in range(MAX_RETRIES):
                try:
                    batch.execute()
                    batch_success = True
                    break 
                except Exception as e:
                    yield f"data: {json.dumps({'log': f'Batch {current_batch_num} connection failed: {str(e)}. Retrying...', 'level': 'error'})}\n\n"
                    time.sleep(2 ** attempt)
            
            if not batch_success:
                 yield f"data: {json.dumps({'log': f'CRITICAL: Batch {current_batch_num} dropped completely.', 'level': 'error'})}\n\n"

            # Repair Loop
            if batch_failures:
                yield f"data: {json.dumps({'log': f'Batch {current_batch_num}: {len(batch_failures)} items hit rate limit. Repairing...', 'level': 'warn'})}\n\n"
                
                count_repaired = 0
                for failed_id in batch_failures:
                    count_repaired += 1
                    time.sleep(0.3) 
                    
                    retry_success = False
                    for retry_att in range(3):
                        try:
                            msg_detail = service.users().messages().get(userId='me', id=failed_id, format='metadata', metadataHeaders=['From']).execute()
                            headers = msg_detail['payload']['headers']
                            from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                            match = re.search(r'<(.+?)>', from_header)
                            clean_email = match.group(1) if match else from_header
                            senders.append(clean_email.lower().strip())
                            retry_success = True
                            break
                        except Exception:
                            time.sleep(1)
                    
                    if not retry_success:
                         yield f"data: {json.dumps({'log': f'Permanently failed to fetch message {failed_id}.', 'level': 'error'})}\n\n"

                    current_absolute = i + (len(chunk) - len(batch_failures)) + count_repaired
                    current_percent = int((current_absolute / total_messages) * 100)
                    yield f"data: {json.dumps({'status': 'progress', 'processed': current_absolute, 'total': total_messages, 'percent': current_percent})}\n\n"
            
            else:
                if current_batch_num % 5 == 0:
                    yield f"data: {json.dumps({'log': f'Batch {current_batch_num}/{total_batches} processed perfectly.'})}\n\n"

            processed_count = min(i + BATCH_SIZE, total_messages)
            progress_data = {
                'status': 'progress',
                'processed': processed_count,
                'total': total_messages,
                'percent': int((processed_count / total_messages) * 100)
            }
            yield f"data: {json.dumps(progress_data)}\n\n"
            
            time.sleep(BATCH_SLEEP_SECONDS)

        # Phase 3: Aggregate
        df = pd.DataFrame(senders, columns=['email'])
        if not df.empty:
            counts = df['email'].value_counts().reset_index()
            counts.columns = ['email', 'count']
            counts = counts.sort_values(by=['count', 'email'], ascending=[False, True])
            result_data = counts.to_dict(orient='records')
        else:
            result_data = []
            
        yield f"data: {json.dumps({'status': 'complete', 'data': result_data, 'log': 'Analysis Complete. Rendering table...', 'level': 'success'})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/apply_actions', methods=['POST'])
def apply_actions():
    actions = request.json 
    def generate_updates():
        service = get_service()
        # FIX 3: Null Safety Check
        if not service:
            yield json.dumps({"msg": "ERROR: Authentication failed. Please reload and login."}) + "\n"
            return

        # FIX 7: Consistent Retry Logic using Constants
        def execute_with_retry(request_obj):
            for attempt in range(MAX_RETRIES):
                try:
                    return request_obj.execute()
                except Exception as e:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(1 + attempt)
                    else:
                        raise Exception(f"Request failed after {MAX_RETRIES} retries: {str(e)}")

        yield json.dumps({"msg": "Starting to process actions..."}) + "\n"

        for item in actions:
            email = item['email']
            action_type = item['action']
            yield json.dumps({"msg": f"Processing: {email}..."}) + "\n"
            time.sleep(BATCH_SLEEP_SECONDS) 

            try:
                if action_type == 'delete':
                    yield json.dumps({"msg": "  - Moving emails to Trash..."}) + "\n"
                    msgs = []
                    
                    next_page_token = None
                    try:
                        while True:
                            list_req = service.users().messages().list(
                                userId='me', 
                                q=f"from:{email}", 
                                maxResults=MAX_MESSAGES_PER_PAGE,
                                pageToken=next_page_token
                            )
                            resp = execute_with_retry(list_req)
                            batch_msgs = resp.get('messages', [])
                            msgs.extend(batch_msgs)
                            
                            next_page_token = resp.get('nextPageToken')
                            if not next_page_token:
                                break
                            yield json.dumps({"msg": f"    ...found {len(msgs)} emails so far..."}) + "\n"
                    except Exception as e:
                        yield json.dumps({"msg": f"  - Warning: Failed to fetch all messages: {str(e)}"}) + "\n"

                    if msgs:
                        all_ids = [m['id'] for m in msgs]
                        total_trashed = 0
                        
                        for i in range(0, len(all_ids), BATCH_SIZE):
                            chunk_ids = all_ids[i:i + BATCH_SIZE]
                            try:
                                execute_with_retry(service.users().messages().batchModify(
                                    userId='me', body={'ids': chunk_ids, 'addLabelIds': ['TRASH']}
                                ))
                                total_trashed += len(chunk_ids)
                                yield json.dumps({"msg": f"    ...trashed {total_trashed} so far..."}) + "\n"
                                time.sleep(BATCH_SLEEP_SECONDS) 
                            except Exception as e:
                                yield json.dumps({"msg": f"    ...chunk failed: {str(e)}"}) + "\n"
                        yield json.dumps({"msg": f"  - SUCCESS: Trashed {total_trashed} emails total."}) + "\n"
                    else:
                        yield json.dumps({"msg": "  - No emails found to delete."}) + "\n"

                elif action_type == 'label':
                    label_id = None
                    if item.get('isNew'):
                        label_name = item['labelName']
                        if item.get('parentId') and 'parentName' in item:
                             label_name = f"{item['parentName']}/{item['labelName']}"
                        yield json.dumps({"msg": f"  - Creating Label: '{label_name}'..."}) + "\n"
                        try:
                            created = execute_with_retry(service.users().labels().create(userId='me', body={'name': label_name}))
                            label_id = created['id']
                            yield json.dumps({"msg": "  - Label created successfully."}) + "\n"
                        except HttpError:
                            yield json.dumps({"msg": f"  - Label likely exists. Fetching ID..."}) + "\n"
                            try:
                                resp = execute_with_retry(service.users().labels().list(userId='me'))
                                lbls = resp.get('labels', [])
                                existing = next((l for l in lbls if l['name'].lower() == label_name.lower()), None)
                                if existing: label_id = existing['id']
                            except Exception as e:
                                yield json.dumps({"msg": f"  - Error finding label: {str(e)}"}) + "\n"
                    else:
                        label_id = item['labelId']
                        if 'labelName' in item:
                             yield json.dumps({"msg": f"  - Applying Label: '{item['labelName']}'..."}) + "\n"

                    if label_id:
                        yield json.dumps({"msg": "  - Creating Filter (Skip Inbox)..."}) + "\n"
                        filter_body = {
                            'criteria': {'from': email},
                            'action': {'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']} 
                        }
                        try:
                            execute_with_retry(service.users().settings().filters().create(userId='me', body=filter_body))
                            yield json.dumps({"msg": "  - Filter created."}) + "\n"
                        except Exception as e: 
                            yield json.dumps({"msg": f"  - Filter Warning: {str(e)}"}) + "\n"

                        yield json.dumps({"msg": "  - Moving existing emails..."}) + "\n"
                        msgs = []
                        
                        next_page_token = None
                        try:
                            while True:
                                list_req = service.users().messages().list(
                                    userId='me', 
                                    q=f"from:{email}", 
                                    maxResults=MAX_MESSAGES_PER_PAGE,
                                    pageToken=next_page_token
                                )
                                resp = execute_with_retry(list_req)
                                batch_msgs = resp.get('messages', [])
                                msgs.extend(batch_msgs)
                                
                                next_page_token = resp.get('nextPageToken')
                                if not next_page_token:
                                    break
                                yield json.dumps({"msg": f"    ...found {len(msgs)} emails so far..."}) + "\n"
                        except Exception as e:
                            yield json.dumps({"msg": f"  - Warning: Failed to fetch all messages: {str(e)}"}) + "\n"

                        if msgs:
                            all_ids = [m['id'] for m in msgs]
                            total_moved = 0
                            
                            for i in range(0, len(all_ids), BATCH_SIZE):
                                chunk_ids = all_ids[i:i + BATCH_SIZE]
                                batch_body = {'ids': chunk_ids, 'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}
                                try:
                                    execute_with_retry(service.users().messages().batchModify(userId='me', body=batch_body))
                                    total_moved += len(chunk_ids)
                                    yield json.dumps({"msg": f"    ...moved {total_moved} so far..."}) + "\n"
                                    time.sleep(BATCH_SLEEP_SECONDS) 
                                except Exception as e:
                                    yield json.dumps({"msg": f"    ...chunk failed: {str(e)}"}) + "\n"

                            yield json.dumps({"msg": f"  - SUCCESS: Moved {total_moved} emails total."}) + "\n"
                        else:
                            yield json.dumps({"msg": "  - No existing emails to move."}) + "\n"
            except Exception as e:
                yield json.dumps({"msg": f"  - ERROR processing {email}: {str(e)}"}) + "\n"
        
        yield json.dumps({"msg": "ALL DONE. Reloading..."}) + "\n"
        yield json.dumps({"status": "complete"}) + "\n"

    return Response(stream_with_context(generate_updates()), mimetype='application/json')

if __name__ == '__main__':
    app.run(debug=True, port=5000)