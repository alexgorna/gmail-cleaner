import os
import json
import pandas as pd
import re
import time
import random
import socket
import httplib2
import google_auth_httplib2
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, stream_with_context
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_key_for_testing_only')
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.settings.basic'
]

if os.environ.get('GOOGLE_CLIENT_SECRETS_JSON'):
    with open('client_secret.json', 'w') as f:
        f.write(os.environ.get('GOOGLE_CLIENT_SECRETS_JSON'))

def get_creds():
    if 'credentials' not in session: return None
    return Credentials(**session['credentials'])

def get_service():
    creds = get_creds()
    if not creds: return None
    # 30s timeout to prevent hanging on slow requests
    http = httplib2.Http(timeout=30)
    authorized_http = google_auth_httplib2.AuthorizedHttp(creds, http=http)
    return build('gmail', 'v1', http=authorized_http)

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
    redirect_uri = url_for('callback', _external=True)
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=redirect_uri)
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session['credentials'] = {
        'token': creds.token, 'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri, 'client_id': creds.client_id,
        'client_secret': creds.client_secret, 'scopes': creds.scopes
    }
    return redirect(url_for('index'))

@app.route('/api/scan_stream')
def scan_stream():
    if not get_creds(): 
        return Response("data: " + json.dumps({'error': 'Not logged in'}) + "\n\n", mimetype='text/event-stream')

    def generate():
        service = get_service()
        messages = []
        
        yield f"data: {json.dumps({'status': 'init', 'message': 'Connecting to Gmail...'})}\n\n"
        
        # --- RETRY HELPER ---
        # Returns the result if successful, or None if it fails 5 times
        def fetch_with_retry(execute_method, is_batch=False):
            attempts = 0
            while attempts < 5:
                try:
                    result = execute_method()
                    if is_batch: return True # Batch executes return None on success
                    return result
                except Exception as e:
                    attempts += 1
                    time.sleep(2 ** attempts) # Wait 2s, 4s, 8s...
            return None

        # --- PHASE 1: LIST ALL MESSAGES ---
        request = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=500)
        
        while request is not None:
            # Retry fetching the list page so we don't crash
            response = fetch_with_retry(request.execute, is_batch=False)
            
            if response is None:
                yield f"data: {json.dumps({'error': 'Failed to fetch email list. Stopping.'})}\n\n"
                return
                
            messages.extend(response.get('messages', []))
            yield f"data: {json.dumps({'status': 'counting', 'count': len(messages)})}\n\n"
            request = service.users().messages().list_next(request, response)

        total_messages = len(messages)
        if total_messages == 0:
            yield f"data: {json.dumps({'status': 'complete', 'data': []})}\n\n"
            return

        # --- PHASE 2: FETCH SENDER DETAILS ---
        senders = []
        batch_size = 25 # Keeping batch small for stability
        
        for i in range(0, total_messages, batch_size):
            chunk = messages[i:i + batch_size]
            batch = service.new_batch_http_request()
            
            def batch_callback(request_id, response, exception):
                if exception is None:
                    headers = response['payload']['headers']
                    from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                    
                    # Extract email inside <...> or use the whole string if no brackets
                    match = re.search(r'<(.+?)>', from_header)
                    clean_email = match.group(1) if match else from_header
                    
                    # We strip() to remove hidden spaces, which might split counts
                    senders.append(clean_email.strip())

            for msg in chunk:
                batch.add(service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From']), callback=batch_callback)
            
            # CRITICAL FIX: We retry the batch if it fails.
            # This ensures we don't "drop" 25 emails just because the network blinked.
            success = fetch_with_retry(batch.execute, is_batch=True)
            
            if not success:
                yield f"data: {json.dumps({'error': f'Failed to fetch details for batch {i}. Data may be incomplete.'})}\n\n"

            processed_count = min(i + batch_size, total_messages)
            progress_data = {
                'status': 'progress',
                'processed': processed_count,
                'total': total_messages,
                'percent': int((processed_count / total_messages) * 100)
            }
            yield f"data: {json.dumps(progress_data)}\n\n"

        # --- PHASE 3: AGGREGATE ---
        df = pd.DataFrame(senders, columns=['email'])
        counts = df['email'].value_counts().reset_index()
        counts.columns = ['email', 'count']
        result_data = counts.to_dict(orient='records')
        
        yield f"data: {json.dumps({'status': 'complete', 'data': result_data})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/get_labels')
def get_labels():
    service = get_service()
    if not service: return jsonify([])
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        labels.sort(key=lambda x: x['name'].lower())
        return jsonify(labels)
    except:
        return jsonify([])

@app.route('/api/apply_actions', methods=['POST'])
def apply_actions():
    actions = request.json 
    def generate_updates():
        service = get_service()
        
        def execute_request(request_obj):
            retries = 0
            max_retries = 3 
            while retries < max_retries:
                try:
                    yield {'result': request_obj.execute()}
                    return
                except HttpError as e:
                    if e.resp.status in [429, 500, 502, 503, 504] or (e.resp.status == 403 and "usageLimits" in str(e)):
                        wait_time = (2 ** retries) + random.random()
                        yield {'log': f"  - Google busy (HTTP {e.resp.status}). Retrying in {int(wait_time)}s..."}
                        time.sleep(wait_time)
                        retries += 1
                        continue
                    raise e
                except Exception as e:
                    wait_time = 2 ** retries
                    yield {'log': f"  - Network timeout ({type(e).__name__}). Retrying in {wait_time}s..."}
                    time.sleep(wait_time)
                    retries += 1
            raise Exception("Max retries exceeded. Connection lost.")

        yield json.dumps({"msg": "Starting to process actions..."}) + "\n"

        for item in actions:
            email = item['email']
            action_type = item['action']
            yield json.dumps({"msg": f"Processing: {email}..."}) + "\n"
            time.sleep(0.5)

            try:
                if action_type == 'delete':
                    yield json.dumps({"msg": "  - Moving emails to Trash..."}) + "\n"
                    msgs = []
                    list_req = service.users().messages().list(userId='me', q=f"from:{email}", maxResults=500)
                    for output in execute_request(list_req):
                        if 'log' in output: yield json.dumps({"msg": output['log']}) + "\n"
                        elif 'result' in output: msgs = output['result'].get('messages', [])

                    if msgs:
                        all_ids = [m['id'] for m in msgs]
                        total_trashed = 0
                        CHUNK_SIZE = 25 
                        for i in range(0, len(all_ids), CHUNK_SIZE):
                            chunk_ids = all_ids[i:i + CHUNK_SIZE]
                            for output in execute_request(service.users().messages().batchModify(
                                userId='me', body={'ids': chunk_ids, 'addLabelIds': ['TRASH']}
                            )):
                                if 'log' in output: yield json.dumps({"msg": output['log']}) + "\n"
                            total_trashed += len(chunk_ids)
                            yield json.dumps({"msg": f"    ...trashed {total_trashed} so far..."}) + "\n"
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
                            created = None
                            for output in execute_request(service.users().labels().create(userId='me', body={'name': label_name})):
                                if 'log' in output: yield json.dumps({"msg": output['log']}) + "\n"
                                elif 'result' in output: created = output['result']
                            label_id = created['id']
                            yield json.dumps({"msg": "  - Label created successfully."}) + "\n"
                        except HttpError:
                            yield json.dumps({"msg": f"  - Label likely exists. Fetching ID..."}) + "\n"
                            lbls = []
                            for output in execute_request(service.users().labels().list(userId='me')):
                                if 'log' in output: yield json.dumps({"msg": output['log']}) + "\n"
                                elif 'result' in output: lbls = output['result'].get('labels', [])
                            existing = next((l for l in lbls if l['name'].lower() == label_name.lower()), None)
                            if existing: label_id = existing['id']
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
                            for output in execute_request(service.users().settings().filters().create(userId='me', body=filter_body)):
                                if 'log' in output: yield json.dumps({"msg": output['log']}) + "\n"
                            yield json.dumps({"msg": "  - Filter created."}) + "\n"
                        except Exception as e: 
                            yield json.dumps({"msg": f"  - Filter Warning: {str(e)}"}) + "\n"

                        yield json.dumps({"msg": "  - Moving existing emails..."}) + "\n"
                        msgs = []
                        list_req = service.users().messages().list(userId='me', q=f"from:{email}", maxResults=500)
                        for output in execute_request(list_req):
                             if 'log' in output: yield json.dumps({"msg": output['log']}) + "\n"
                             elif 'result' in output: msgs = output['result'].get('messages', [])

                        if msgs:
                            all_ids = [m['id'] for m in msgs]
                            total_moved = 0
                            CHUNK_SIZE = 25
                            for i in range(0, len(all_ids), CHUNK_SIZE):
                                chunk_ids = all_ids[i:i + CHUNK_SIZE]
                                batch_body = {'ids': chunk_ids, 'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}
                                for output in execute_request(service.users().messages().batchModify(userId='me', body=batch_body)):
                                    if 'log' in output: yield json.dumps({"msg": output['log']}) + "\n"
                                total_moved += len(chunk_ids)
                                yield json.dumps({"msg": f"    ...moved {total_moved} so far..."}) + "\n"
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