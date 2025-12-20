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
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

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

def get_creds():
    if 'credentials' not in session: return None
    return Credentials(**session['credentials'])

def get_service():
    creds = get_creds()
    if not creds: return None
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
    return jsonify(session.get('user_info', {}))

@app.route('/api/scan_stream')
def scan_stream():
    if not get_creds(): 
        return Response("data: " + json.dumps({'error': 'Not logged in'}) + "\n\n", mimetype='text/event-stream')

    def generate():
        # FIX 1: Yield IMMEDIATELY before doing any work
        yield f"data: {json.dumps({'status': 'init', 'message': 'Connecting to Gmail...'})}\n\n"
        
        service = get_service()
        messages = []
        
        # FIX 2: Give feedback that we are fetching the list
        yield f"data: {json.dumps({'status': 'init', 'message': 'Fetching email list...'})}\n\n"
        
        # --- PHASE 1: LIST MESSAGES ---
        # FIX 3: Reduced maxResults from 500 -> 250 to get faster visual updates
        request = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=250)
        
        page_num = 1
        while request is not None:
            page_success = False
            for attempt in range(5):
                try:
                    response = request.execute()
                    msgs = response.get('messages', [])
                    messages.extend(msgs)
                    # This update will now happen roughly twice as often
                    yield f"data: {json.dumps({'status': 'counting', 'count': len(messages), 'log': f'Fetched page {page_num} ({len(msgs)} items). Total: {len(messages)}'})}\n\n"
                    request = service.users().messages().list_next(request, response)
                    page_success = True
                    break 
                except Exception as e:
                    yield f"data: {json.dumps({'log': f'Page {page_num} failed: {str(e)}. Retrying ({attempt+1}/5)...', 'level': 'warn'})}\n\n"
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

        # --- PHASE 2: FETCH DETAILS ---
        senders = []
        batch_size = 18 
        total_batches = (total_messages // batch_size) + 1
        
        for i in range(0, total_messages, batch_size):
            chunk = messages[i:i + batch_size]
            current_batch_num = (i // batch_size) + 1
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
            for attempt in range(5):
                try:
                    batch.execute()
                    batch_success = True
                    break 
                except Exception as e:
                    yield f"data: {json.dumps({'log': f'Batch {current_batch_num} connection failed: {str(e)}. Retrying...', 'level': 'error'})}\n\n"
                    time.sleep(2 ** attempt)
            
            if not batch_success:
                 yield f"data: {json.dumps({'log': f'CRITICAL: Batch {current_batch_num} dropped completely.', 'level': 'error'})}\n\n"

            # --- REPAIR LOOP ---
            if batch_failures:
                err_snippet = first_error_msg if first_error_msg else "Unknown Error"
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

            processed_count = min(i + batch_size, total_messages)
            progress_data = {
                'status': 'progress',
                'processed': processed_count,
                'total': total_messages,
                'percent': int((processed_count / total_messages) * 100)
            }
            yield f"data: {json.dumps(progress_data)}\n\n"
            
            time.sleep(0.2)

        # --- PHASE 3: AGGREGATE ---
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
        def execute_with_retry(request_obj):
            for attempt in range(4):
                try:
                    return request_obj.execute()
                except Exception as e:
                    time.sleep(1 + attempt)
            raise Exception("Connection failed after retries")

        yield json.dumps({"msg": "Starting to process actions..."}) + "\n"

        for item in actions:
            email = item['email']
            action_type = item['action']
            yield json.dumps({"msg": f"Processing: {email}..."}) + "\n"
            time.sleep(0.2) 

            try:
                if action_type == 'delete':
                    yield json.dumps({"msg": "  - Moving emails to Trash..."}) + "\n"
                    msgs = []
                    list_req = service.users().messages().list(userId='me', q=f"from:{email}", maxResults=500)
                    try:
                        resp = execute_with_retry(list_req)
                        msgs = resp.get('messages', [])
                    except: pass 

                    if msgs:
                        all_ids = [m['id'] for m in msgs]
                        total_trashed = 0
                        CHUNK_SIZE = 18 
                        for i in range(0, len(all_ids), CHUNK_SIZE):
                            chunk_ids = all_ids[i:i + CHUNK_SIZE]
                            try:
                                execute_with_retry(service.users().messages().batchModify(
                                    userId='me', body={'ids': chunk_ids, 'addLabelIds': ['TRASH']}
                                ))
                                total_trashed += len(chunk_ids)
                                yield json.dumps({"msg": f"    ...trashed {total_trashed} so far..."}) + "\n"
                                time.sleep(0.2) 
                            except:
                                yield json.dumps({"msg": "    ...chunk failed, skipping..."}) + "\n"
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
                            except: pass
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
                        list_req = service.users().messages().list(userId='me', q=f"from:{email}", maxResults=500)
                        try:
                            resp = execute_with_retry(list_req)
                            msgs = resp.get('messages', [])
                        except: pass

                        if msgs:
                            all_ids = [m['id'] for m in msgs]
                            total_moved = 0
                            CHUNK_SIZE = 18
                            for i in range(0, len(all_ids), CHUNK_SIZE):
                                chunk_ids = all_ids[i:i + CHUNK_SIZE]
                                batch_body = {'ids': chunk_ids, 'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}
                                try:
                                    execute_with_retry(service.users().messages().batchModify(userId='me', body=batch_body))
                                    total_moved += len(chunk_ids)
                                    yield json.dumps({"msg": f"    ...moved {total_moved} so far..."}) + "\n"
                                    time.sleep(0.2) 
                                except:
                                    yield json.dumps({"msg": "    ...chunk failed, skipping..."}) + "\n"

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