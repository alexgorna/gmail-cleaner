import os
import json
import pandas as pd
import re
import time
import random
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, stream_with_context
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

if os.environ.get('GOOGLE_CLIENT_SECRETS_JSON'):
    with open('client_secret.json', 'w') as f:
        f.write(os.environ.get('GOOGLE_CLIENT_SECRETS_JSON'))

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

def get_creds():
    if 'credentials' not in session: return None
    return Credentials(**session['credentials'])

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
    creds = get_creds()
    if not creds: 
        return Response("data: " + json.dumps({'error': 'Not logged in'}) + "\n\n", mimetype='text/event-stream')

    def generate():
        service = build('gmail', 'v1', credentials=creds)
        
        messages = []
        request = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=500)
        yield f"data: {json.dumps({'status': 'init', 'message': 'Fetching message list...'})}\n\n"

        while request is not None:
            response = request.execute()
            messages.extend(response.get('messages', []))
            request = service.users().messages().list_next(request, response)
            yield f"data: {json.dumps({'status': 'counting', 'count': len(messages)})}\n\n"
        
        total_messages = len(messages)
        if total_messages == 0:
            yield f"data: {json.dumps({'status': 'complete', 'data': []})}\n\n"
            return

        senders = []
        batch_size = 50
        
        for i in range(0, total_messages, batch_size):
            chunk = messages[i:i + batch_size]
            batch = service.new_batch_http_request()
            
            def batch_callback(request_id, response, exception):
                if exception is None:
                    headers = response['payload']['headers']
                    from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                    match = re.search(r'<(.+?)>', from_header)
                    clean_email = match.group(1) if match else from_header
                    senders.append(clean_email)

            for msg in chunk:
                batch.add(service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From']), callback=batch_callback)
            
            try:
                batch.execute()
            except Exception as e:
                print(f"Batch error: {e}")

            processed_count = min(i + batch_size, total_messages)
            progress_data = {
                'status': 'progress',
                'processed': processed_count,
                'total': total_messages,
                'percent': int((processed_count / total_messages) * 100)
            }
            yield f"data: {json.dumps(progress_data)}\n\n"

        df = pd.DataFrame(senders, columns=['email'])
        counts = df['email'].value_counts().reset_index()
        counts.columns = ['email', 'count']
        result_data = counts.to_dict(orient='records')
        
        yield f"data: {json.dumps({'status': 'complete', 'data': result_data})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/get_labels')
def get_labels():
    creds = get_creds()
    service = build('gmail', 'v1', credentials=creds)
    results = service.users().labels().list(userId='me').execute()
    labels = results.get('labels', [])
    labels.sort(key=lambda x: x['name'].lower())
    return jsonify(labels)

@app.route('/api/apply_actions', methods=['POST'])
def apply_actions():
    creds = get_creds()
    actions = request.json 

    def generate_updates():
        service = build('gmail', 'v1', credentials=creds)
        
        def execute_with_retry(request_obj):
            retries = 0
            max_retries = 5
            while retries < max_retries:
                try:
                    return request_obj.execute()
                except HttpError as e:
                    if e.resp.status in [429, 500, 502, 503, 504] or (e.resp.status == 403 and "usageLimits" in str(e)):
                        sleep_time = (2 ** retries) + random.random()
                        time.sleep(sleep_time)
                        retries += 1
                        continue
                    raise e
                except Exception:
                    time.sleep(2 ** retries)
                    retries += 1
            raise Exception("Max retries exceeded. Connection unstable.")

        yield json.dumps({"msg": "Starting to process actions..."}) + "\n"

        for item in actions:
            email = item['email']
            action_type = item['action']
            
            yield json.dumps({"msg": f"Processing: {email}..."}) + "\n"
            time.sleep(0.5)

            try:
                if action_type == 'delete':
                    yield json.dumps({"msg": "  - Moving emails to Trash..."}) + "\n"
                    msgs_response = execute_with_retry(
                        service.users().messages().list(userId='me', q=f"from:{email}")
                    )
                    msgs = msgs_response.get('messages', [])
                    
                    if msgs:
                        ids = [m['id'] for m in msgs]
                        execute_with_retry(
                            service.users().messages().batchModify(
                                userId='me', 
                                body={'ids': ids, 'addLabelIds': ['TRASH']}
                            )
                        )
                        yield json.dumps({"msg": f"  - SUCCESS: Trashed {len(ids)} emails."}) + "\n"
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
                            created = execute_with_retry(
                                service.users().labels().create(userId='me', body={'name': label_name})
                            )
                            label_id = created['id']
                            yield json.dumps({"msg": "  - Label created successfully."}) + "\n"
                        except HttpError:
                            yield json.dumps({"msg": f"  - Label '{label_name}' likely exists. Fetching ID..."}) + "\n"
                            lbls = execute_with_retry(service.users().labels().list(userId='me'))
                            existing = next((l for l in lbls.get('labels', []) if l['name'].lower() == label_name.lower()), None)
                            if existing: label_id = existing['id']
                    else:
                        label_id = item['labelId']
                        # LOGGING FIX FOR EXISTING LABELS
                        if 'labelName' in item:
                            yield json.dumps({"msg": f"  - Applying Label: '{item['labelName']}'..."}) + "\n"

                    if label_id:
                        yield json.dumps({"msg": "  - Creating Filter (Skip Inbox)..."}) + "\n"
                        filter_body = {
                            'criteria': {'from': email},
                            'action': {'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']} 
                        }
                        try:
                            execute_with_retry(
                                service.users().settings().filters().create(userId='me', body=filter_body)
                            )
                            yield json.dumps({"msg": "  - Filter created."}) + "\n"
                        except Exception as e: 
                            yield json.dumps({"msg": f"  - Filter Warning: {str(e)}"}) + "\n"

                        yield json.dumps({"msg": "  - Moving existing emails..."}) + "\n"
                        msgs_response = execute_with_retry(
                            service.users().messages().list(userId='me', q=f"from:{email}")
                        )
                        msgs = msgs_response.get('messages', [])
                        
                        if msgs:
                            ids = [m['id'] for m in msgs]
                            batch_body = {'ids': ids, 'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}
                            execute_with_retry(
                                service.users().messages().batchModify(userId='me', body=batch_body)
                            )
                            yield json.dumps({"msg": f"  - SUCCESS: Moved {len(ids)} emails."}) + "\n"
                        else:
                            yield json.dumps({"msg": "  - No existing emails to move."}) + "\n"

            except Exception as e:
                yield json.dumps({"msg": f"  - ERROR processing {email}: {str(e)}"}) + "\n"
        
        yield json.dumps({"msg": "ALL DONE. Reloading..."}) + "\n"
        yield json.dumps({"status": "complete"}) + "\n"

    return Response(stream_with_context(generate_updates()), mimetype='application/json')

if __name__ == '__main__':
    app.run(debug=True, port=5000)