import os
import json
import pandas as pd
import re
import time
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
    service = build('gmail', 'v1', credentials=creds)
    actions = request.json 
    processed_count = 0

    for item in actions:
        email = item['email']
        action_type = item['action']
        
        if action_type == 'delete':
            msgs = service.users().messages().list(userId='me', q=f"from:{email}").execute().get('messages', [])
            if msgs:
                ids = [m['id'] for m in msgs]
                service.users().messages().batchDelete(userId='me', body={'ids': ids}).execute()

        elif action_type == 'label':
            label_id = None
            if item.get('isNew'):
                label_body = {'name': item['labelName']}
                if item.get('parentId') and 'parentName' in item:
                        label_body['name'] = f"{item['parentName']}/{item['labelName']}"
                try:
                    created = service.users().labels().create(userId='me', body=label_body).execute()
                    label_id = created['id']
                except HttpError:
                    lbls = service.users().labels().list(userId='me').execute().get('labels', [])
                    existing = next((l for l in lbls if l['name'].lower() == label_body['name'].lower()), None)
                    if existing: label_id = existing['id']
            else:
                label_id = item['labelId']

            if label_id:
                # 1. Create Filter
                # Note: We ONLY remove 'INBOX'. We do NOT remove 'UNREAD'.
                filter_body = {
                    'criteria': {'from': email},
                    'action': {'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']} 
                }
                try:
                    service.users().settings().filters().create(userId='me', body=filter_body).execute()
                except Exception: pass

                # 2. Apply to existing messages
                msgs = service.users().messages().list(userId='me', q=f"from:{email}").execute().get('messages', [])
                if msgs:
                    ids = [m['id'] for m in msgs]
                    batch_body = {'ids': ids, 'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}
                    service.users().messages().batchModify(userId='me', body=batch_body).execute()
        processed_count += 1
    return jsonify({"status": "success", "processed": processed_count})

if __name__ == '__main__':
    app.run(debug=True, port=5000)