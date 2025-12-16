import os
import json
import pandas as pd
import re
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- PRODUCTION SETUP: Create secret file from Environment Variable ---
# This allows Railway to inject your secrets safely without putting them on GitHub.
if os.environ.get('GOOGLE_CLIENT_SECRETS_JSON'):
    print("Detected Environment Variable for Secrets. Creating client_secret.json...")
    with open('client_secret.json', 'w') as f:
        f.write(os.environ.get('GOOGLE_CLIENT_SECRETS_JSON'))

app = Flask(__name__)

# Use a secure key from Railway, or a default for local testing
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_key_for_testing_only')

# Allow non-HTTPS for local testing (Railway handles HTTPS automatically)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.settings.basic'
]

def get_creds():
    if 'credentials' not in session:
        return None
    creds_data = session['credentials']
    return Credentials(**creds_data)

@app.route('/')
def index():
    creds = get_creds()
    if not creds:
        return render_template('login.html') 
        # Note: You need a simple login.html template with a "Login with Google" button
    return render_template('dashboard.html')

@app.route('/login')
def login():
    # This automatically detects if you are on localhost or Railway
    redirect_uri = url_for('callback', _external=True)
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=redirect_uri)
    
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    redirect_uri = url_for('callback', _external=True)
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=redirect_uri)
    
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    
    # Store credentials in session
    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    return redirect(url_for('index'))

# --- API ENDPOINTS ---

@app.route('/api/scan_inbox')
def scan_inbox():
    creds = get_creds()
    if not creds: return jsonify({"error": "Not logged in"}), 401
    
    service = build('gmail', 'v1', credentials=creds)
    
    # Fetch headers only for speed (max 500 for demo)
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=500).execute()
    messages = results.get('messages', [])
    
    if not messages:
        return jsonify([])

    # Batch Request to get 'From' headers efficiently
    batch = service.new_batch_http_request()
    senders = []

    def batch_callback(request_id, response, exception):
        if exception is None:
            headers = response['payload']['headers']
            from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            # Regex to pull just the email: "Name <email@site.com>" -> "email@site.com"
            match = re.search(r'<(.+?)>', from_header)
            clean_email = match.group(1) if match else from_header
            senders.append(clean_email)

    for msg in messages:
        batch.add(service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From']), callback=batch_callback)
    
    batch.execute()

    # Rank them
    df = pd.DataFrame(senders, columns=['email'])
    counts = df['email'].value_counts().reset_index()
    counts.columns = ['email', 'count']
    
    return jsonify(counts.to_dict(orient='records'))

@app.route('/api/get_labels')
def get_labels():
    creds = get_creds()
    service = build('gmail', 'v1', credentials=creds)
    results = service.users().labels().list(userId='me').execute()
    return jsonify(results.get('labels', []))

@app.route('/api/apply_actions', methods=['POST'])
def apply_actions():
    creds = get_creds()
    service = build('gmail', 'v1', credentials=creds)
    actions = request.json # Expects list of objects from frontend

    processed_count = 0

    for item in actions:
        email = item['email']
        action_type = item['action']
        
        # 1. DELETE ACTION
        if action_type == 'delete':
            # Find messages
            query = f"from:{email}"
            msgs = service.users().messages().list(userId='me', q=query).execute().get('messages', [])
            if msgs:
                ids = [m['id'] for m in msgs]
                service.users().messages().batchDelete(userId='me', body={'ids': ids}).execute()

        # 2. LABEL / FILTER ACTION
        elif action_type == 'label':
            label_id = None
            
            # A. Create Label if needed (and handle nesting)
            if item.get('isNew'):
                label_name = item['labelName']
                label_body = {'name': label_name}
                
                # If user selected a parent folder to nest under
                if item.get('parentId'): 
                    # We need the parent NAME, not ID, for the API (Parent/Child)
                    # Ideally frontend sends parentName, or we look it up. 
                    # Assuming frontend sends 'parentName' for simplicity here:
                    if 'parentName' in item:
                        label_body['name'] = f"{item['parentName']}/{label_name}"

                try:
                    created = service.users().labels().create(userId='me', body=label_body).execute()
                    label_id = created['id']
                except HttpError:
                    # If label exists, search for it to get ID
                    lbls = service.users().labels().list(userId='me').execute().get('labels', [])
                    existing = next((l for l in lbls if l['name'].lower() == label_body['name'].lower()), None)
                    if existing: label_id = existing['id']
            else:
                label_id = item['labelId']

            if label_id:
                # B. Create Filter (Skip Inbox + Apply Label)
                filter_body = {
                    'criteria': {'from': email},
                    'action': {
                        'addLabelIds': [label_id],
                        'removeLabelIds': ['INBOX', 'UNREAD'] # Mark read and archive
                    }
                }
                try:
                    service.users().settings().filters().create(userId='me', body=filter_body).execute()
                except Exception as e:
                    print(f"Filter creation error: {e}")

                # C. Apply to existing messages (Retroactive)
                query = f"from:{email}"
                msgs = service.users().messages().list(userId='me', q=query).execute().get('messages', [])
                if msgs:
                    ids = [m['id'] for m in msgs]
                    batch_body = {
                        'ids': ids,
                        'addLabelIds': [label_id],
                        'removeLabelIds': ['INBOX']
                    }
                    service.users().messages().batchModify(userId='me', body=batch_body).execute()
        
        processed_count += 1

    return jsonify({"status": "success", "processed": processed_count})

if __name__ == '__main__':
    # Standard boilerplate for running locally
    app.run(debug=True, port=5000)