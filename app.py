import os
import time
import requests
import sqlite3
import pandas as pd
import io
from flask import Flask, render_template, request, redirect, url_for, session, abort, send_file
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
from google.oauth2 import id_token
import google.auth.transport.requests

# --- CONFIGURATION ---
# Allow HTTP for local testing and Railway internal routing
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# THE FIX: Allow Google to send extra scope data (OpenID) without crashing
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1' 

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_key_needs_to_be_changed")

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile", 
    "https://www.googleapis.com/auth/userinfo.email", 
    "openid"
]

DB_NAME = "search_console.db"

# --- DATABASE HELPER ---
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    # Create Users table with profile support
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            name TEXT,
            profile_pic TEXT,
            last_login DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Create Keywords table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            keyword TEXT,
            target_url TEXT,
            rank INTEGER,
            last_checked DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

# Initialize DB on startup
init_db()

# --- CORE LOGIC ---
def check_keyword_ranking(keyword, target_url):
    """
    Scrapes Google Search to find the rank of a target_url for a keyword.
    Returns: Rank (1-100) or None if not found.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    search_url = f"https://www.google.com/search?q={keyword}&num=100"
    
    try:
        response = requests.get(search_url, headers=headers)
        if response.status_code != 200:
            return None
        
        # Simple parsing logic (can be replaced with BeautifulSoup for robustness)
        text = response.text
        # This is a basic approximation. For production, consider an API like SerpApi.
        if target_url in text:
            # Very rough estimation based on string finding; 
            # Real SEO scraping requires parsing the specific DOM elements.
            return 1 # Placeholder for "Found"
        return None
    except Exception as e:
        print(f"Error checking {keyword}: {e}")
        return None

# --- ROUTES ---

@app.route("/")
def index():
    if "google_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES
    )
    flow.redirect_uri = url_for("callback", _external=True)
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session["state"]
    )
    flow.redirect_uri = url_for("callback", _external=True)

    # Use the fix allowed by OAUTHLIB_RELAX_TOKEN_SCOPE
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    # Extract user info
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    session["profile_pic"] = id_info.get("picture")

    # Save to DB
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO users (id, email, name, profile_pic, last_login)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            profile_pic=excluded.profile_pic,
            last_login=CURRENT_TIMESTAMP
    ''', (session["google_id"], session["email"], session["name"], session["profile_pic"]))
    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    if "google_id" not in session:
        return redirect(url_for("login"))

    user_id = session["google_id"]
    
    # Get Filter/Search params
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 5
    offset = (page - 1) * per_page

    conn = get_db_connection()
    
    # Logic for Search + Pagination
    if search_query:
        query = f"%{search_query}%"
        keywords = conn.execute(
            'SELECT * FROM keywords WHERE user_id = ? AND keyword LIKE ? LIMIT ? OFFSET ?',
            (user_id, query, per_page, offset)
        ).fetchall()
        total_count = conn.execute(
            'SELECT COUNT(*) FROM keywords WHERE user_id = ? AND keyword LIKE ?',
            (user_id, query)
        ).fetchone()[0]
    else:
        keywords = conn.execute(
            'SELECT * FROM keywords WHERE user_id = ? LIMIT ? OFFSET ?',
            (user_id, per_page, offset)
        ).fetchall()
        total_count = conn.execute(
            'SELECT COUNT(*) FROM keywords WHERE user_id = ?',
            (user_id,)
        ).fetchone()[0]

    conn.close()

    total_pages = (total_count + per_page - 1) // per_page

    user_data = {
        "name": session.get("name"),
        "picture": session.get("profile_pic")
    }

    return render_template(
        "dashboard.html", 
        keywords=keywords, 
        user=user_data, 
        page=page, 
        total_pages=total_pages,
        search_query=search_query
    )

@app.route("/add_keyword", methods=["POST"])
def add_keyword():
    if "google_id" not in session:
        return redirect(url_for("login"))

    keyword = request.form.get("keyword")
    target_url = request.form.get("url")
    user_id = session["google_id"]

    if keyword and target_url:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO keywords (user_id, keyword, target_url, rank, last_checked) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)',
            (user_id, keyword, target_url, 0) # Default rank 0
        )
        conn.commit()
        conn.close()

    return redirect(url_for("dashboard"))

@app.route("/delete_keyword/<int:keyword_id>")
def delete_keyword(keyword_id):
    if "google_id" not in session:
        return redirect(url_for("login"))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM keywords WHERE id = ? AND user_id = ?', (keyword_id, session["google_id"]))
    conn.commit()
    conn.close()
    
    return redirect(url_for("dashboard"))

@app.route("/export_csv")
def export_csv():
    if "google_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    df = pd.read_sql_query("SELECT keyword, target_url, rank, last_checked FROM keywords WHERE user_id = ?", conn, params=(session["google_id"],))
    conn.close()

    output = io.StringIO()
    df.to_csv(output, index=False)
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=keywords_report.csv"}
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)