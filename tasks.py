import os
import re
import json
import time
import redis
import httplib2
import google_auth_httplib2
from collections import Counter

from celery_app import celery_app
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import ai_labeler

# --- CONSTANTS (mirror app.py values) ---
BATCH_SIZE = 18
BATCH_SLEEP_SECONDS = 0.2
MAX_RETRIES = 5
MAX_MESSAGES_PER_PAGE = 500
JOB_TTL = 7200  # Redis key expiry: 2 hours


def get_redis_client():
    return redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))


def set_progress(r, job_id, data):
    """Write the current progress snapshot to Redis."""
    r.setex(f'scan:{job_id}:progress', JOB_TTL, json.dumps(data))


def append_log(r, job_id, msg, level='info'):
    """Append a log line to the job's log list (capped at 100 entries)."""
    key = f'scan:{job_id}:logs'
    entry = json.dumps({'msg': msg, 'level': level, 't': time.time()})
    r.rpush(key, entry)
    r.ltrim(key, -100, -1)
    r.expire(key, JOB_TTL)


@celery_app.task
def run_inbox_scan(job_id, credentials_dict):
    r = get_redis_client()

    try:
        # --- Build and optionally refresh credentials ---
        creds = Credentials(**credentials_dict)
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                set_progress(r, job_id, {'status': 'failed', 'error': f'Token refresh failed: {e}'})
                return

        http = httplib2.Http(timeout=30)
        authorized_http = google_auth_httplib2.AuthorizedHttp(creds, http=http)
        service = build('gmail', 'v1', http=authorized_http)

        set_progress(r, job_id, {
            'status': 'running', 'percent': 0,
            'processed': 0, 'total': 0,
            'message': 'Connecting to Gmail...'
        })
        append_log(r, job_id, 'Starting connection to Gmail API...')

        # --- Phase 1: List all message IDs ---
        messages = []
        list_req = service.users().messages().list(
            userId='me', labelIds=['INBOX'], maxResults=MAX_MESSAGES_PER_PAGE
        )
        page_num = 1

        while list_req is not None:
            page_success = False
            for attempt in range(MAX_RETRIES):
                try:
                    response = list_req.execute()
                    msgs = response.get('messages', [])
                    messages.extend(msgs)
                    append_log(r, job_id, f'Fetched page {page_num} ({len(msgs)} items). Total: {len(messages)}')

                    list_req = service.users().messages().list_next(list_req, response)
                    page_success = True
                    break
                except Exception:
                    time.sleep(2 ** attempt)

            if not page_success:
                set_progress(r, job_id, {'status': 'failed', 'error': 'Failed to fetch message list after retries.'})
                return
            page_num += 1

        total_messages = len(messages)
        append_log(r, job_id, f'List complete. Found {total_messages} emails. Starting Detail Scan...', 'success')

        if total_messages == 0:
            r.setex(f'scan:{job_id}:results', JOB_TTL, json.dumps([]))
            set_progress(r, job_id, {
                'status': 'complete', 'percent': 100,
                'processed': 0, 'total': 0, 'message': 'Complete'
            })
            return

        # --- Phase 2: Batch fetch From headers ---
        senders = []
        total_batches = (total_messages // BATCH_SIZE) + (1 if total_messages % BATCH_SIZE > 0 else 0)

        for i in range(0, total_messages, BATCH_SIZE):
            chunk = messages[i:i + BATCH_SIZE]
            current_batch_num = (i // BATCH_SIZE) + 1
            batch = service.new_batch_http_request()

            def batch_callback(request_id, response, exception, _senders=senders):
                if exception is None:
                    headers = response['payload']['headers']
                    from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                    match = re.search(r'<(.+?)>', from_header)
                    clean_email = match.group(1) if match else from_header
                    _senders.append(clean_email.lower().strip())

            for msg in chunk:
                batch.add(
                    service.users().messages().get(
                        userId='me', id=msg['id'],
                        format='metadata', metadataHeaders=['From']
                    ),
                    callback=batch_callback
                )

            try:
                batch.execute()
            except Exception:
                pass

            if current_batch_num % 5 == 0:
                append_log(r, job_id, f'Batch {current_batch_num}/{total_batches} processed.')

            current_processed = min(i + BATCH_SIZE, total_messages)
            progress_pct = int((current_processed / total_messages) * 100)
            set_progress(r, job_id, {
                'status': 'running',
                'percent': progress_pct,
                'processed': current_processed,
                'total': total_messages,
                'message': f'Processed {current_processed} of {total_messages} emails...'
            })

            time.sleep(BATCH_SLEEP_SECONDS)

        # --- Build and store results ---
        if senders:
            counts = Counter(senders)
            result_data = [
                {'email': email, 'count': count}
                for email, count in sorted(counts.items(), key=lambda x: (-x[1], x[0]))
            ]
        else:
            result_data = []

        r.setex(f'scan:{job_id}:results', JOB_TTL, json.dumps(result_data))
        set_progress(r, job_id, {
            'status': 'complete',
            'percent': 100,
            'processed': total_messages,
            'total': total_messages,
            'message': 'Analysis complete. Rendering table...'
        })
        append_log(r, job_id, 'Analysis complete. Rendering table...', 'success')

    except Exception as e:
        set_progress(r, job_id, {'status': 'failed', 'error': str(e)})
        append_log(r, job_id, f'Fatal error: {e}', 'error')


# ── AI Label Suggestions ───────────────────────────────────────────────────────

AI_JOB_TTL = 3600  # Redis key expiry: 1 hour


def _set_ai_status(r, job_id, data):
    r.setex(f'ai:{job_id}:status', AI_JOB_TTL, json.dumps(data))


@celery_app.task
def run_ai_suggestions(job_id, senders, label_names):
    """
    Call DeepSeek in the background worker (no HTTP timeout constraint).
    Writes status to ai:{job_id}:status and results to ai:{job_id}:result.
    """
    r = get_redis_client()
    _set_ai_status(r, job_id, {
        'status': 'running',
        'message': f'Asking DeepSeek to analyse {len(senders)} senders…',
    })

    try:
        result = ai_labeler.suggest_labels(senders, label_names)
        group_count = len(result.get('suggestions', []))
        r.setex(f'ai:{job_id}:result', AI_JOB_TTL, json.dumps(result))
        _set_ai_status(r, job_id, {
            'status': 'complete',
            'groups': group_count,
            'senders_sent': len(senders),
        })
    except Exception as e:
        _set_ai_status(r, job_id, {
            'status': 'failed',
            'error': str(e),
            'senders_sent': len(senders),
        })
