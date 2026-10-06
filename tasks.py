import os
import re
import json
import time
import redis
import httplib2
import google_auth_httplib2
import concurrent.futures
import threading
from collections import Counter
from email.utils import parseaddr

# Sender addresses come from attacker-controlled From headers: keep only well-formed addresses
_SAFE_EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&*+/=?^_`{|}~'-]+@[a-z0-9.-]+$")

from celery_app import celery_app
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import ai_labeler
import jev_labeler  # must be imported at load time: Celery drops the app dir from sys.path afterwards
import history_labeler

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
def run_inbox_scan(job_id, credentials_dict, source_label_id=None, source_label_name=None):
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

        scan_source = source_label_name or 'Inbox'
        set_progress(r, job_id, {
            'status': 'running', 'percent': 0,
            'processed': 0, 'total': 0,
            'message': 'Connecting to Gmail...',
            'source_label_id': source_label_id,
            'source_label_name': source_label_name,
        })
        append_log(r, job_id, f'Starting connection to Gmail API... (source: {scan_source})')

        # --- Phase 1: List all message IDs ---
        messages = []
        list_kwargs = {'userId': 'me', 'maxResults': MAX_MESSAGES_PER_PAGE}
        if source_label_id:
            list_kwargs['labelIds'] = [source_label_id]
        else:
            list_kwargs['labelIds'] = ['INBOX']
        list_req = service.users().messages().list(**list_kwargs)
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

        # --- Phase 2: Batch fetch From + Subject headers ---
        senders = []
        subjects_by_email = {}  # email -> [subject, ...] (up to 3 per sender)
        MAX_SUBJECTS = 3
        total_batches = (total_messages // BATCH_SIZE) + (1 if total_messages % BATCH_SIZE > 0 else 0)

        for i in range(0, total_messages, BATCH_SIZE):
            chunk = messages[i:i + BATCH_SIZE]
            current_batch_num = (i // BATCH_SIZE) + 1
            batch = service.new_batch_http_request()

            def batch_callback(request_id, response, exception,
                               _senders=senders, _subjects=subjects_by_email):
                if exception is None:
                    headers = response['payload']['headers']
                    from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                    _, parsed_addr = parseaddr(from_header)
                    clean_email = (parsed_addr or '').lower().strip()
                    if not _SAFE_EMAIL_RE.match(clean_email):
                        clean_email = 'invalid-sender@unknown'
                    _senders.append(clean_email)

                    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
                    if subject:
                        bucket = _subjects.setdefault(clean_email, [])
                        if len(bucket) < MAX_SUBJECTS:
                            bucket.append(subject[:120])  # cap each subject length

            for msg in chunk:
                batch.add(
                    service.users().messages().get(
                        userId='me', id=msg['id'],
                        format='metadata', metadataHeaders=['From', 'Subject']
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
                {'email': email, 'count': count,
                 'subjects': subjects_by_email.get(email, [])}
                for email, count in sorted(counts.items(), key=lambda x: (-x[1], x[0]))
            ]
        else:
            result_data = []

        r.setex(f'scan:{job_id}:results', JOB_TTL, json.dumps(result_data))
        set_progress(r, job_id, {
            'status': 'complete',
            'percent': 100,
            'source_label_id': source_label_id,
            'source_label_name': source_label_name,
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


# Hard wall-clock timeout for the entire AI call (connect + generate + transfer).
# Slightly longer than AI_TIMEOUT_SECONDS so the requests-level timeout fires first
# under normal conditions; this is a belt-and-suspenders kill-switch.
AI_HARD_TIMEOUT = int(os.environ.get('AI_TIMEOUT_SECONDS', '90')) + 30


AI_BATCH_SIZE = int(os.environ.get('AI_BATCH_SIZE', '50'))  # DeepSeek output stays under max_tokens at ~50 senders


@celery_app.task
def run_ai_suggestions(job_id, senders, label_names):
    """
    Call the AI provider in the background worker (no HTTP timeout constraint).
    Writes status to ai:{job_id}:status and results to ai:{job_id}:result.
    """
    r = get_redis_client()
    _set_ai_status(r, job_id, {
        'status': 'running',
        'message': f'Analysing {len(senders)} senders…',
    })

    try:
        # Large requests are split into batches of AI_BATCH_SIZE so DeepSeek's answer is never truncated.
        # Each batch runs in a thread with a hard wall-clock timeout; the requests-level timeout=(10, 90)
        # catches most hangs, this catches the rest (e.g. keepalive bytes that reset the per-chunk timer).
        batches = [senders[i:i + AI_BATCH_SIZE] for i in range(0, len(senders), AI_BATCH_SIZE)] or [[]]
        result = {'suggestions': []}
        failed_batches = 0
        for n, batch in enumerate(batches, 1):
            if len(batches) > 1:
                _set_ai_status(r, job_id, {
                    'status': 'running',
                    'message': f'Batch {n}/{len(batches)}: analysing {len(batch)} senders…',
                    'partial_groups': len(result['suggestions']),
                })
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(ai_labeler.suggest_labels, batch, label_names)
                try:
                    part = future.result(timeout=AI_HARD_TIMEOUT)
                    result['suggestions'].extend(part.get('suggestions', []))
                except concurrent.futures.TimeoutError:
                    failed_batches += 1
                    print(f'[ai] batch {n}/{len(batches)} exceeded {AI_HARD_TIMEOUT}s')
                    if len(batches) == 1:
                        raise TimeoutError(
                            f'AI call exceeded hard timeout of {AI_HARD_TIMEOUT}s — '
                            f'no response from provider after {len(senders)} senders'
                        )
                except Exception as e:
                    failed_batches += 1
                    print(f'[ai] batch {n}/{len(batches)} failed: {e}')
                    if len(batches) == 1:
                        raise
        if failed_batches == len(batches):
            raise RuntimeError('All AI batches failed')
        result['failed_batches'] = failed_batches

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


# ── Jev on page load ───────────────────────────────────────────────────────────

JEV_JOB_TTL = 3600
JEV_MAX_SENDERS = int(os.environ.get('JEV_MAX_SENDERS', '2000'))
JEV_ONLOAD_TIMEOUT = int(os.environ.get('JEV_ONLOAD_TIMEOUT', '600'))


HISTORY_CACHE_TTL = int(os.environ.get('HISTORY_CACHE_TTL', str(7 * 24 * 3600)))


class _HistoryCache:
    """Per-user cache of each sender's filing history in Redis (keys hist:<user>:<sender>)."""
    def __init__(self, r, user_key):
        self.r, self.prefix = r, f'hist:{user_key}:'

    def get(self, email):
        raw = self.r.get(self.prefix + email)
        return json.loads(raw) if raw else None

    def set(self, email, votes, sampled):
        self.r.setex(self.prefix + email, HISTORY_CACHE_TTL, json.dumps([votes, sampled]))


@celery_app.task
def run_jev_classify(job_id, senders, label_names, credentials_dict=None, user_key=None):
    """
    Recommend labels for every scanned sender right after the scan. Two sources run IN PARALLEL:
      - Jev on every sender (fast: answers in ~5 s, so the page is usable right away)
      - the user's own Gmail filters and filing history (slower; cached per user for HISTORY_CACHE_TTL)
    History is the stronger signal: when it decides a sender it overwrites Jev's answer, and Jev never
    overwrites history. Answers stream into Redis (hash jev:{job_id}:decisions) so the page updates live.
    Status carries jev_done so the page can unlock while history is still checking.
    """
    r = get_redis_client()
    status_key, dec_key = f'jev:{job_id}:status', f'jev:{job_id}:decisions'
    senders = senders[:JEV_MAX_SENDERS]
    lock = threading.Lock()
    st = {'jev_n': 0, 'jev_done': False, 'checked': 0, 'history_total': 0, 'history_done': not credentials_dict}
    hist_owned, jev_decisions = set(), {}
    hist_result = {'decisions': {}, 'stats': {}}

    def set_status(data):
        r.setex(status_key, JEV_JOB_TTL, json.dumps(data))

    def push_running():
        set_status({'status': 'running', 'phase': 'history' if st['jev_done'] else 'jev',
                    'jev_done': st['jev_done'], 'done': st['jev_n'], 'total': len(senders),
                    'checked': st['checked'], 'history_total': st['history_total']})

    def write(email, decision):
        r.hset(dec_key, email, json.dumps(decision))
        r.expire(dec_key, JEV_JOB_TTL)

    def on_history(email, decision):
        if decision:
            with lock:
                hist_owned.add(email)
                write(email, decision)

    def on_history_progress(checked, total):
        st['checked'], st['history_total'] = checked, total
        push_running()

    def on_jev(email, decision):
        with lock:
            st['jev_n'] += 1
            if decision:
                jev_decisions[email] = decision
                if email not in hist_owned:
                    write(email, decision)
        if st['jev_n'] % 10 == 0:
            push_running()

    def run_history():
        try:
            creds = Credentials(**credentials_dict)
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())

            def gmail_client():
                return build('gmail', 'v1', http=google_auth_httplib2.AuthorizedHttp(
                    creds, http=httplib2.Http(timeout=30)), cache_discovery=False)

            cache = _HistoryCache(r, user_key) if user_key else None
            d, left, stats = history_labeler.classify_from_history(
                gmail_client, senders, on_result=on_history, on_progress=on_history_progress, cache=cache)
            hist_result['decisions'], hist_result['stats'] = d, stats
            print(f"[history] {stats.get('filter', 0)} by filter, {stats.get('history', 0)} by history, "
                  f"{len(left)} not in history, {stats.get('filters_read', 0)} sender filters, {stats.get('seconds')}s")
        except Exception as e:
            print(f'[history] skipped: {type(e).__name__}: {e}')
        finally:
            st['history_done'] = True

    push_running()
    client = None
    hist_thread = None
    try:
        if credentials_dict:
            hist_thread = threading.Thread(target=run_history, daemon=True)
            hist_thread.start()

        stats = {'jev_errors': 0, 'senders_answered': 0, 'seconds': 0, 'model': None, 'jev_calls': 0,
                 'input_tokens': 0}
        client = jev_labeler._make_client() if jev_labeler.jev_available() else None
        if client is not None:
            _d, _u, stats = jev_labeler.classify_with_jev(
                client, senders, label_names, on_result=on_jev, phase_timeout=JEV_ONLOAD_TIMEOUT)
        st['jev_done'] = True
        push_running()

        if hist_thread is not None:
            hist_thread.join(timeout=JEV_ONLOAD_TIMEOUT)

        decisions = {**jev_decisions, **hist_result['decisions']}
        by_action = Counter(d['action'] for d in decisions.values())
        hs = hist_result['stats']
        print(f"[jev] on-load: {by_action.get('use_existing', 0)} existing label "
              f"({hs.get('filter', 0)} filter, {hs.get('history', 0)} history), {by_action.get('no_label', 0)} person, "
              f"{by_action.get('new_in_folder', 0)} new-in-folder, {len(senders) - len(decisions)} unknown, "
              f"{stats['jev_errors']} errors, {stats['jev_calls']} calls, {stats['input_tokens']} input tokens, "
              f"Jev {stats['seconds']}s, history {hs.get('seconds')}s, model={stats['model']}")
        all_failed = stats['senders_answered'] and stats['jev_errors'] == stats['senders_answered']
        set_status({'status': 'failed' if all_failed and not hist_result['decisions'] else 'complete',
                    'jev_done': True, 'done': len(senders), 'total': len(senders),
                    'decided': len(decisions), 'unknown': len(senders) - len(decisions), 'errors': stats['jev_errors'],
                    'from_history': len(hist_result['decisions']),
                    'seconds': stats['seconds'], 'history_seconds': hs.get('seconds'), 'model': stats['model']})
    except Exception as e:
        print(f'[jev] on-load job failed: {type(e).__name__}: {e}')
        set_status({'status': 'failed', 'error': str(e), 'done': st['jev_n'], 'total': len(senders)})
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
