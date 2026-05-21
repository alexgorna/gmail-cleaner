# Session Notes — May 21, 2026

## Project Overview
Gmail Cleaner is a Flask web app that connects via Google OAuth and helps bulk-organize a Gmail inbox by sender. It scans the inbox in real time (Server-Sent Events), shows a ranked table of senders by email count, and lets the user bulk-delete or label emails from each sender.

Stack: Python/Flask, Gmail API, Bootstrap 5, Vanilla JS, Redis sessions, deployed on Railway via Gunicorn.

---

## What We Did Today

### 1. Codebase Evaluation
- Read all source files (`app.py`, `templates/dashboard.html`, `requirements.txt`, `Procfile`)
- Reviewed the full GitHub commit history
- Visited the live app at https://web-production-3e7d0.up.railway.app/ via Chrome to observe it mid-scan
- Produced a full architectural summary of the app end-to-end

---

### 2. Bug Fix — Dropdown Selections Reset After Label Creation
**Commit:** `5beec66` — *"Fix: Restore dropdown selections after new label creation"*

**Problem:** After configuring actions (delete/label) on several rows, creating a new label via the modal would reset all other rows' dropdowns back to "Choose action..." — losing all prior selections visually.

**Root cause:** `confirmLabelCreation()` replaced the `innerHTML` of every row's `<optgroup>` to inject the new label option. The browser lost the selected state for any dropdown whose value lived inside that optgroup.

**Fix:** After the optgroup replacement, loop through all `.action-select` dropdowns and restore their visual selection from the `pendingActions` map.

**File changed:** `templates/dashboard.html`

---

### 3. Feature — Live Label Suggestions While Typing in Create Label Modal
**Commit:** `3d019bf` — *"Feature: Live label suggestions while typing in Create Label modal"*

**What it does:**
- As the user types in the label name input, existing labels whose name **contains** the typed text are shown in a live dropdown below the input (up to 10 results)
- The matching portion of each suggestion is **highlighted in blue**
- Clicking a suggestion fills the input with that label's full name
- If the typed text is an **exact match** to an existing label, a yellow warning banner appears: *"A label with this exact name already exists."*
- Uses `onmousedown` (not `onclick`) to prevent the input losing focus before the click registers

**Files changed:** `templates/dashboard.html`

---

### 4. Feature — "Apply Existing Label" Button on Exact Duplicate Detection
**Commit:** `5123fdb` — *"Feature: Apply Existing Label button when duplicate detected in modal"*

**What it does:**
- When the exact duplicate warning is visible, a green **"Apply Existing"** button appears in the modal footer alongside "Create Label"
- Clicking it applies the already-existing label to the current row (or bulk-selected rows) and closes the modal — no unnecessary label creation
- The button hides/shows in sync with the warning banner, and is reset when the modal opens

**Files changed:** `templates/dashboard.html`

---

### 5. GitHub Authentication Setup
- Diagnosed that the repo was using HTTPS with password auth, which GitHub no longer supports
- Created a Personal Access Token (`repo` scope, expires Aug 19 2026) via github.com/settings/tokens
- Saved the token into the git remote URL so `git push origin main` works from the terminal without prompts

---

### 6. Investigation + Fix — Inbox Scan Cap: Raised to 10,000 + Visible Error State
**Commits:** (part of multi-file commit with app.py + dashboard.html)

**Investigation:** The cap (`MAX_INBOX_SCAN_LIMIT = 5000`) was added Dec 20 2025 as a defensive measure after repeated timeout crashes. It was the last in a series of firefighting commits (watchdog timers, retry logic, heartbeats, gunicorn timeout bumped to 600s). Root causes at the time: Pandas memory overhead (now gone), SSE connection held open during multi-minute scan, Railway reverse-proxy timeouts.

**Changes made:**
- Raised cap from 5,000 → **10,000** (safe given Pandas removal + 600s gunicorn timeout)
- Added `type: 'cap_exceeded'` field to the backend error payload so the frontend can distinguish it from generic errors
- When cap is hit, the **hero section now shows a clear user-facing message** (yellow warning icon, plain-English explanation, count of emails found, link to refresh) instead of silently logging to the hidden system console
- Progress bar is hidden when cap is hit so it doesn't look like the scan is still running

**Files changed:** `app.py`, `templates/dashboard.html`

**Future consideration:** A proper long-term fix would be moving Phase 2 (header fetching) to a background job so the SSE connection doesn't need to stay alive for the full scan duration.

---

### 7. Performance Fix — Apply Actions Slowness
**Commit:** *"Perf: Remove redundant sleep per action; scope label search to inbox only"*

**Problem:** Applying labels to multiple senders felt noticeably slow.

**Root causes found:**
1. A `time.sleep(0.2s)` fired before processing each sender — pure wasted time on top of the rate-limiting sleeps already inside the batch loops
2. The label action searched `from:{email}` across the entire mailbox (inbox, archive, sent, all folders), then ran `batchModify` on every result — even emails already organized elsewhere that didn't need touching

**Fixes:**
- Removed the redundant per-sender sleep
- Changed label action query to `in:inbox from:{email}` — only fetches and processes emails actually in the inbox, which is the correct scope for "move to label"
- Delete action intentionally kept as broad search (`from:{email}`) since delete-all-from-sender is the expected behavior

**Files changed:** `app.py`

---

### 8. Bug Fix — Label Suggestions Overlay Hides Nest Checkbox
**Commit:** deployed ✓

**Problem:** The live suggestions list in the Create Label modal was `position: absolute`, causing it to float over (and hide) the "Nest under parent label" checkbox below the input.

**Fix:** Removed `position: absolute` and `z-index` from the suggestions list, making it part of the normal document flow. When suggestions appear, the checkbox is now pushed down naturally rather than obscured.

**Files changed:** `templates/dashboard.html`

---

### 9. Feature — Gmail Search Link Icon Next to Each Sender
**Commit:** deployed ✓

**What it does:** Each email address row now has a small external-link icon to its right. Clicking it opens a new tab directly to `https://mail.google.com/mail/u/0/#search/{email}` — the Gmail search results for that sender — without leaving the app.

**Implementation details:**
- Icon is the user-supplied SVG (external-link-outline), inlined directly in the JS with `fill="currentColor"` so it inherits CSS color
- Built via DOM API (`createElement`, `createTextNode`) rather than innerHTML to keep XSS safety on the email address
- URL uses `encodeURIComponent` on the email address
- Icon is muted gray at rest (opacity 0.5), turns blue on hover — subtle but discoverable
- Opens with `target="_blank"` and `rel="noopener noreferrer"`

**Files changed:** `templates/dashboard.html`

---

### 10. Bug Fix — Critical Login Broken (InvalidGrantError / PKCE Mismatch)
**Commit:** *"Fix: Restore PKCE code_verifier in callback to fix InvalidGrantError"* — deployed ✓

**Problem:** All users hit a 500 Internal Server Error on login. After the initial fix (forcing `https://` for Railway's SSL termination), the error changed to a user-visible "Login failed (InvalidGrantError). Please try again." message.

**Root cause:** A newer version of `google-auth-oauthlib` automatically enables PKCE (Proof Key for Code Exchange). During `/login`, the library generates a `code_verifier` and sends the corresponding `code_challenge` to Google as part of the authorization URL. In `/callback`, a brand-new `Flow` object is created — which has no knowledge of the original verifier. When `fetch_token()` was called without restoring the verifier, Google rejected the token exchange because the PKCE proof didn't match.

**Two-part fix:**
1. In `/login`: `session['code_verifier'] = flow.code_verifier` — persist the verifier before redirecting to Google
2. In `/callback`: `flow.code_verifier = session.get('code_verifier')` — restore it onto the new flow object before calling `flow.fetch_token()`

**Why this wasn't an issue before:** `requirements.txt` has no version pins. A `google-auth-oauthlib` upgrade silently introduced PKCE, which is the correct security behavior — but the callback never accounted for it.

**Files changed:** `app.py`

**Side note:** The https-forcing fix (item 1 from the login investigation) was also necessary and remains in place. Railway terminates SSL at its load balancer, so `request.url` arrives as `http://` inside the container; oauthlib rejects non-https URLs in production mode. The fix: `if auth_response.startswith('http://'): auth_response = 'https://' + auth_response[7:]`

---

### 11. Feature — Live Inbox Count Deduction + Organized Emails Summary in Hero
**Commit:** deployed ✓

**What it does:**
- After the scan completes, the hero now shows two lines:
  1. *"You have **X emails** in your inbox."* — the X is blue (existing `.hero-count` style)
  2. *"You successfully organized **X emails**."* — the X is Spotify green (`#1DB954`), hidden until at least one action has been applied
- When Apply Actions is clicked, the second line immediately shows **"Processing..."** with three sequentially blinking animated dots (CSS `@keyframes blink-dot` with staggered `animation-delay`)
- While actions are processing, the top inbox count decreases live with each `row_complete` event — the "Processing..." line stays visible
- When the backend signals completion, the "Processing..." text is replaced with the final **"You successfully organized X emails."** in Spotify green
- Session totals reset on each fresh inbox scan

**Implementation details:**
- `currentInboxCount` and `sessionOrganizedCount` JS variables track state across the session
- `row_complete` events update `currentInboxCount` but do NOT touch the organized summary during processing
- The `complete` event is the single place that writes the final organized count
- CSS animation: `.processing-dot` spans use `blink-dot` keyframes (0% opacity → 40% full → 80% back to 0), with `nth-child(2)` at +0.2s and `nth-child(3)` at +0.4s for the wave effect

**Files changed:** `templates/dashboard.html`

---

### 12. Feature — "Processing..." Blinking State During Apply Actions
**Commit:** pending deployment

**What it does:**
- As soon as Apply Actions is clicked, the "You successfully organized X emails" line (whether previously visible or not) switches to "Processing..." with three blinking animated dots
- The top inbox count (`You have X emails in your inbox`) continues deducting live as each sender's emails are moved
- When all actions finish, the blinking text is replaced with the final "You successfully organized X emails" in Spotify green
- This gives clear visual feedback that work is happening, without prematurely showing a count mid-process

**Files changed:** `templates/dashboard.html`

---

### 13. Architecture — Background Job Refactor (Celery + Redis)
**Commit:** pending deployment

**Motivation:** The SSE-based scan held an HTTP connection open for the full duration of Phase 2 (up to 3–4 minutes for large inboxes). This caused Railway proxy timeouts, required a 600s Gunicorn timeout, and made concurrent users impossible since each scan occupied a long-running thread. With commercialization in mind, this was the highest-leverage architectural change to make first.

**New architecture:**
- `POST /api/start_scan` — instantly queues the scan job and returns a `job_id` (milliseconds)
- Celery worker picks up the job and runs Phase 1 + Phase 2 independently of any HTTP connection
- Worker writes progress snapshots and log lines to Redis under `scan:{job_id}:progress` and `scan:{job_id}:logs` (2-hour TTL)
- `GET /api/scan_status/<job_id>` — returns current progress + any new log lines since `log_offset`
- `GET /api/scan_results/<job_id>` — returns final sender data once status is `complete`
- Frontend polls `/api/scan_status` every 1.5 seconds (each call completes in <100ms)

**New files:**
- `celery_app.py` — Celery app config (Redis broker/backend, 30-min soft limit, 35-min hard kill)
- `tasks.py` — `run_inbox_scan` Celery task with full Phase 1 + Phase 2 scan logic

**Files changed:** `app.py`, `templates/dashboard.html`, `requirements.txt`, `Procfile`

**What was removed:** `/api/scan_stream` SSE endpoint and the `EventSource` client in JS

**What was added to Procfile:**
```
worker: celery -A tasks worker --loglevel=info --concurrency=2
```
Railway runs both `web` and `worker` processes from the same deploy. On other platforms (Fly.io, VPS), the worker runs as a separate process/service.

**Security:** Job IDs are UUIDs stored in the user's session. `scan_status` and `scan_results` verify the `job_id` matches `session['scan_job_id']` — users cannot access each other's jobs.

**Cap exceeded handling:** The worker sets `status: failed, error: cap_exceeded` in Redis; the poll handler renders the same user-facing warning as before.

**Backup of pre-refactor stable state:** `backup_stable_2026_05_21/` in project root.

---

## Pending / Next Steps
- Consider pinning versions in `requirements.txt` to prevent future silent regressions from library upgrades
- Google OAuth app verification (required before commercializing — sensitive scopes need Google review)
- Continue working through the feature backlog
