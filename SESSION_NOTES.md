# Session Notes — May 21, 2026

## Project Overview
Gmail Cleaner is a Flask web app that connects via Google OAuth and helps bulk-organize a Gmail inbox by sender. It scans the inbox as a background job (Celery + Redis), shows a ranked table of senders by email count, and lets the user bulk-delete or label emails from each sender.

Stack: Python/Flask, Celery, Gmail API, Bootstrap 5, Vanilla JS, Redis (sessions + job state), deployed on Railway via Gunicorn (web) + Celery worker.

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
**Commit:** deployed ✓

**What it does:**
- As soon as Apply Actions is clicked, the "You successfully organized X emails" line (whether previously visible or not) switches to "Processing..." with three blinking animated dots
- The top inbox count (`You have X emails in your inbox`) continues deducting live as each sender's emails are moved
- When all actions finish, the blinking text is replaced with the final "You successfully organized X emails" in Spotify green
- This gives clear visual feedback that work is happening, without prematurely showing a count mid-process

**Files changed:** `templates/dashboard.html`

---

### 13. Architecture — Background Job Refactor (Celery + Redis)
**Commit:** `00916a4` — deployed ✓ (Railway: web + worker + Redis all Online)

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

### 14. Feature — AI Label Suggestions (DeepSeek)
**Commit:** `ea19fb1` — deployed ✓

**What it does:**
- After a scan, a **✦ AI** button appears in the toolbar
- Clicking it sends the sender list + user's existing label list to DeepSeek, which groups senders by company/org and recommends a Gmail label for each group (following the user's existing label structure)
- Per-row: a small inline hint appears below each sender address — "Existing label **Finance** recommended." or "Creating label **Stripe** recommended." — with an **Apply AI** and **✕** button
- Bulk: **Apply AI** / **Dismiss AI** buttons appear in the toolbar once suggestions are loaded
- Applying a suggestion pre-fills the dropdown (use_existing selects the label; create_new silently creates it via API first, then selects it) — no emails are moved until the user clicks Apply Actions

**Architecture (pluggable, flag-guarded):**
- `ai_labeler.py` — self-contained adapter; swap provider by adding to `PROVIDER_CONFIGS` and setting `AI_PROVIDER` env var; disable entirely with `AI_LABELING_ENABLED=false`
- Default provider: `deepseek` (`deepseek-v4-flash`, cheapest model), OpenAI-compatible API
- Structured JSON output enforced via `response_format: {type: 'json_object'}` + schema in system prompt
- New endpoint: `POST /api/suggest_labels` — reads senders from Redis scan results, fetches labels from Gmail API, calls `ai_labeler.suggest_labels()`

**New files:** `ai_labeler.py`
**Files changed:** `app.py`, `templates/dashboard.html`, `requirements.txt` (added `requests`)
**Railway env var added:** `DEEPSEEK_API_KEY`

---

### 15. Fix — JSON Parse Errors from DeepSeek
**Commits:** `937e750`, `e603613` — deployed ✓

**Problems seen:**
1. `Expecting ',' delimiter: line 816 column 49` — malformed JSON mid-response (unescaped character)
2. `Expecting value: line 1 column 1 (char 0)` — DeepSeek returned empty content string (known flakiness in JSON mode)

**Fixes in `ai_labeler.py`:**
- `_clean_json()` — strips markdown fences, extracts outermost `{...}` block before parsing
- Auto-retry with half senders on `JSONDecodeError` or `ValueError`
- Increased `max_tokens` 8000 → 16000; default `AI_MAX_SENDERS` 1000 → 500
- Empty content treated as `ValueError` (triggers retry); `reasoning_content` checked as fallback
- Rich logging: `finish_reason`, token counts in system logs

---

### 16. Fix — AI Call Timeout (232s Railway Proxy Limit)
**Commit:** `dce42f1` — deployed ✓

**Problem:** DeepSeek API call blocked the Flask worker thread for ~232 seconds, hitting Railway's reverse-proxy timeout and dropping the connection.

**Fix:** Moved the AI call to a Celery background task (same pattern as the inbox scan).

**Architecture changes:**
- `POST /api/suggest_labels` now queues a Celery job and returns `{job_id}` instantly (milliseconds)
- New `GET /api/ai_status/<job_id>` — returns `{status, message}` from Redis; worker writes `running`/`complete`/`failed`
- New `GET /api/ai_results/<job_id>` — returns full suggestions JSON once complete
- `tasks.py`: added `run_ai_suggestions` Celery task + `_set_ai_status` helper; Redis keys `ai:{job_id}:status` and `ai:{job_id}:result` (1-hour TTL)
- `dashboard.html`: `requestAISuggestions()` rewritten — POST → receive `job_id` → poll `/api/ai_status` every 2s → on complete fetch `/api/ai_results` → call `processAISuggestions()`

**Files changed:** `app.py`, `tasks.py`, `templates/dashboard.html`

---

### 17. Feature — Parent Label Auto-Creation, Email Subjects in AI Prompt, Mobile UI, Bulk-Apply Bug Fix
**Commit:** `9184375` — deployed ✓

**Four improvements shipped together:**

**A. Parent label auto-creation:**
- Previously, if the AI suggested a nested label like `Finance/Stripe` and the `Finance` parent didn't yet exist, the child label creation would fail silently.
- `applyAISuggestion()` now checks for the parent first. If not found in `existingLabels`, it calls `POST /api/create_label` to create it, pushes the result into `existingLabels`, and calls `regenerateLabelOptions()` so the dropdown reflects the new parent before creating the child.
- Multiple children sharing the same new parent only trigger one parent creation (the second call lands on an already-created label and gracefully falls back to a lookup by name).

**B. Email subjects in AI prompt:**
- The inbox scan now collects up to 3 `Subject` headers per sender (capped at 120 chars each) during Phase 2 batch fetching, stored in `subjects_by_email`.
- Results JSON includes `"subjects": [...]` per sender entry.
- `POST /api/suggest_labels` enriches each sender with its subjects before passing to the AI worker.
- `ai_labeler._call_provider()` formats subjects as `email | subjects: "Sub1", "Sub2"` in the prompt, giving the model better context for grouping and `no_label` decisions.
- `metadataHeaders` in the batch request expanded to `['From', 'Subject']`.

**C. Initial mobile UI overhaul:**
- Controls bar stacks vertically on screens ≤768px; action buttons wrap and stretch full-width.
- Count column hidden on mobile via `d-none d-sm-table-cell` on `<th>` / `<td>`.
- Action select narrowed; table padding and font sizes reduced for small screens.
- (Later enlarged in item 19 after user feedback about touch target size.)

**D. Bulk-apply bug fix:**
- **Bug:** Running AI, filtering rows with the search box, then clicking "Apply AI (All)" — suggestions disappeared and nothing was applied.
- **Root cause 1:** `_selectLabelInRow()` only set `pendingActions` as a fallback if the `<select>` DOM element wasn't found. With a search filter active, filtered-out rows have no DOM element, so `pendingActions` was never written for them.
- **Root cause 2:** `applyAllAI()` didn't call `renderTable()` after the loop, so the table didn't reflect the newly-applied actions.
- **Fix:** `_selectLabelInRow()` now unconditionally writes `pendingActions[email]` first, then optionally sets the select's value if the element exists. `applyAllAI()` calls `renderTable()` after the loop.

**Files changed:** `app.py`, `tasks.py`, `templates/dashboard.html`

---

### 18. Fix — Limit AI to Displayed Rows; Remove Provider Name from Logs
**Commit:** `9250b22` — deployed ✓

**Problems:**
1. With a full scan, 773 senders were sent to the AI → `finish_reason=length` (response truncated at 52,951 chars), causing a parse error.
2. System log said "sending X senders to DeepSeek..." — baking in the provider name even though the stack is designed to be provider-agnostic.

**Fixes:**
- `requestAISuggestions()` now slices `filteredData` to the currently displayed page (`filteredData.slice(start, end).map(r => r.email)`) and sends only those senders to the AI. Typically 50 rows per page — well within token limits.
- Log message changed to `"AI: sending X senders (background job)..."` with no provider name.

**Files changed:** `templates/dashboard.html`

---

### 19. Feature — `no_label` AI Hint + Enlarged Mobile Touch Targets
**Commit:** `4b4a1f0` — deployed ✓

**What it does (two changes in one commit):**

**A. no_label UI:**
- When the AI identifies a sender as ad-hoc, infrequent, or non-transactional (e.g. a personal Gmail contact), the AI hint now shows: *"Applying a label not recommended."* in amber text with only the ✕ dismiss button — no "Apply AI" button, since there's no label to apply.
- For `use_existing` and `create_new` suggestions the hint is unchanged.
- The `no_label` action is stored in `aiSuggestions` and the hint rendering branches on `suggestion.action === 'no_label'`.

**B. Mobile CSS — fat-thumb touch targets:**
- All interactive controls raised to `min-height: 44px` (action buttons, AI bulk buttons, action select, pagination buttons).
- Font sizes raised to `0.875rem` for buttons and selects (from 0.68–0.78rem).
- AI hint apply/dismiss buttons raised to `min-height: 36px` with comfortable padding.
- Padding on `.action-select` increased to `8px 24px 8px 10px`.

**Files changed:** `templates/dashboard.html`

---

### 20. Fix — Wrong DeepSeek Model Name (5-Minute Hangs)
**Commit:** `6af2bc6` — deployed ✓

**Problem:** The AI button would queue a job and then hang for 5+ minutes with status "running", eventually timing out.

**Root cause 1 — invalid model name:** `PROVIDER_CONFIGS` had `model: 'deepseek-v4-flash'`, which doesn't exist. DeepSeek's API silently routed invalid model names to `deepseek-reasoner` (R1), their chain-of-thought reasoning model. R1 works through problems step-by-step before answering and routinely takes 5–10 minutes for a prompt of this size. The correct fast/cheap model name is `deepseek-chat` (DeepSeek V3).

**Root cause 2 — ineffective timeout:** `requests` was called with `timeout=90` (a single int). This form only covers the time until the first byte of the HTTP response is received — once DeepSeek sent back `200 OK` headers, the 90-second timer stopped, allowing the response body to stream indefinitely.

**Fixes:**
- Model corrected: `'deepseek-v4-flash'` → `'deepseek-chat'` in `PROVIDER_CONFIGS`.
- Timeout changed to `timeout=(10, 90)` — the tuple form sets a 10-second connect timeout and a 90-second *read* timeout applied per chunk. If the server goes silent for 90 seconds between bytes, a `ReadTimeout` is raised and the Celery task catches it, setting status to `failed`.

**Files changed:** `ai_labeler.py`

---

### 21. Feature — Highlight Rows Where AI Has Been Applied
**Commit:** `7dced13` — deployed ✓

**What it does:**
- Clicking **Apply AI** on a row immediately gives it a light blue background with a blue left border, so the user can see at a glance which rows they've already acted on.
- The highlight persists through pagination, search filtering, and `renderTable()` re-renders — it's stored in a JS `Set` (`aiAppliedRows`), not just a CSS class on the live DOM element.
- If the user later clicks **Apply Actions** and the row moves to the greyed-out `row-processed` state, that takes visual priority over the AI highlight.
- Running a new inbox scan resets `aiAppliedRows` so highlights don't carry over between sessions.

**Implementation:**
- `let aiAppliedRows = new Set()` declared alongside `aiSuggestions`.
- `applyAISuggestion()` calls `aiAppliedRows.add(email)` and immediately sets `tr.className = 'row-ai-applied'` on the live row element (no full re-render needed).
- `renderTable()` checks `aiAppliedRows.has(row.email)` and sets the class during each rebuild.
- CSS: `.row-ai-applied { background-color: #eff6ff; border-left: 3px solid #3b82f6; }`

**Files changed:** `templates/dashboard.html`

---

### 22. Fix — Remove Broken `via.placeholder.com` Avatar Fallback
**Commit:** `8263e33` — deployed ✓

**Problem:** The user avatar `<img>` tag used `https://via.placeholder.com/32` as its initial `src`. The app replaced this with the real Google profile picture once `/api/user_info` returned, but in the meantime the browser tried to fetch from `via.placeholder.com` — a third-party service that has been unreliable and frequently down — producing a `net::ERR_CONNECTION_CLOSED` error in the console on every page load.

**Fix:** Replaced the external URL with an inline SVG data URI — a simple grey circle with a white silhouette figure. No external request is ever made. The Google profile picture still loads on top of it as before.

**Files changed:** `templates/dashboard.html`

---

### 23. Feature — Skip Inbox / Auto Label Checkboxes Per Label Row
**Commit:** `30156f2` — deployed ✓

**What it does:**
- Whenever a label is selected in a row's action dropdown, two small checkboxes appear directly below it: **Skip Inbox** and **Auto Label**, both checked by default.
- The four combinations give the user full control over what happens to emails from that sender:

| Skip Inbox | Auto Label | Behaviour |
|---|---|---|
| ✓ | ✓ | Default (unchanged) — existing inbox emails archived to label; Gmail filter created so future emails also skip inbox |
| ✓ | ✗ | One-time cleanup — existing emails archived, no filter created (future emails land in inbox as normal) |
| ✗ | ✓ | Tag only — existing emails get the label but stay in inbox; filter created so future emails are also tagged (but not archived) |
| ✗ | ✗ | Label existing emails as a tag only, no filter — completely non-destructive |

**Implementation details:**
- `pendingActions[email]` extended with `skipInbox: bool` and `autoLabel: bool` (both default `true`).
- `handleActionChange()` sets defaults when a label is first selected, preserving any values already set if the user switches between labels on the same row.
- `toggleLabelOption(checkboxEl, field)` updates the relevant flag in `pendingActions` on each checkbox change.
- Checkboxes are rendered inside the action `<td>` via `tr.innerHTML` in `renderTable()`, with their `checked` state and `display` driven from `pendingActions[email]` — so they survive pagination and filter changes correctly.
- `app.py apply_actions` reads `item.get('skipInbox', True)` and `item.get('autoLabel', True)`:
  - Filter creation is skipped entirely when `autoLabel` is false.
  - When `autoLabel` is true, `removeLabelIds: ['INBOX']` is included in the filter action only when `skipInbox` is true.
  - `batchModify` on existing messages omits `removeLabelIds: ['INBOX']` when `skipInbox` is false.

**Backlog note:** Unsubscribe support (detect `List-Unsubscribe` header during scan, handle `mailto:` / one-click POST / manual link) deferred to future iteration.

**Files changed:** `app.py`, `templates/dashboard.html`

---

## Pending / Next Steps
- End-to-end test of AI suggestions on the live app
- Consider pinning versions in `requirements.txt` to prevent future silent regressions from library upgrades
- Google OAuth app verification (required before commercializing — sensitive scopes need Google review)
- Continue working through the feature backlog

---

### 24. UX Epic — Designer Report: 5-Item Polish Pass + Dev Note

**Commit:** `e1148d0` — *"UX Epic: header hierarchy, zebra rows, selection badge, warning contrast, sub-header, AI tooltips"*

**Context:** A web designer evaluated the app and produced a 5-item report (plus a developer note). All items were implemented in a single epic commit to `templates/dashboard.html`.

**Backup taken:** `backup_ux_epic/dashboard.html.pre_ux_epic` (1292 lines, pre-epic state)

---

#### Item 1 — Header Action Hierarchy

**Problem:** "Dismiss AI" and "Apply AI" (bulk) were both using full outline-button styles (`btn-outline-secondary` and `btn-outline-primary fw-bold`), competing visually with the primary "Apply Actions" CTA. Export CSV and utility buttons had inconsistent weight.

**Fix:**
- **Dismiss AI** → `btn btn-light text-secondary border rounded-pill` (ghost, same weight as utility row)
- **Apply AI** (bulk) → `btn btn-outline-secondary rounded-pill fw-bold` (secondary outline — actionable but subordinate)
- **Apply Actions** → unchanged `btn btn-primary` (dominant CTA)
- **CSV / Reload / AI** → unchanged `btn btn-light text-secondary border rounded-pill`

Now: Apply Actions is clearly the primary action; bulk AI actions are secondary; utilities are tertiary.

---

#### Item 2 — Table Row Visual Separation

**Problem:** All rows had identical white background; hover effect was too subtle (#f8fafc).

**Fix (CSS additions):**
```css
/* Zebra striping */
.table-custom tbody tr:nth-child(even) td { background-color: #f8fafc; }

/* Stronger hover */
.table-custom tbody tr:hover td { background-color: #dbeafe !important; }

/* AI-applied rows override zebra (but still yield to hover) */
.row-ai-applied td { background-color: #eff6ff !important; }

/* Action column subtle left border for visual grouping */
.table-custom td:last-child { border-left: 1px solid #f1f5f9; }
.table-custom th:last-child { border-left: 1px solid #e2e8f0; }
```

The `.row-ai-applied` rule was moved from TR-level to TD-level so it wins over zebra striping from the new nth-child rule.

---

#### Item 3 — Bulk Selection Counter Badge

**Problem:** Selected row count ("0 Selected") was a plain `fw-bold small` span — easy to miss.

**Fix:**
- Restyled as `.selection-badge` pill: blue background (#eff6ff), blue text (#1d4ed8), blue border (#bfdbfe), rounded-20
- Text updated from "X Selected" → "X item(s) selected" (grammatically correct)
- Added **Deselect All** button (`.btn-deselect-all`) inline in the bulk actions bar — clears all checked rows and hides the bulk bar
- `deselectAll()` JS function added

---

#### Item 4 — Accessibility & Color Contrast (no_label Warning)

**Problem:** `no_label` AI hint text used `color:#92400e` which fails WCAG 2.1 AA contrast ratio. Color alone conveyed warning state (no icon).

**Fix:**
- Color updated: `#92400e` → `#C2410C` (WCAG AA compliant on white/light backgrounds)
- Added Bootstrap Icon `bi-exclamation-triangle-fill` before text (color is no longer the sole indicator)
- Wrapper: `.ai-no-label-warning { color: #C2410C; display: inline-flex; align-items: center; gap: 4px; }`
- HTML generated: `<span class="ai-no-label-warning"><i class="bi bi-exclamation-triangle-fill" aria-hidden="true"></i> Applying a label not recommended.</span>`

---

#### Item 5 — Contextual Sub-Header

**Problem:** No contextual information about the scan scope shown to the user after scanning.

**Fix:**
- Added `<div id="scan-subheader" class="scan-subheader">` between controls-wrapper and table — initially hidden
- After scan completes: populated as *"Grouped by X unique senders across Y total emails"*
- When search is active: updates to *"Showing X senders (Y emails) — filtered from A unique senders across B total emails"*
- `updateSubheader()` JS function called from `handleSearch()` and after scan completion
- Styled as a thin strip (#fafbfc background, 0.78rem text, #64748b color)

---

#### Item 6 (Dev Note) — On-Demand AI Info Icons with Accessible Tooltips

**Problem:** AI suggestion hints showed label name with no context about what "use existing" vs "create new" means. No keyboard-accessible explanation.

**Fix:**
- Added `.ai-info-btn` button next to the hint text for `use_existing` and `create_new` suggestions
- Uses Bootstrap 5's built-in tooltip: `data-bs-toggle="tooltip"` + `data-bs-placement="top"`
- Tooltip text:
  - `use_existing`: *"Label 'X' already exists in your Gmail — emails will be organised under it."*
  - `create_new`: *"A new label 'X' will be created [under 'Parent']."*
- Accessibility: `tabindex="0"`, `aria-label="More info about this suggestion"`, focus-visible outline
- Tooltips initialized after each `renderTable()` call via: `new bootstrap.Tooltip(el, { trigger: 'hover focus' })`
- CSS: `.ai-info-btn:focus { outline: 2px solid #bfdbfe; }` for visible keyboard focus ring

---

**All 6 items committed and pushed in one epic commit.** Railway auto-deploys on push to `main`.

---

### 25. Mobile Responsive Epic — Designer Report (412×915 viewport)

**Commit:** `4ff5b5b` — *"Mobile Responsive Epic: card stack, bottom sheet, tooltip overlay, touch targets, compact sub-header"*

**Context:** The web designer evaluated the app at 412×915 (Pixel 6 / Galaxy S22 equivalent) and filed a mobile UX report with 2 HIGH priority items, 2 MEDIUM, 1 LOW, and an A11Y section. All items were implemented in a single epic commit to `templates/dashboard.html`.

---

#### HIGH-1 — Card Stack View (Table → Cards)

**Problem:** The HTML `<table>` rendered with horizontal scroll on narrow viewports, making senders and actions hard to read and tap.

**Fix — CSS Grid card layout at ≤768px:**
- `thead { display: none }` — column headers hidden on mobile
- Each `tbody tr` becomes a `display: grid !important` card with:
  ```
  grid-template-areas: "check email count"
                        "check action action"
  grid-template-columns: 48px 1fr auto
  ```
- Cards get `border: 1px solid #e2e8f0`, `border-radius: 12px`, `margin-bottom: 8px`, `background: white`
- Zebra striping moved from td-level (UX Epic) to tr-level on mobile (`tr:nth-child(even) { background: #f8fafc !important; }`) — td backgrounds set to `transparent` to avoid conflict
- Action column (`td:nth-child(4)`) spans full width, has a subtle top border as a divider
- `action-select` expands to `width: 100%` inside the card

---

#### HIGH-2 — Touch Targets ≥ 44px

**Problem:** Several controls were too small for reliable touch (checkbox 13px, AI hint buttons ~28px tall, info icon ~16px).

**Fix:**
- Checkbox `td` is 48px wide; `form-check-input` set to `width: 20px; height: 20px`
- `btn-ai-apply` and `btn-ai-dismiss` both set to `min-height: 34px`
- `.ai-info-btn` on mobile: `min-width: 34px; min-height: 34px; display: inline-flex; align-items: center; justify-content: center`
- All pagination buttons already ≥ 44px from earlier work

---

#### MEDIUM-1 — Sticky Footer / Bottom Sheet for Bulk Actions

**Problem:** The desktop bulk-actions bar (in the controls row) disappeared into the page on mobile — no sticky affordance for selection feedback.

**Fix:**
- Added `#mobile-bottom-sheet` fixed to `bottom: 0`, full width, `border-radius: 16px 16px 0 0`
- Hidden by default via `transform: translateY(110%)`; shown with `.visible` class → `translateY(0)`, animated with `cubic-bezier(0.4, 0, 0.2, 1)` transition
- Contents: selected count badge, Deselect All, Delete button, Clear button, label `<select>` (mirrors labels from `populateBulkDropdown()`)
- Desktop `#bulk-actions-container` hidden on mobile via `display: none !important`
- `updateSelection()` adds/removes `.visible` class and updates count text
- `populateBulkDropdown()` also populates `#mobile-sheet-label-select` with the same label list
- `applyMobileSheetLabel(select)` — helper to route label selection or "Create New Label" from the sheet

---

#### MEDIUM-2 — Compact Sub-Header on Mobile

**Problem:** The contextual sub-header sentence was too long for 412px (e.g. *"Grouped by 744 unique senders across 1,561 total emails"*).

**Fix:** `updateSubheader()` now checks `window.innerWidth <= 768`:
- Mobile format: `"744 senders, 1,561 emails total"` / `"12 senders, 38 emails (filtered)"`
- Desktop format: unchanged long form
- A `resize` event listener re-runs `updateSubheader()` so the text updates if the user rotates their device

---

#### A11Y — Mobile Tooltip Replacement

**Problem:** Bootstrap tooltips use `hover` and `focus` triggers. On touch-only devices, `hover` never fires — tapping the ⓘ info icon did nothing.

**Fix:**
- `infoBtn` gets a `data-tooltip-text` attribute during `renderTable()`
- A `click` event listener detects touch devices (`'ontouchstart' in window || navigator.maxTouchPoints > 0`)
- On touch tap: `showMobileTooltip(text)` populates `#mobile-tooltip-overlay` with the tooltip text and makes it visible
- The overlay is a full-screen semi-opaque backdrop with a centred white card, a text paragraph, and a "Close" button
- `closeMobileTooltip()` removes the `.visible` class; tapping outside the box also closes it
- Bootstrap tooltip still fires normally on desktop (hover/focus) — no regression

---

#### Touch Feedback

- `tr:active { background: #f0f9ff !important }` with `td { background-color: transparent !important }` for press state on card rows
- `btn-ai-apply:active { background: #dbeafe }`
- `btn-ai-dismiss:active { background: #e2e8f0 }`

---

**Files changed:** `templates/dashboard.html` only. Commit pushed; Railway auto-deploys on push to `main`.

---

### 26. Feature — Label Manager (`/labels` page)

**What it does:**
- Full label management page at `/labels` with a Finder-style collapsible tree
- Inline rename (click pencil → type → Enter to save, Escape to cancel)
- Move modal (change parent via select → renames the full path including children)
- Delete with optional cascade (checkbox to also delete all child labels)
- Create new label with optional parent
- Search/filter with live highlighting
- Stats row: total labels, folders, flat labels, max depth
- AI Reorganize panel (slides in from right): sends all label names to DeepSeek, returns merge/rename/move/group suggestions; accept/skip per suggestion; "Apply changes" streams operations back with live log

**Backend routes added to `app.py`:**
- `GET /labels` — renders `templates/labels.html`
- `GET /api/labels_tree` — returns nested tree of user labels with `id`, `name`, `fullName`, `children`, `messagesTotal`
- `POST /api/labels/rename` — renames a label and all its children (Gmail has no native move; rename is the mechanism); returns `childrenRenamed` count
- `POST /api/labels/delete` — deletes a label, optionally cascading to children
- `POST /api/labels/ai_reorganize` — calls DeepSeek directly (not via Celery) with all label names; returns `{suggestions, totalLabels}`
- `POST /api/labels/apply_plan` — streaming endpoint; executes a list of accepted operations server-side, yielding NDJSON progress lines

**AI reorganize (`api_ai_reorganize`):**
- Calls DeepSeek `deepseek-chat` directly via `import requests as _http` (same pattern as `ai_labeler.py` — NOT the openai package)
- Uses `DEEPSEEK_API_KEY` env var
- `response_format: {type: json_object}`, `temperature: 0.3`
- `max_tokens: 4000` (was 2000 — bumped after truncation error; `ai_labeler.py` uses 16000 for the same reason, see item 15)
- `timeout=(10, 90)` — tuple form for connect+read timeouts (same as `ai_labeler.py`)
- Checks `finish_reason == 'length'` and returns a user-facing error instead of a parse crash
- JSON cleaned with regex (same robust approach as `ai_labeler._clean_json`)
- Returns suggestions typed as `merge`, `rename`, `move`, `group` — each with `description`, `reason`, `params`
- Resolves Gmail label IDs upfront (attached to `params` before returning to client)

**New file:** `templates/labels.html`
- Matches dashboard design exactly: same CSS variables, same navbar, same blue gradient hero, same card/shadow, same `.console-window` CSS
- CSRF: `<meta name="csrf-token">` + `csrfHeaders()` helper function — same as dashboard
- System log: `#scan-debugger` with `.console-window` class, "System ready." hardcoded on load, toggle button always visible, `log(msg, type)` function identical in behavior to dashboard's `logToScanDebugger()`
- AI errors write to the console log in addition to showing in the AI panel

**Key lessons / pitfalls:**
- DO NOT use the `openai` package — the project calls DeepSeek via raw `requests` HTTP. Always read `ai_labeler.py` before adding any AI call.
- CSRF: all POST routes must receive `X-CSRFToken` header; Flask-WTF returns 400 HTML which breaks JSON parsing in JS (check `csrfHeaders()` helper).
- Gmail has no "move label" API — moving is implemented as a rename to a new full path; children must be renamed individually.
- `max_tokens=2000` was the initial (too-low) default for the reorganize endpoint; it caused `Unterminated string` JSON parse errors. Always use ≥4000 for label list responses.

**Files changed:** `app.py`, `templates/labels.html` (new), `templates/dashboard.html` (Labels nav link added)

---

### 27. Fix — Merge Suggestion UX + AI Prompt Quality (May 29 2026)

**Context:** User accepted a DeepSeek suggestion to "Merge '1 Password' into 'Security/Bitwarden'" expecting a new Security/1Password label to be created. Instead, the merge permanently deleted "1 Password" and folded all its emails into the existing Bitwarden label with no way to distinguish them. Multiple prompt/UI fixes followed.

**Fix 1 — Destructive merge warning in card UI (`templates/labels.html`):**
- Every merge suggestion card now shows a red warning box below the params:
  `"⚠ Destructive & irreversible. Source labels are permanently deleted and all their emails folded into the target. Cannot be undone."`

**Fix 2 — AI prompt: strict merge rules (`app.py`, `api_ai_reorganize`):**
Added explicit MERGE RULES section to the DeepSeek system prompt:
- NEVER merge a child label into its own parent/ancestor (e.g. `Aluguel/CondLink` → `Aluguel`)
- NEVER merge labels representing different companies/products/services (1Password ≠ Bitwarden)
- Only merge truly identical labels (same name, different case; or two names for one service)
- MERGE DIRECTION: when a flat stray and a nested label are duplicates, always keep the nested one — merge the flat stray INTO the nested one (e.g. sourceNames=["Sixt"], targetName="Viagens/SIXT")
- NEVER include a commentary/no-op entry to explain why a suggestion was skipped — just omit it entirely

**Fix 3 — Backend guard: block child→parent merges (`app.py`, `api_labels_apply_plan`):**
Even if AI hallucinates a child→parent merge, the backend now rejects it:
```python
if src_name.startswith(target_name + '/') or target_name.startswith(src_name + '/'):
    yield json.dumps({'msg': f'  ⛔ Blocked: ...'}) + '\n'
    continue
```

**Fix 4 — Frontend filter: drop no-op AI suggestions (`templates/labels.html`):**
After receiving the AI response, suggestions are filtered before rendering:
- `merge`: must have non-empty `targetName` and at least one `sourceNames` entry
- `rename`: must have both `oldName` and `newName` and they must differ
- `move`: must have `labelName` and `newParentName`
- `group`: must have `newParentName` and at least one `childNames` entry
- Filtered count logged: "X invalid filtered out"

**Fix 5 — Auto-update Gmail filters on merge (`app.py`, `api_labels_apply_plan`):**
After deleting each source label during a merge, the backend now:
1. Lists all Gmail filters via `service.users().settings().filters().list()`
2. Finds any filter whose `action.addLabelIds` contains the deleted source label ID
3. Deletes that filter and recreates it pointing to the target label ID
4. Logs: `↻ Updated N filter(s) to use "TargetLabel"`
- Only merges require this — rename/move/group preserve label IDs

**Fix 6 — Rename reverts on Enter (blur race condition) (`templates/labels.html`):**
Root cause: `submitRename` called `renderTree()` synchronously which removed the focused input from DOM, firing `blur` → `cancelRename()` which aborted the rename before the fetch happened.
Fix: added `renameSubmitting` flag; `cancelRename()` returns immediately if `renameSubmitting` is true.
```js
let renameSubmitting = false;
function cancelRename() { if (renameSubmitting) return; renamingId = null; renderTree(); }
async function submitRename(...) {
  renameSubmitting = true; renamingId = null; renderTree(); renameSubmitting = false;
  // fetch happens here safely
}
```

**Files changed:** `app.py`, `templates/labels.html`
**Commits:** `5796fad`, `61345fc`, `6548a60`, `a6d33d0`, `23d4777`, `e413d4a`
