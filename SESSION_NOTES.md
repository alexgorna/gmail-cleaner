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

---

### 28. Fix — Rename Timeout + Cascade Verification (May 29 2026)

**Problem:** Renaming a label showed "Renamed X → Y" in the system log but Gmail did not actually change the label name. Root cause: the `api_label_rename` endpoint was calling `service.users().labels().get()` as a pre-fetch step to read the old label name — this extra round-trip was timing out on Railway, causing the entire request to fail. Because the timeout returned a JSON error body `{"error": "The read operation timed out"}`, the frontend `res.json()` parsed it successfully and `data.error` was truthy — but earlier test showed it logged success, suggesting the error path had a separate issue.

**Fix:**
- Removed the unnecessary `labels().get()` pre-fetch — the client already knows `oldFullName` and sends it in the request body
- Backend now expects `oldFullName` from the client alongside `labelId` and `newFullName`
- Added post-patch verification: after `labels().patch()`, checks that `updated.get('name') == new_full_name`; returns a 500 error if Gmail didn't apply the rename
- Frontend `submitRename` updated to send `oldFullName` in the request body

**Cascade behavior (already correct, confirmed):**
When renaming a parent label (e.g. "Banco" → "Banks"), the endpoint:
1. Fetches all labels once via `labels().list()`
2. Finds every child whose name starts with `"Banco/"` (e.g. "Banco/Savings", "Banco/Credit Card")
3. Renames each child in parallel (ThreadPoolExecutor, 5 workers): replaces prefix → "Banks/Savings", "Banks/Credit Card"
4. Then renames the parent itself
5. Returns `childrenRenamed` count to client for display in the log

**Files changed:** `app.py`, `templates/labels.html`
**Commits:** `2d93821`, `68adc51`

---

### 28b. Feature — Queue + Apply Changes UX for /labels (May 29 2026)

**Context:** User identified that the labels page fired each action immediately (rename on Enter, delete after one modal confirm), which is the opposite of the dashboard pattern where you queue everything then click Apply once.

**Implementation:**
- All three tree actions — rename, move, delete — now queue into `pendingManualOps` array instead of executing immediately
- Each queued op shows a visual chip on the label row: `✏ → NewName` (rename), `→ Parent` (move), `🗑 delete` / `🗑 + children` (delete), all with an `×` cancel button
- A counter badge in the toolbar shows the total of AI-accepted + manual-queued ops; "Apply Changes" button stays disabled at zero
- `applyAccepted()` drains both `accepted` (AI) and `pendingManualOps` (manual) into a single operations array, sends to `/api/labels/apply_plan` streaming endpoint, and clears both queues on completion
- `cancelManualOp(labelId)` removes an op from the queue and re-renders the tree
- Message counts displayed in parentheses next to each label name, fetched via Gmail batch API (25 per chunk, 150ms sleep, retry failures individually)
- Color-error fix: `patch_name()` helper in `apply_plan` retries a rename with `color: {}` if Gmail rejects with 400 (invalid color palette)

**Files changed:** `app.py`, `templates/labels.html`

---

### 29. Fix — AI Hallucinations (chunked calls) + Re-run Button (May 29 2026)

**Problem 1 — 74% hallucination rate:**
Sending all 474 labels to DeepSeek in a single call caused the model to invent label names that don't exist (e.g., suggesting "Google Alerts" when only "Google/Google Alerts" exists). Backend validation dropped these, resulting in 7/9 suggestions discarded. Root cause: 474 names is too many for the model to track reliably in one context window.

**Fix:**
- Split label list into chunks of 80
- Run one DeepSeek call per chunk (~6 calls total for 474 labels), each with `max_tokens: 2000`
- Each call receives: (a) SUBSET of 80 labels to analyze, (b) FULL list of 474 for context (so it can reference any label as a merge target/parent)
- Results from all chunks are combined, then run through the existing validation layer
- 0.5s sleep between chunks to avoid rate limiting
- Chunk failures are caught and logged (other chunks still run)

**Problem 2 — Re-run button closed panel:**
Clicking "AI Reorganize" a second time toggled `aiOpen = false` and closed the panel instead of re-running analysis.

**Fix:**
- `toggleAIPanel()` now checks: if panel already open → call `runAIAnalysis()` directly; if closed → open it and run analysis.

**Files changed:** `app.py`, `templates/labels.html`
**Commit:** `be5bccb`

---

### 30. Fix — Dashboard AI crash "sequence item 0: expected str instance, dict found" (May 29 2026)

**Problem:** Dashboard AI suggestions failing after ~4s with "sequence item 0: expected str instance, dict found". Error originated in `ai_labeler.py:_call_provider()` at `'\n'.join(existing_labels)` — `existing_labels` was receiving label dicts instead of plain name strings. Most likely cause: Celery worker running a previous version of the code that passed full label objects rather than just their names.

**Fix:** Made `_call_provider` defensive — normalizes `existing_labels` before joining: if an item is a dict, extracts `item['name']`; otherwise calls `str(item)`. This handles any shape the argument arrives in.

**Files changed:** `ai_labeler.py`
**Commit:** `f04fd2a`

---

### 31. Feature — Manual Merge UI on /labels page (May 29 2026)

**Request:** User wanted to manually merge two labels (pick which to delete, which to keep), mirroring what the AI merge does but driven by the user.

**Implementation:**
- Added a merge icon button (`bi-diagram-2`) to every label row in the tree, alongside rename/move/delete
- New "Merge label" modal with:
  - Red "source" panel showing the label you clicked (the one that will be deleted)
  - Searchable dropdown (`<input>` + `<select size="6">`) to pick the target label (the one that survives)
  - "Swap source and target" link to reverse the direction without reopening the modal
  - Inline warning that updates as you select: shows the destructive consequence, and blocks merging a label with its own parent/child (same guard as AI)
  - "Queue merge" button (disabled until a valid target is selected)
- On confirm, queues a `{type:'merge'}` op into `pendingManualOps` with the same shape as AI merge ops (`sourceNames`, `sourceIds`, `targetName`, `targetId`)
- Tree chip for pending merge shows "⇢ merge into '<target>'" in red (same style as delete chip)
- Apply Changes executes it through the existing `/api/labels/apply_plan` streaming endpoint

**Files changed:** `templates/labels.html`
**Commit:** `755837c`

---

### 32. Fix — Filter update timeout + Apply Changes UX feedback (May 29 2026)

**Problem 1 — Filter update timing out:**
During a merge, `settings.filters.list()` was being called once per source label using the main service (10s timeout). On Railway this timed out, producing `⚠ Could not update filters`. The merge itself succeeded (emails moved, label deleted) but Gmail filters weren't updated.

**Fix:**
- Build a dedicated `filter_svc` with 30s timeout ONCE before the source loop
- Pre-fetch the full filter list once (instead of once per source)
- Reuse the cached list for all sources in the merge — no repeated slow API calls
- `filter_svc = None` guard: if the fetch fails, filter update is skipped gracefully with a warning
- Refactored `generate()` to build the service from `get_creds()` directly (so `creds` is available for the filter service)

**Problem 2 — No "in progress" or "done" feedback on Apply Changes button:**
While a merge runs (e.g. moving 2402 emails), the button went grey and nothing else changed. User couldn't tell if it was working or done.

**Fix:**
- Button shows spinner + "Applying…" while streaming
- On success: flashes green "✓ Done" for 2 seconds, then restores "Apply Changes"
- On error: restores "Apply Changes" immediately

**Files changed:** `app.py`, `templates/labels.html`
**Commit:** `7320876`

---

### 33. Feature — Scan any label as source (May 29 2026)

**Request:** On the main dashboard, after the inbox scan completes, let the user switch to any Gmail label as the scan source and reorganize emails within it — moving them to a different label.

**UX:**
- Inbox scan always runs first on load (unchanged)
- After scan completes, a **"Scanning: Inbox ▾"** pill appears in a bar between the controls and subheader
- Dropdown lists all user labels (sorted); selecting one immediately re-runs the scan against that label
- Hero text updates: "You have X emails in 'LabelName'."
- While scanning, progress bar shows "Scanning 'LabelName' (X%)"
- Skip Inbox / Auto Label checkboxes are hidden when source is a label (inbox-only concept)
- Selecting a new source resets `pendingActions` so stale selections from a previous scan don't carry over

**Move semantics (label source):**
- When source is a label: messages are fetched using `labelIds=[source_label_id]` + `from:{email}` query
- `batchModify` adds the destination label AND removes the source label (`removeLabelIds: [source_label_id]`)
- No Gmail filter is created (filter creation is inbox-specific)
- Apply log shows: `"moved X emails from 'LabelName' to label"`

**Inbox source (unchanged behaviour):**
- Messages fetched with `q=in:inbox from:{email}`
- Skip Inbox / Auto Label checkboxes shown as before
- Gmail filter created if Auto Label is on

**Backend changes:**
- `POST /api/start_scan`: accepts optional `source_label_id` and `source_label_name` in JSON body; passes to Celery task
- `tasks.py run_inbox_scan`: accepts `source_label_id`/`source_label_name` kwargs; uses `labelIds=[source_label_id]` in Phase 1 list; stores source info in progress and results
- `POST /api/apply_actions`: accepts `{actions, source_label_id, source_label_name}` dict body (backwards compatible with plain list); routes label action to inbox or label path based on `source_label_id`

**Files changed:** `app.py`, `tasks.py`, `templates/dashboard.html`
**Commit:** `847b955`

---

### 34. Fix — Rescan source label crash (null progress-wrapper) (May 29 2026)

**Problem:** Selecting a label from the source picker after a scan completed threw a null error on `document.getElementById('scan-progress-wrapper').style.display = ''` because that element was replaced when the scan completion rewrote `hero-status-content`. The error aborted `startScan()` before the fetch fired.

**Fix:** Removed the pre-replacement `.style.display` line — `startScan()` now unconditionally replaces `hero-status-content` innerHTML (which creates the progress elements) before doing anything else.

**Files changed:** `templates/dashboard.html`
**Commit:** `d2762cb`

---

### 35. Fix — Gmail filter creation silently failing (May 29 2026)

**Problem:** After applying a label action with Skip Inbox + Auto Label checked, emails from the same sender kept landing in inbox. The `settings.filters.create()` call was using a 20s-timeout service inside `exec_retry`, timing out silently due to bare `except: pass`.

**Fix:**
- `make_service(timeout=20)` now accepts a timeout parameter
- Filter creation uses `make_service(timeout=30)` — dedicated longer-timeout service
- Removed `exec_retry` wrapper for filter (it doesn't retry on timeout anyway)
- Filter result logged back into the SSE stream per row: `+ filter created (skip inbox)` or `⚠ filter failed: <reason>`
- `filter_note` always defined (covers auto_label=False case too)

**Files changed:** `app.py`
**Commit:** `52b60ea`

---

### 36. Feature — Bulk CSV reorganize on /labels page (May 29 2026)

**What it does:**
- **Download template**: "Bulk CSV" button downloads a CSV pre-filled with all labels and message counts. Columns 3–6 are empty for the user to fill in.
- **Upload & process**: Upload icon button triggers a file picker. Parsed entirely in JS — no backend route needed. Each row with any action column filled gets queued into `pendingManualOps`. Blank rows and rows with all-empty action columns are skipped.
- **Apply Changes**: executes through the existing `/api/labels/apply_plan` streaming endpoint.
- **Guide modal**: ⓘ info icon opens a modal explaining all 6 columns with examples and priority order.
- **System log**: every queued operation and every skip/error is logged to the console window.

**CSV columns:**
1. `label` — full name including parent path (read-only)
2. `messages` — email count (read-only)
3. `move_to_parent` — exact name of existing parent to move under
4. `rename` — new short name (last segment only); can combine with move_to_parent
5. `merge_into` — full name of target label; source is deleted, emails moved (same as UI merge)
6. `delete` — type "delete" to queue deletion

**Priority order:** delete > merge_into > move_to_parent/rename

**Safeguards:**
- Merge blocked if source/target are parent-child (same guard as UI and backend)
- Unknown label names logged as warnings and skipped
- Same name after move/rename logged as warning and skipped

**Files changed:** `templates/labels.html`
**Commit:** `7ab827c`

---

### 37. Fix — Filter creation scope check + warning visibility (June 17 2026)

**Problem:** After applying a label action with Auto Label checked, Gmail filters were silently not being created. Two bugs compounded:

1. **Silent failure in frontend:** `logToScanDebugger(jsonLog.msg, 'success')` always logged messages green — even `⚠ filter failed: ...` errors appeared as green successes, hiding the problem from the user.
2. **Missing scope in session token:** Users who authenticated before `gmail.settings.basic` was added to `SCOPES` had session tokens without the filter permission. The `settings.filters.create()` call returned 403, which was caught and logged — but invisibly (bug 1). No guidance was shown to re-authenticate.

**Fixes:**

**`templates/dashboard.html`** — `logToScanDebugger` call for `row_complete` messages now uses `'warn'` level (yellow) when the message contains `⚠`, `'success'` (green) otherwise:
```javascript
// Before:
logToScanDebugger(jsonLog.msg, 'success');
// After:
logToScanDebugger(jsonLog.msg, jsonLog.msg.includes('⚠') ? 'warn' : 'success');
```

**`app.py`** — before attempting filter creation, checks if the stored session token includes `gmail.settings.basic`. If the scope is absent, emits a clear re-login warning instead of making a doomed API call:
```python
stored_scopes = set(creds_data.get('scopes') or [])
settings_scope = 'https://www.googleapis.com/auth/gmail.settings.basic'
if stored_scopes and settings_scope not in stored_scopes:
    filter_note = ' ⚠ filter skipped — log out and back in to grant Gmail filter permission'
else:
    # ... existing try/except filter creation block
```

**User action required:** If the warning appears, the user must log out of the app and log back in to issue a new OAuth token that includes the filter scope.

**Files changed:** `app.py`, `templates/dashboard.html`
**Commit:** `312b840` — deployed ✓

---

### 38. Fix — Filter creation timeouts + "already exists" error (June 17 2026)

**Problems observed in production logs:**
1. 4 out of 5 parallel filter creations timed out: `⚠ filter failed: The read operation timed out.` — Gmail's filter API is slow and can't handle 5 concurrent calls.
2. One filter returned `HttpError 400 "Filter already exists"` — treated as an error when it's actually fine (the filter is already doing its job).

**Fixes in `app.py`:**
- Added `import threading` and `_filter_lock = threading.Semaphore(1)` next to `PARALLEL_WORKERS` — a module-level lock that serializes filter creation across threads.
- Wrapped the `settings.filters.create()` call in `with _filter_lock:` — email labeling still runs in parallel, only filter creation is serialized.
- Increased per-call timeout from 30s → 60s for the filter service.
- Added specific handling for `'Filter already exists'` in the exception: logs as `+ filter already exists` (green success) instead of `⚠ filter failed`.

**Files changed:** `app.py`
**Commit:** `1bdc108` — deployed ✓

---

### 39. Security hardening (October 5 2026)

**Audit findings (Railway + repo):**
1. GitHub personal access token was embedded in the git remote URL (`.git/config`). Not in any tracked file or git history.
2. `web` service on Railway had no `FLASK_SECRET_KEY` and no `ENVIRONMENT` variable, so production fell back to `'dev_key_for_testing_only'` and set `OAUTHLIB_INSECURE_TRANSPORT=1`.
3. Stored XSS: when a `From:` header had no `<...>`, the raw header became the "email" and was injected unescaped into `data-email="..."` in the dashboard table. Any sender could craft it.
4. Label names (including AI-created ones) were rendered unescaped in dashboard dropdowns, and passed into inline `onclick='...'` handlers in both pages. `esc()` alone is not safe there because the browser decodes `&#39;` back to `'` before running the JS.
5. No cookie hardening (Secure/SameSite) and no security headers. CSV export allowed spreadsheet formula injection.

**Fixes:**
- `.git/config`: remote set to `https://github.com/alexgorna/gmail-cleaner.git` (token removed). Token must still be revoked on GitHub.
- `app.py`: `IS_PRODUCTION` (true when `ENVIRONMENT=production` or Railway's `RAILWAY_ENVIRONMENT_NAME=production`). App refuses to start in production without `FLASK_SECRET_KEY`. `OAUTHLIB_INSECURE_TRANSPORT` only outside production. Session cookie `Secure` (prod), `HttpOnly`, `SameSite=Lax`. `after_request` adds `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, HSTS (prod).
- `tasks.py`: sender parsed with `email.utils.parseaddr` and validated against a safe address regex; anything else becomes `invalid-sender@unknown`.
- `templates/dashboard.html`: `escapeHtml` now also escapes `'`; new `jsArg()` helper (HTML-escaped JSON string) for inline handlers; escaped emails, label names/ids, source label name; `CSS.escape` in the `data-email` selector; CSV export quotes cells and neutralizes `= + - @` prefixes.
- `templates/labels.html`: new `jsArg()`; all inline handlers in the tree (`startRename`, `showMoveModal`, `showMergeModal`, `showDeleteModal`, `handleRenameKey`, `toggleExpand`, `cancelManualOp`) use it.

**Verified:** `py_compile` OK, inline JS passes `node --check`, Flask smoke test (prod without secret fails fast; headers + `Secure; HttpOnly; SameSite=Lax` cookie present; dev still works), `jsArg` round-trip with a quote/script payload, sender parser rejects HTML payloads.

**Deploy order (requires approval):** 1) set `FLASK_SECRET_KEY` + `ENVIRONMENT=production` on `web`, 2) push. Pushing first would crash `web` (fail-closed).
**Commit:** `68decce` (pushed via GitHub Desktop), deployed ✓ Oct 5 2026. Railway vars set on `web`: `FLASK_SECRET_KEY` (new random), `ENVIRONMENT=production`. Old GitHub tokens were already expired and have been deleted. Redis confirmed on private network (`redis.railway.internal`).

---

### 40. Jev hybrid labeler (October 5 2026)

**Backup first:** annotated tag `pre-jev-2026-10-05` on `68decce` (last DeepSeek-only version, deployed and working) plus a zip snapshot at `_backups/pre-jev-2026-10-05_68decce.zip`. `.gitignore` now excludes `_backups/` and the old `backup_*` folders. Rollback options: Railway "Redeploy" on the Oct 5 04:17 deployment, or set `AI_PROVIDER=deepseek` (instant, no code change).

**What changed:**
- New `jev_labeler.py`. For each sender (email + up to 3 subjects), one Jev System One call asks two questions at once: `personal` (Noul: is this a real person?) and `label` (Choice over the user's existing labels plus `__none__`). Routing: personal ≥ 0.80 → `no_label`; label ≠ none with confidence ≥ 0.70 → `use_existing`; everything else goes to DeepSeek, which still names new labels.
- Fallbacks: no `TYPESAFE_API_KEY`, client error, or every Jev call failing → the whole job runs on DeepSeek exactly as before. If DeepSeek fails on the leftover senders, Jev's answers are still returned. Senders Jev hasn't answered within `JEV_PHASE_TIMEOUT` (45 s) go to DeepSeek.
- `ai_labeler.py`: new `AI_PROVIDER=hybrid` mode; the old body moved to `_suggest_with_llm(senders, labels, provider)`. Default is still `deepseek`, so deploying this code changes nothing until the variable is flipped.
- Results carry `meta` (jev_resolved, llm_resolved, errors, input tokens, seconds, model) and each group has `source: jev|llm`. The frontend ignores both for now.
- `requirements.txt`: `typesafe-sdk==0.7.2` (real SDK: `client.system_one(state=..., questions=...)`, answers in `response.nouls[...]` / `response.choices[...]` with `.confidence`). Model pinned to `jev-1.13.0` via `JEV_MODEL`.
- Tunables (env): `JEV_MIN_CONFIDENCE`, `JEV_PERSONAL_THRESHOLD`, `JEV_CONCURRENCY` (8), `JEV_PHASE_TIMEOUT`, `HYBRID_LLM_PROVIDER` (deepseek).
- Security: email subjects are untrusted, but Jev can only return one of the options we give it, so prompt injection can at worst cause a wrong valid pick.

**Verified (container, real SDK with a mocked HTTP transport):** happy path (3 of 4 senders by Jev, 1 to DeepSeek, every sender covered once), no-key fallback, bad-key fallback over the network, phase-timeout fallback, `AI_PROVIDER` routing, group-name extraction (`mail.ibm.com` → Ibm, `bbc.co.uk` → Bbc).

**To turn on:** set `AI_PROVIDER=hybrid` on the `gmail-cleaner` worker in Railway. `TYPESAFE_API_KEY` is already set there.
**Commit:** `d4a60a3`, deployed ✓ (default still DeepSeek). First prod run after deploy: 50 senders, 490 labels, DeepSeek 10 s, 5.3k in / 2.3k out tokens.

---

### 41. Jev: support more than 255 labels (October 5 2026)

**Problem:** production logs showed the account has 490 labels. Jev's Choice accepts at most 255 options, so the first version skipped label matching entirely above that.

**Fix in `jev_labeler.py`:** labels are split into chunks of 254 (+ `__none__`), all asked in the same request as `label_0`, `label_1`, ... next to `personal`. With one chunk, behavior is unchanged. With several, each chunk's pick with confidence ≥ `JEV_CANDIDATE_MIN` (0.35) becomes a finalist and a second request chooses among the finalists + `__none__`, so the final confidence is comparable. Worst case 2 Jev calls per sender. Stats now include `label_chunks` and `finalist_rounds`.

**Verified:** mocked 490-label run through the real SDK (2 chunks, every request ≤ 255 options, right labels picked, unknown sender sent to DeepSeek); small label sets still use one round.
**Commit:** `13725b2`, pushed together with #42.

---

### 42. Jev on page load + "Ask AI" per row (October 5 2026)

**Alex's requested UX:** Jev runs automatically after the scan; rows Jev knows show **Apply recommendation**. Rows Jev doesn't know show an **Ask AI** button (DeepSeek for that one sender). The top **AI** button asks DeepSeek about every sender Jev did not recognize.

**Backend:**
- `tasks.py`: new Celery task `run_jev_classify(job_id, senders, label_names)`. Writes each decision to Redis hash `jev:{id}:decisions` as it arrives, status in `jev:{id}:status` (running/complete/failed/off, done/total, decided/unknown, seconds, model). Limits: `JEV_MAX_SENDERS` (2000), `JEV_ONLOAD_TIMEOUT` (600 s). TTL 1 h.
- `tasks.py`: `run_ai_suggestions` now splits big requests into batches of `AI_BATCH_SIZE` (50) so DeepSeek's answer is never truncated; status shows "Batch n/m". One failed batch no longer fails the whole job.
- `app.py`: `POST /api/jev_classify` (uses the current scan + user labels; returns `{enabled:false}` when Jev is off) and `GET /api/jev_results/<id>` (status + all decisions so far).
- `app.py`: AI job ownership now tracks a list per session (`ai_job_ids`, last 25; `jev_job_ids`, last 5) so several per-row "Ask AI" clicks can run at once. Previously only the last job id was allowed.
- `jev_labeler.py`: `jev_available()` (key present and `JEV_ENABLED` != false); `classify_with_jev(..., on_result=, phase_timeout=)` streams results.
- `AI_PROVIDER` stays `deepseek`. The `hybrid` mode from #40 still exists but is not used by the page.

**Frontend (`dashboard.html`):**
- After a scan completes, `startJevRecommendations()` starts the Jev job and polls every 1.5 s, merging new decisions into `aiSuggestions` (with `source: 'jev'`) and re-rendering. The AI button shows progress (`12/150`) and is disabled while Jev runs.
- Jev suggestions say **Apply recommendation**; DeepSeek ones say **Apply AI**. Bulk buttons renamed **Apply all** / **Dismiss all**.
- Rows with no suggestion (after Jev finishes, not processed, no manual action) show **No recommendation. Ask AI**, which calls `requestAISuggestions([email])`. While waiting the button shows "Asking AI…".
- `requestAISuggestions()` without arguments now sends every row needing AI (all pages, not just the visible page). `processAISuggestions` merges instead of replacing. Dismissing a suggestion re-renders so the row offers Ask AI.
- A rescan resets Jev state and suggestions.

**Off switch:** set `JEV_ENABLED=false` on the `gmail-cleaner` and `web` services; the page then shows Ask AI on every row (old behavior with per-row control).

**Verified:** server flow with fakeredis + simulated Gmail + Jev through the real SDK (302 labels → 2 chunks; 3 decided, 117 unknown; two concurrent row asks both allowed; 117 senders → batches 50/50/17; foreign job ids 403; no key → disabled). Headless Chromium on the rendered template with mocked APIs: Jev rows show Apply recommendation / not-recommended warning, unknown rows show Ask AI, per-row Ask AI sends only that sender, top AI sends only the remaining unknown sender, Apply recommendation selects the label, dismiss brings back Ask AI, no page errors.
**Commit:** `3b0dbfb`, deployed ✓.
**Post-deploy fix (Railway only):** the first live scan showed "No recommendation" on every row because `/api/jev_classify` runs on `web`, and `jev_available()` checks `TYPESAFE_API_KEY`, which only existed on the worker. Added `TYPESAFE_API_KEY=${{gmail-cleaner.TYPESAFE_API_KEY}}` (Railway reference, value never copied) on `web`; redeployed OK.

---

### 43. Fix — Jev stuck on "Recommending…" (October 5 2026)

**Problem (worker log):** `run_jev_classify` raised `ModuleNotFoundError: No module named 'jev_labeler'`. `celery -A tasks` puts the app folder on `sys.path` only while loading `tasks.py` and removes it afterwards, so a module imported lazily inside a task can't be found (gunicorn on `web` was fine). The import ran before the task's `try`, so the status stayed `running` and the page polled forever.

**Fixes:**
- `tasks.py` and `ai_labeler.py`: `import jev_labeler` moved to module top level. **Rule for this repo: never import project modules inside Celery task functions.**
- `dashboard.html`: stall guard. If Jev reports no progress for 90 s, the page stops waiting, logs a message and shows Ask AI on the remaining rows.

**Commit:** `f78767c`, deployed ✓. First real Jev run: 195 senders, 490 labels → 86 decided (44%), 109 unknown, 0 errors, 10.1 s, ~1.09M input tokens (≈ $0.05). Good picks seen (Kohl's → Promos, Southwest → Travels/Southwest) but misses on obvious cases (vgornatti@gmail.com not flagged personal; Atlassian, estatesales, elevault unknown).

---

### 44. Jev diagnostics for threshold tuning (October 5 2026)

Alex chose "measure, then tune" over guessing new thresholds.
- `jev_labeler.py`: each sender logs one line `[jev-diag] email | personal=… | picks=[(label, conf) per chunk] | final=(label, conf) | -> action`. Controlled by `JEV_DIAG_LOG` (default true; set `false` once tuning is done, since it writes sender addresses to the Railway logs).
- `dashboard.html`: the info tooltip on a Jev recommendation shows "Recommendation confidence: NN%".
- Next: read the diag lines from one real scan, pick `JEV_PERSONAL_THRESHOLD` / `JEV_MIN_CONFIDENCE` / `JEV_CANDIDATE_MIN` from the actual score distribution (these are env vars, so tuning needs no code push).
**Commit:** `f11a5d2`, deployed ✓.

**Findings from the diag log (195 senders, Oct 5 04:56):** 93 decided, 102 unknown.
- Kohl's → "Promos." at 97% was wrong for Alex's system (one sub-label per brand). Two causes: Jev saw a flat list of names with no structure, and the finalist round rubber-stamped a single candidate against `__none__` (42% → 97%). 8 recommendations were inflated this way; Dunkin' (99% in its chunk) and Domino's (98%) were real two-way finals and correct.
- Most "misses" had no existing label at all (Atlassian, Elevault, EstateSales): correct to skip, they need a new label.
- Personal question is ambiguous for this user: vgornatti@gmail.com 0.73, recruiters 0.60–0.77 (filed under Emprego/Job Opp, which Jev picked correctly 13 times).

---

### 45. Folder-aware Jev (October 5 2026)

Alex approved the redesign.
- `jev_labeler.py` rewritten around the label tree (`build_label_tree`): call 1 asks `personal` + `folder` (Choice over top-level labels; each folder described as "Folder with N sub-labels, for example: …"). If the pick is a folder (confidence ≥ `JEV_FOLDER_MIN` 0.60), call 2 chooses among its sub-labels + `__new__` (chunked if > 254; a final round only when ≥ 2 real chunk winners; a single winner keeps its own score).
- Decision order: existing label ≥ 0.70 → `use_existing`; else personal ≥ `JEV_PERSONAL_THRESHOLD` (now **0.70**) → `no_label`; else folder known but no sub-label → **`new_in_folder`** (parent); else unknown. Parent folders are never recommended as a destination.
- Page: `new_in_folder` rows say "Belongs under **Promos.**, no label for it yet." with **Ask AI for a name**. The top AI button includes these rows. Requests send `hints: {email: folder}`; `app.py` passes them as `folder_hint`; DeepSeek's prompt gets `| folder: "Promos."` and a rule to create "Promos./<Brand>" or reuse an existing sub-label, never a bare folder.
- `applyAISuggestion` now ignores `no_label` and `new_in_folder` (previously "Apply all" would hit `suggestion.label` undefined on a no_label row).
- Thread-safe stats; worker log line now counts existing / person / new-in-folder / unknown and total calls.
- Cost: options per request drop from 490 to (top-level count) + (one folder's sub-labels).

**Verified:** mocked label tree shaped like Alex's (Promos. with 300 sub-labels, Travels, Emprego, Health, plain Amazon/Netflix): Dunkin' found in the second Promos. chunk at its own 97% (no final round), Kohl's → new_in_folder Promos., recruiter → Emprego/Job Opp even with personal 0.61, vgornatti → no_label (0.73), Amazon (plain label) → use_existing, Amazon Health → new_in_folder Health, every request ≤ 255 options. Headless page test: new_in_folder row text/button, top AI sends hint `{promo@shop.com: "Promos."}`, no page errors. DeepSeek prompt line contains `folder: "Promos."`.
**Commit:** `597fa96`, deployed ✓. Live run (Oct 5 05:07, 195 senders, 490 labels → 86 top-level, 25 folders): 60 existing label, 7 person, 42 new-in-folder, 86 unknown, 0 errors, 282 calls, 420k input tokens (was 1.09M), 8.6 s.

---

### 46. Jev: decide by why the sender writes, not by names mentioned (October 5 2026)

**Problem Alex spotted:** `adobe@myworkday.com` (job application at Adobe via Workday) and `e.ogull@tenthrevolution.com` (recruiter pitching Adobe roles) were recommended the plain label **Adobe** (folder confidence 0.76 / 0.90). Jev matched on the company name mentioned instead of the purpose; the label "Adobe" is for Alex's own dealings with Adobe, and recruiting belongs under Emprego.

**Fix (`jev_labeler.py`):** shared `_SENDER_RULES` text added to both the folder and the sub-label instructions: decide by why the sender writes; a company-named label is for the user's own dealings with that company; recruiters, staffing agencies, job offers and applications go to job/career labels even when they mention a company with its own label.

**Not yet verified against live Jev** (instructions-only change; check the `[jev-diag]` lines for these two senders after the next scan).

**Backlog (bigger fix):** let Jev learn what each label means from emails Alex already filed there (a few sender examples per label, cached per user), instead of guessing from label names. Would also make Portuguese folder names like "Emprego" unambiguous.
**Commit:** `872d7c0`, deployed ✓. Live run (Oct 5 05:20): `adobe@myworkday.com` → folder Emprego 0.98 (new_in_folder), `e.ogull@tenthrevolution.com` → Emprego 0.96 (Job Opp only 0.46, so it fell to person 0.77). Totals: 51 existing, 7 person, 55 new-in-folder, 70 unknown (was 86), 422k tokens, 8.7 s. Alex: "recommendations were better this last time."

**Known gap, left as is by Alex's choice:** inside Emprego, recruiters score Job Opp at 0.46–0.67 and get "new label" instead, because the instructions say folders hold one sub-label per company. Possible fix (backlog `jev-10`): mention catch-all sub-labels and prefer them.

---

### 47. Jev: brand name match offers hidden sub-labels (October 5 2026)

**Problem Alex spotted:** `adi@agentmail.to` got "Belongs under Newsletters" although **Services/AgentMail** exists. The folder step describes each folder with only 6 example sub-labels, so Jev never saw AgentMail under Services (log: folder Newsletters 0.85, sub `__new__` 0.96). `singh.adi@withagentmail.com` got no folder at all.

**Fix (`jev_labeler.py`):**
- `build_name_index()`: key = leaf sub-label name normalized to `[a-z0-9]` (e.g. `agentmail`, `dunkin`, `dominos`), skipping folders, top-level labels (already offered), keys under 3 chars and generic words (`_GENERIC_KEYS`: support, promos, travel, gmail, amazon…).
- `name_matches(email)`: a key matches if it equals a token of the address (split on `@ . - _ +`) or, for keys of 6+ chars, appears anywhere in the address (`withagentmail.com` → AgentMail). Up to 5, longest first.
- Matches are added as extra options in Jev's first (folder) question, described as "existing sub-label whose name matches this sender". If Jev picks one with confidence ≥ 0.70 → `use_existing` directly. Jev still decides, so a false match (e.g. `targetedmarketing.com` → Promos./Target) is only an option, not a recommendation.
- Diag log shows `names=[...]`.

**Verified:** name matching on real senders (AgentMail ×2, Dunkin' via `dunkinextras@`, Domino's, Southwest, Whatnot, Substack, Synchrony, UDX exact token; EA and generic words not matched). SDK mock: AgentMail offered in the first question and recommended directly; folder tree tests from #45 still pass.
**Commit:** `e851167`, deployed ✓. Live run (Oct 5 05:32): 73 existing (was 51), 8 person, 46 new-in-folder, 56 unknown (was 70), 237 calls, 395k tokens, 7.2 s. `singh.adi@withagentmail.com` → Services/AgentMail 0.86 ✓; `adi@agentmail.to` offered AgentMail but Jev chose Newsletters 0.43. Near misses with the right name-matched label under 0.70: Parent Square ×3 (0.47–0.54), Coursera ×2 (0.60/0.68), TelyRx 0.68. Duplicate labels noticed: Emprego/UDX and Jobs/UDX.

---

### 48. Jev: two-way name match, lower bar when name and Jev agree (October 5 2026)

Issues Alex spotted: `noreply@mktg.universalorlando.com` should match **Promos./Universal Orlando Resort** (log: `names=None`, the label name is longer than the address part); `nespresso@mail-de.nespresso.com` (German emails) went to E-Commerce/Nespresso but belongs in the **Germany** folder.

**Fixes (`jev_labeler.py`):**
- `name_matches()` also matches in reverse: brand-looking domain parts (6+ chars, not in `_GENERIC_DOMAIN_PARTS` like mktg/mail/notifications, not generic words) found inside a longer label name. `universalorlando` → Promos./Universal Orlando Resort; `orlandomagic.com` does not hit Orlando Health.
- `JEV_NAME_MATCH_MIN` (default **0.50**): when Jev's top pick IS a name-matched label, 0.50 is enough (two independent signals agree). Other picks still need 0.70. Would have caught Parent Square, Coursera, TelyRx.
- A country-folder rule (for the Nespresso case) was written and then **removed before push**: Alex's direction is that this is a product launching to many users, so no fixes for his specific cases.

**Verified:** matcher on 15 real senders; SDK mocks (#45 tree, #47 names, new lower-bar test: name-matched 0.55 accepted, unmatched 0.55 rejected).
**Commit:** `6f9455b`, deployed ✓. Live run (Oct 5 05:41): 77 existing (was 73), 7 person, 44 new-in-folder, 55 unknown, 234 calls, 393k tokens, 7.6 s. Universal Orlando ×2 → Promos./Universal Orlando Resort (0.97/0.96), Coursera ×2 (0.55/0.68), TelyRx (0.68), Parent Square 1 of 3 (others 0.48, and folder-only 0.50). Still missed: adi@agentmail.to (Jev prefers Newsletters 0.46). These are the cases the history/filters step should cover.

**Product direction (Alex, Oct 5):** stop tuning to Alex's inbox; make it work for most users. Plan agreed in principle:
1. Use each user's own Gmail filters and past labeled emails first (no AI when a match exists).
2. Describe labels to Jev from real filed emails (sample senders/subjects per label), not from hand-written rules.
3. Measure accuracy per account automatically: hide labels on already-labeled emails and check Jev's predictions.
4. Then remove user-specific instructions (recruiting rule, "one sub-label per company", never-pick-parent-folder).
Score log stays on while tuning (Alex). Launch checks: turn the log off before other users; Google verification / security assessment for the gmail.modify scope.

---

### 49. Recommend from the user's own Gmail filters and history first (October 5 2026)

Product step 1 from #48 (works for any user, any language or folder style; no AI).

**New `history_labeler.py`** (imported at top of `tasks.py` and `app.py`):
- **Filters:** `settings.filters.list`; keeps filters whose only criterion is `from` and that add exactly one user label. Parses `a@x.com OR b@y.com`, `(x.com | y.com)`, `{a b}`. Match: exact address, domain or sub-domain, or a bare word (4+ chars) inside the address. Result `source: 'filter'`, confidence 1.0. (Filters created by our own Apply Actions count too, so a sender handled once is recognized next time.)
- **History:** per sender `messages.list(q='from:(<address>) has:userlabels', maxResults=HISTORY_SAMPLE=5)`, then `messages.get(format='minimal')` for the label ids, all through Gmail batch HTTP (`HISTORY_BATCH=40` per request). The most common user label wins if it covers ≥ `HISTORY_MIN_SHARE` (0.6) of the sample. Result `source: 'history'`, `evidence: 'N of M'`. Ties/mixed history are left for Jev.
- Diag lines `[history-diag]` (same `JEV_DIAG_LOG` switch). Off switch: `HISTORY_ENABLED=false`.

**Wiring:**
- `tasks.run_jev_classify(job_id, senders, labels, credentials_dict=None)`: builds a Gmail client from the user's credentials, runs history first (streaming decisions to Redis), then Jev only on the senders left. Works even when Jev is off. Status includes `from_history`. Log line `[history] N by filter, N by history, N left for Jev, …`.
- `app.py /api/jev_classify`: passes `session['credentials']` to the task (same pattern as the scan; see backlog sec-08 about tokens in task args). Enabled when Jev or history is enabled.
- `dashboard.html`: recommendations keep `basis` (`filter` / `history` / `jev`) and `evidence`; the ⓘ tooltip says "Based on your existing Gmail filter for this sender." or "You filed 3 of 3 recent emails from this sender here."

**Verified (simulated Gmail):** filter with OR list and domain filter matched; filter with a subject criterion ignored; history 3/3 → Services/AgentMail, 1/1 → Parent Square; 2/2 split → left for Jev; end to end through the Celery task with fakeredis: 4 decided from history/filters, Jev only received the 3 remaining senders.
**Commit:** `2629133`, deployed ✓. First live run (Oct 6 02:53, 150 senders, 709 sender filters): 7 by filter, 16 by history, 127 left for Jev; Jev 5.2 s. **But** the history step took 25.2 s with no visible progress (Alex: "it is stuck"), and Gmail rejected 51 list + 10 get calls inside the batches (too many concurrent requests), so those senders were never checked. Good history hits: adobe@myworkday.com → Jobs (4/4), Universal → Promos./Universal Orlando Resort (5/5), ClassLink → Parent Portal (5/5), Namecheap 3/3, Starfish 5/5. Observed: utility labels like `.Archive` / `.Sanitize` show up in history votes (e.g. vgornatti@gmail.com → .Archive 5/5).

---

### 50. History step: parallel connections, retries, visible progress (October 6 2026)

- `history_labeler.py`: Gmail batch HTTP replaced by `HISTORY_WORKERS` (5) threads, each with its own Gmail client (`service_factory`; the Google client isn't thread-safe). Every call goes through `_execute()` with backoff on 429 / 403 rateLimitExceeded / 5xx (`HISTORY_RETRIES` 4: 0.5, 1, 2 s). A sender whose lookup still fails just goes on to Jev.
- `classify_from_history(service_factory, senders, on_result, on_progress)`; progress every 5 senders.
- `tasks.py`: status during history = `{phase: 'history', checked, history_total}`.
- `dashboard.html`: AI button shows **History 40/150** during that phase; the 90 s stall guard counts `checked` as progress.

**Verified (simulated Gmail):** a sender whose first `messages.list` returns 429 is retried and still resolved from history (AgentMail 3/3); filters, mixed history and the end-to-end Celery task test from #49 still pass.

**Decision (Alex):** keep following each user's history as is, including utility labels like `.Sanitize` (his own "deal with later" label); don't special-case naming patterns that other users won't share. Possible generic feature later: let each user exclude labels from recommendations.
**Commit:** `763cde6`, deployed ✓. Live run (Oct 6 02:59, 150 senders): no Gmail errors, 7 by filter + 28 by history (was 23), but history took **28.0 s** (Jev 4.6 s, task 32.7 s). Alex: "That history thing takes too long, I am not liking it." Also decided: keep following history as is, including utility labels like `.Sanitize` (no name-based special cases); generic idea logged as backlog gen-04 (let users exclude labels).

---

### 51. History in parallel with Jev, cached per user, 3-email sample (October 6 2026)

- **`tasks.run_jev_classify(..., credentials_dict, user_key)`** now runs history in a background thread **while Jev classifies every sender**. Jev answers land in ~5 s; status gets `jev_done: true`. History decisions overwrite Jev's in the Redis hash; Jev never overwrites history (`hist_owned` set under a lock). Final log line: `existing label (N filter, N history) … Jev Xs, history Ys`.
- **Cache:** `_HistoryCache` stores each sender's history votes in Redis `hist:<user_key>:<sender>` for `HISTORY_CACHE_TTL` (7 days). `user_key` = first 16 hex of sha256(user email) from `session['user_info']`, computed in `app.py`. Only lookups that succeeded are cached. Filters are still read fresh each time (1 call).
- **`HISTORY_SAMPLE` 5 → 3** (2 of 3 must agree): about 40% fewer Gmail calls.
- **Page:** when `jev_done` arrives, the page unlocks (AI button normal, Ask AI buttons shown, log "Recommendations ready. Checking your past emails to improve them…") and keeps polling. A later history/filter answer replaces a Jev answer only if that row still shows Jev's untouched suggestion (not applied, dismissed, or manually set). `topAIBusy` keeps the end of history from resetting the AI button during a top-AI request. Final message: "Recommendations ready for N senders (M from your own filters and history)".

**Verified:** fake Gmail with 0.4 s per list / 0.2 s per get: Jev answers present at 0.05 s, history finished at 1.07 s and upgraded AgentMail and Parent Square, unknown sender kept Jev's answer; second scan with the same user key made **0** Gmail list calls. Headless page: page unlocked with Ask AI during history, then rows upgraded (new_in_folder → history label; Ask AI → filter label), tooltip "You filed 3 of 3 recent emails from this sender here", no page errors.
**Commit:** `d92199d`, deployed ✓ (then rolled back, see #52).

---

### 52. Rollback: history step removed (October 6 2026)

**Alex: "I don't like that history thing, roll back."** Code restored to `6f9455b` (Jev folder-aware matching, two-way name match, 0.50 bar for name-matched picks, Ask AI per row):
- `app.py`, `tasks.py`, `templates/dashboard.html` checked out from `6f9455b`; `history_labeler.py` deleted.
- Removed with it: filters/history lookups, parallel Gmail lookups and retries, the per-user history cache, the "History n/N" progress and the jev_done page unlock.
- Leftover Redis keys `hist:<user>:<sender>` expire on their own within 7 days; nothing reads them.
- Lessons kept for later: on the real account history took 25–28 s for 150 senders and Gmail batch HTTP hit "too many concurrent requests"; the parallel + cache design (#51) is in git history (`d92199d`) if this idea comes back.
**Commit:** pending push
