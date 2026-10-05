"""
Jev labeler: Jev (TypeSafe System One) makes fast, cheap decisions about which EXISTING label fits a sender.

Folder-aware, two steps per sender (email + up to 3 recent subjects):
  1. One call: "personal" (Noul: is this a real person?) + "folder" (Choice over TOP-LEVEL labels; folders are
     described with a few of their sub-labels so Jev understands the structure).
  2. If the chosen top-level label is a folder: one call choosing among its sub-labels, plus "__new__"
     (no sub-label fits; a new one is needed in this folder). Folders bigger than 254 sub-labels are split into
     chunks in the same request; a final round runs only when two or more chunk winners are real candidates
     (a single candidate keeps its own score: no rubber-stamp final against "none").

Decision order:
  existing label with confidence >= JEV_MIN_CONFIDENCE        -> use_existing
  personal >= JEV_PERSONAL_THRESHOLD                           -> no_label
  folder confidence >= JEV_FOLDER_MIN and no sub-label fits   -> new_in_folder (the LLM names it later)
  otherwise                                                    -> unknown (the page offers "Ask AI")

A parent folder is never recommended as a destination by itself (the user's convention is one sub-label per
brand, e.g. Promos./Costco).

Env vars: TYPESAFE_API_KEY, JEV_ENABLED, JEV_MODEL (jev-1.13.0), JEV_MIN_CONFIDENCE (0.70),
JEV_PERSONAL_THRESHOLD (0.70), JEV_FOLDER_MIN (0.60), JEV_CANDIDATE_MIN (0.35), JEV_CONCURRENCY (8),
JEV_PHASE_TIMEOUT (45 s), JEV_DIAG_LOG (true).

Email subjects are attacker-controlled text. Jev can only return one of the options we give it,
so a malicious subject can at worst cause a wrong (but valid) pick, never arbitrary output.
"""

import os
import re
import time
import threading
import concurrent.futures

JEV_MODEL              = os.environ.get('JEV_MODEL', 'jev-1.13.0')
JEV_MIN_CONFIDENCE     = float(os.environ.get('JEV_MIN_CONFIDENCE', '0.70'))
JEV_PERSONAL_THRESHOLD = float(os.environ.get('JEV_PERSONAL_THRESHOLD', '0.70'))
JEV_FOLDER_MIN         = float(os.environ.get('JEV_FOLDER_MIN', '0.60'))
JEV_CONCURRENCY        = int(os.environ.get('JEV_CONCURRENCY', '8'))
JEV_PHASE_TIMEOUT      = int(os.environ.get('JEV_PHASE_TIMEOUT', '45'))
JEV_DIAG_LOG           = os.environ.get('JEV_DIAG_LOG', 'true').lower() == 'true'  # per-sender score log for tuning

NONE_OPTION   = '__none__'
NEW_OPTION    = '__new__'
MAX_OPTIONS   = 255          # Jev Choice limit, including the extra option
CHUNK_SIZE    = MAX_OPTIONS - 1
CANDIDATE_MIN = float(os.environ.get('JEV_CANDIDATE_MIN', '0.35'))  # chunk winner must reach this to enter a final
MAX_SUBJECTS  = 3
MAX_SUBJ_LEN  = 200
EXAMPLES_PER_FOLDER = 6

_PERSONAL_Q = {
    'type': 'noul',
    'instructions': (
        'Is this sender a real individual person writing personal, ad-hoc or conversational email, '
        'rather than an automated, marketing, newsletter, notification, receipt or company system sender?'
    ),
}

_SENDER_RULES = (
    "Decide by WHY this sender writes to the user, not by which company names appear in the email. "
    "A label named after a company is for the user's own dealings with that company (its products, account, "
    "billing, newsletters). Job offers, recruiters, staffing agencies and job applications belong with the "
    "user's job or career labels even when they mention a company that has its own label. "
)

_FOLDER_INSTRUCTIONS = (
    "The user organizes Gmail with labels. These are the user's top-level labels; folders hold one sub-label "
    "per company or topic. " + _SENDER_RULES +
    "Which top-level label does email from this sender belong under? "
    f'Pick "{NONE_OPTION}" if none of them is a good fit.'
)


def _sub_instructions(folder):
    return (
        f'Email from this sender belongs in the "{folder}" folder, which holds one sub-label per company or topic. '
        + _SENDER_RULES +
        'Which existing sub-label is the right place for all email from this sender? '
        f'Pick "{NEW_OPTION}" if none of these sub-labels is specifically about this sender\'s company or topic.'
    )


def jev_available():
    return bool(os.environ.get('TYPESAFE_API_KEY', '').strip()) and os.environ.get('JEV_ENABLED', 'true').lower() == 'true'


def _make_client():
    """Build a TypeSafe client, or return None when Jev is not configured."""
    if not os.environ.get('TYPESAFE_API_KEY', '').strip():
        print('[jev] TYPESAFE_API_KEY not set; using LLM only')
        return None
    from typesafe_sdk import TypeSafeClient
    return TypeSafeClient(model=JEV_MODEL)


def _sender_state(s):
    if isinstance(s, dict):
        subjects = [str(x)[:MAX_SUBJ_LEN] for x in (s.get('subjects') or [])[:MAX_SUBJECTS]]
        return s.get('email', ''), {'sender_email': s.get('email', ''), 'recent_subjects': subjects}
    return str(s), {'sender_email': str(s), 'recent_subjects': []}


def _label_names(existing_labels):
    names = [l['name'] if isinstance(l, dict) else str(l) for l in (existing_labels or [])]
    return [n for n in dict.fromkeys(names) if n and n not in (NONE_OPTION, NEW_OPTION)]


def build_label_tree(labels):
    """
    Returns (top_levels, children):
      top_levels: ordered list of top-level label names (first path segment, existing or implied)
      children:   {top_level: [full names of every label below it]}  (empty list = plain label, not a folder)
    """
    top_levels, children = [], {}
    for name in labels:
        top = name.split('/', 1)[0]
        if top not in children:
            children[top] = []
            top_levels.append(top)
        if name != top:
            children[top].append(name)
    return top_levels, children


def _folder_question(top_levels, children):
    criteria = {}
    for top in top_levels:
        kids = children[top]
        if kids:
            examples = ', '.join(k.split('/', 1)[1] for k in kids[:EXAMPLES_PER_FOLDER])
            criteria[top] = f'Folder with {len(kids)} sub-labels, for example: {examples}'
        else:
            criteria[top] = None
    criteria[NONE_OPTION] = 'None of these top-level labels fits this sender.'
    return {'type': 'choice', 'instructions': _FOLDER_INSTRUCTIONS, 'criteria': criteria}


def _sub_question(folder, names):
    criteria = {n: None for n in names}
    criteria[NEW_OPTION] = f'No existing sub-label fits; this sender needs a new sub-label inside "{folder}".'
    return {'type': 'choice', 'instructions': _sub_instructions(folder), 'criteria': criteria}


def _group_name_from_email(email):
    """'billing@mail.stripe.com' -> 'Stripe'; 'john.doe@gmail.com' -> 'John Doe'."""
    local, _, domain = email.partition('@')
    parts = [p for p in domain.split('.') if p]
    generic = {'gmail', 'yahoo', 'outlook', 'hotmail', 'icloud', 'aol', 'proton', 'protonmail', 'live', 'me'}
    if len(parts) >= 2 and parts[-2] not in generic:
        # Country second-level domains (bbc.co.uk, x.com.br) put the brand one level further left
        sld = {'co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'ne', 'or'}
        root = parts[-3] if len(parts) >= 3 and parts[-2] in sld else parts[-2]
        return root.replace('-', ' ').title()
    return re.sub(r'[._+-]+', ' ', local).strip().title() or email


def _ask_jev(client, state, questions, stats, lock):
    resp = client.system_one(state=state, questions=questions)
    with lock:
        stats['jev_calls'] += 1
        stats['model'] = getattr(resp, 'model', None) or stats['model']
        stats['input_tokens'] += (getattr(getattr(resp, 'usage', None), 'input_tokens', 0) or 0)
    return resp


def _pick_in_folder(client, state, folder, kids, stats, lock, diag):
    """Choose a sub-label of `folder`. Returns (label_or_NEW, confidence)."""
    chunks = [kids[i:i + CHUNK_SIZE] for i in range(0, len(kids), CHUNK_SIZE)]
    qs = {f'sub_{i}': _sub_question(folder, c) for i, c in enumerate(chunks)}
    resp = _ask_jev(client, state, qs, stats, lock)
    picks = [resp.choices.get(f'sub_{i}') for i in range(len(chunks))]
    picks = [p for p in picks if p is not None]
    diag['sub_picks'] = [(p.choice, round(p.confidence, 3)) for p in picks]
    real = [p for p in picks if p.choice != NEW_OPTION and p.confidence >= CANDIDATE_MIN]
    if len(real) >= 2:
        # Several chunk winners: let them compete directly so the scores are comparable
        final = _ask_jev(client, state, {'sub': _sub_question(folder, [p.choice for p in real])}, stats, lock)
        with lock:
            stats['finalist_rounds'] += 1
        p = final.choices.get('sub')
        diag['sub_final'] = (p.choice, round(p.confidence, 3)) if p else None
        return (p.choice, p.confidence) if p else (NEW_OPTION, 0.0)
    if len(real) == 1:
        return real[0].choice, real[0].confidence      # keep its own score: no rubber-stamp final
    best_new = max((p.confidence for p in picks if p.choice == NEW_OPTION), default=0.0)
    return NEW_OPTION, best_new


def _decide_one(client, state, top_levels, children, stats, lock, diag):
    """
    Returns one of:
      ('use_existing', label, conf) | ('no_label', p) | ('new_in_folder', folder, conf) | None
    """
    qs = {'personal': _PERSONAL_Q}
    if top_levels:
        qs['folder'] = _folder_question(top_levels, children)
    resp = _ask_jev(client, state, qs, stats, lock)

    personal = resp.nouls.get('personal')
    p_personal = personal.noul if personal is not None else 0.0
    diag['personal'] = round(p_personal, 3)
    folder_ans = resp.choices.get('folder')
    diag['folder'] = (folder_ans.choice, round(folder_ans.confidence, 3)) if folder_ans else None

    label_choice, folder_for_new = None, None
    if folder_ans and folder_ans.choice != NONE_OPTION:
        folder = folder_ans.choice
        kids = children.get(folder, [])
        if not kids:
            # A plain top-level label (no sub-labels) is a real destination
            if folder_ans.confidence >= JEV_MIN_CONFIDENCE:
                label_choice = (folder, folder_ans.confidence)
        elif folder_ans.confidence >= JEV_FOLDER_MIN:
            sub, conf = _pick_in_folder(client, state, folder, kids, stats, lock, diag)
            # Folder already passed JEV_FOLDER_MIN; the sub-label must pass JEV_MIN_CONFIDENCE on its own
            if sub != NEW_OPTION and conf >= JEV_MIN_CONFIDENCE:
                label_choice = (sub, conf)
            else:
                folder_for_new = (folder, folder_ans.confidence)

    if label_choice:
        return ('use_existing', label_choice[0], label_choice[1])
    if p_personal >= JEV_PERSONAL_THRESHOLD:
        return ('no_label', p_personal)
    if folder_for_new:
        return ('new_in_folder', folder_for_new[0], folder_for_new[1])
    return None


def classify_with_jev(client, senders, existing_labels, on_result=None, phase_timeout=None):
    """
    Returns (decisions, unresolved, stats).
      decisions:  {email: {'action': 'no_label'|'use_existing'|'new_in_folder', 'label'?, 'parent'?, 'confidence'}}
      unresolved: list of the original sender items Jev could not decide
    on_result(email, decision_or_None) is called as each sender finishes (used for live page updates).
    """
    phase_timeout = phase_timeout or JEV_PHASE_TIMEOUT
    labels = _label_names(existing_labels)
    top_levels, children = build_label_tree(labels)
    if len(top_levels) > CHUNK_SIZE:
        print(f'[jev] {len(top_levels)} top-level labels; only the first {CHUNK_SIZE} are offered')
        top_levels = top_levels[:CHUNK_SIZE]
    folders = sum(1 for t in top_levels if children[t])
    print(f'[jev] {len(labels)} labels -> {len(top_levels)} top-level ({folders} folders)')

    decisions, unresolved = {}, []
    stats = {'senders_answered': 0, 'jev_calls': 0, 'jev_errors': 0, 'jev_timeouts': 0,
             'finalist_rounds': 0, 'input_tokens': 0, 'model': None, 'top_levels': len(top_levels)}
    lock = threading.Lock()
    started = time.monotonic()

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=JEV_CONCURRENCY)
    futures, diags = {}, {}
    for item in senders:
        email, state = _sender_state(item)
        diags[email] = {}
        futures[pool.submit(_decide_one, client, state, top_levels, children, stats, lock, diags[email])] = (item, email)

    done_items = set()
    try:
        for fut in concurrent.futures.as_completed(futures, timeout=phase_timeout):
            item, email = futures[fut]
            done_items.add(fut)
            stats['senders_answered'] += 1
            try:
                outcome = fut.result()
            except Exception as e:  # auth, rate limit after retries, network
                stats['jev_errors'] += 1
                if stats['jev_errors'] <= 3:
                    print(f'[jev] call failed for one sender: {type(e).__name__}: {e}')
                outcome = 'error'
            if outcome in (None, 'error'):
                unresolved.append(item)
            elif outcome[0] == 'no_label':
                decisions[email] = {'action': 'no_label', 'confidence': round(outcome[1], 3)}
            elif outcome[0] == 'use_existing':
                decisions[email] = {'action': 'use_existing', 'label': outcome[1], 'confidence': round(outcome[2], 3)}
            else:
                decisions[email] = {'action': 'new_in_folder', 'parent': outcome[1], 'confidence': round(outcome[2], 3)}
                unresolved.append(item)   # still needs a name from the LLM
            if JEV_DIAG_LOG:
                dg = diags.get(email, {})
                print(f"[jev-diag] {email} | personal={dg.get('personal')} | folder={dg.get('folder')} "
                      f"| sub={dg.get('sub_picks')} | final={dg.get('sub_final')} "
                      f"| -> {decisions.get(email, {}).get('action', 'unknown')} {decisions.get(email, {}).get('label') or decisions.get(email, {}).get('parent') or ''}")
            if on_result:
                try:
                    on_result(email, decisions.get(email))
                except Exception as e:
                    print(f'[jev] on_result callback failed: {e}')
    except concurrent.futures.TimeoutError:
        for fut, (item, _email) in futures.items():
            if fut not in done_items:
                fut.cancel()
                stats['jev_timeouts'] += 1
                unresolved.append(item)
        print(f'[jev] phase timeout after {phase_timeout}s; {stats["jev_timeouts"]} senders left undecided')
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    stats['seconds'] = round(time.monotonic() - started, 2)
    return decisions, unresolved, stats


def _decisions_to_groups(decisions):
    """Turn per-sender Jev decisions into the app's suggestion-group schema."""
    groups = {}
    for email, d in decisions.items():
        if d['action'] not in ('use_existing', 'no_label'):
            continue   # new_in_folder senders are also in `unresolved` and get named by the LLM
        name = _group_name_from_email(email)
        key = (d['action'], d.get('label'), name)
        g = groups.setdefault(key, {'senders': [], 'group_name': name, 'action': d['action'], 'source': 'jev'})
        if d['action'] == 'use_existing':
            g['label'] = d['label']
        g['senders'].append(email)
    return list(groups.values())


def suggest_labels_hybrid(senders, existing_labels, llm_fn):
    """
    Same contract as ai_labeler.suggest_labels: returns {'suggestions': [...]}.
    llm_fn(senders, existing_labels) -> {'suggestions': [...]} is the existing DeepSeek path.
    """
    client = None
    try:
        client = _make_client()
    except Exception as e:
        print(f'[jev] client init failed ({type(e).__name__}: {e}); using LLM only')

    if client is None:
        result = llm_fn(senders, existing_labels)
        result['meta'] = {'provider': 'llm_only', 'reason': 'jev_unavailable'}
        return result

    try:
        decisions, unresolved, stats = classify_with_jev(client, senders, existing_labels)
    finally:
        try:
            client.close()
        except Exception:
            pass

    # Every call failed (bad key, outage): behave exactly like the old path
    if stats['senders_answered'] and stats['jev_errors'] == stats['senders_answered']:
        print('[jev] all calls failed; falling back to LLM for everything')
        result = llm_fn(senders, existing_labels)
        result['meta'] = {'provider': 'llm_only', 'reason': 'jev_errors', **stats}
        return result

    suggestions = _decisions_to_groups(decisions)
    llm_error = None
    if unresolved:
        try:
            llm_result = llm_fn(unresolved, existing_labels)
            for g in llm_result.get('suggestions', []):
                g.setdefault('source', 'llm')
                suggestions.append(g)
        except Exception as e:
            # Keep Jev's answers even if the LLM half fails
            llm_error = f'{type(e).__name__}: {e}'
            print(f'[jev] LLM step failed for {len(unresolved)} senders: {llm_error}')
            if not suggestions:
                raise

    meta = {
        'provider': 'hybrid',
        'jev_resolved': sum(1 for d in decisions.values() if d['action'] in ('use_existing', 'no_label')),
        'llm_resolved': len(unresolved) if not llm_error else 0,
        'llm_error': llm_error,
        **stats,
    }
    print(f"[jev] done: {meta['jev_resolved']} by Jev, {len(unresolved)} to LLM, "
          f"{stats['jev_errors']} errors, {stats['input_tokens']} input tokens, {stats['seconds']}s, model={stats['model']}")
    return {'suggestions': suggestions, 'meta': meta}
