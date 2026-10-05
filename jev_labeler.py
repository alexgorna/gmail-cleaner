"""
Jev hybrid labeler: Jev (TypeSafe System One) makes fast, cheap decisions; the LLM only names new labels.

How it works, per sender (email + up to 3 recent subjects):
  1. One Jev call answers two questions in parallel:
       - "personal": Noul, probability the sender is a real person writing ad-hoc mail
       - "label":    Choice over the user's EXISTING labels, plus a "none fits" option
  2. Routing:
       personal >= JEV_PERSONAL_THRESHOLD              -> action "no_label"
       label != none and confidence >= JEV_MIN_CONFIDENCE -> action "use_existing"
       anything else                                   -> sent to the LLM (DeepSeek) to group and name
  3. If Jev is unavailable (missing key, auth, network), everything goes to the LLM as before.

Env vars:
  TYPESAFE_API_KEY        required for Jev (read by the SDK)
  JEV_MODEL               default "jev-1.13.0" (pinned for reproducible results)
  JEV_MIN_CONFIDENCE      default 0.70
  JEV_PERSONAL_THRESHOLD  default 0.80
  JEV_CONCURRENCY         default 8 parallel requests
  JEV_PHASE_TIMEOUT       default 45 s; senders Jev hasn't answered by then go to the LLM

Email subjects are attacker-controlled text. Jev can only return one of the options we give it,
so a malicious subject can at worst cause a wrong (but valid) pick, never arbitrary output.
"""

import os
import re
import time
import concurrent.futures

JEV_MODEL              = os.environ.get('JEV_MODEL', 'jev-1.13.0')
JEV_MIN_CONFIDENCE     = float(os.environ.get('JEV_MIN_CONFIDENCE', '0.70'))
JEV_PERSONAL_THRESHOLD = float(os.environ.get('JEV_PERSONAL_THRESHOLD', '0.80'))
JEV_CONCURRENCY        = int(os.environ.get('JEV_CONCURRENCY', '8'))
JEV_PHASE_TIMEOUT      = int(os.environ.get('JEV_PHASE_TIMEOUT', '45'))
JEV_DIAG_LOG           = os.environ.get('JEV_DIAG_LOG', 'true').lower() == 'true'  # per-sender score log for tuning

NONE_OPTION   = '__none__'
MAX_OPTIONS   = 255          # Jev Choice limit, including NONE_OPTION
CHUNK_SIZE    = MAX_OPTIONS - 1
CANDIDATE_MIN = float(os.environ.get('JEV_CANDIDATE_MIN', '0.35'))  # stage-1 bar to become a finalist
MAX_SUBJECTS  = 3
MAX_SUBJ_LEN  = 200

_PERSONAL_Q = {
    'type': 'noul',
    'instructions': (
        'Is this sender a real individual person writing personal, ad-hoc or conversational email, '
        'rather than an automated, marketing, newsletter, notification, receipt or company system sender?'
    ),
}

_LABEL_INSTRUCTIONS = (
    'Which of the user\'s existing Gmail labels is the best folder for all email from this sender? '
    f'Pick "{NONE_OPTION}" if none of the labels is a good fit.'
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
    return [n for n in dict.fromkeys(names) if n and n != NONE_OPTION]


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


def _ask_jev(client, state, questions):
    return client.system_one(state=state, questions=questions)


def _label_question(names):
    criteria = {name: None for name in names}
    criteria[NONE_OPTION] = 'None of these labels fits this sender well.'
    return {'type': 'choice', 'instructions': _LABEL_INSTRUCTIONS, 'criteria': criteria}


def _decide_one(client, state, base_questions, n_chunks, stats, diag=None):
    """
    One sender. Labels beyond Jev's 255-option limit are split into chunks asked in the SAME request
    (one Choice per chunk). When there is more than one chunk, the best pick of each chunk becomes a
    finalist and a second request chooses among the finalists, so confidences are comparable.
    Returns ('no_label', p) | ('use_existing', label, conf) | None.
    """
    resp = _ask_jev(client, state, base_questions)
    stats['jev_calls'] += 1
    stats['model'] = getattr(resp, 'model', None) or stats['model']
    stats['input_tokens'] += (getattr(getattr(resp, 'usage', None), 'input_tokens', 0) or 0)

    diag = diag if diag is not None else {}
    personal = resp.nouls.get('personal')
    diag['personal'] = round(personal.noul, 3) if personal is not None else None
    raw_picks = [resp.choices.get(f'label_{i}') for i in range(n_chunks)]
    diag['picks'] = [(p.choice, round(p.confidence, 3)) for p in raw_picks if p is not None]
    if personal is not None and personal.noul >= JEV_PERSONAL_THRESHOLD:
        return ('no_label', personal.noul)
    if n_chunks == 0:
        return None

    picks = raw_picks
    picks = [p for p in picks if p is not None and p.choice != NONE_OPTION]
    if n_chunks == 1:
        p = picks[0] if picks else None
        return ('use_existing', p.choice, p.confidence) if p and p.confidence >= JEV_MIN_CONFIDENCE else None

    finalists = [p.choice for p in picks if p.confidence >= CANDIDATE_MIN]
    if not finalists:
        return None
    final = _ask_jev(client, state, {'label': _label_question(finalists)})
    stats['jev_calls'] += 1
    stats['finalist_rounds'] += 1
    stats['input_tokens'] += (getattr(getattr(final, 'usage', None), 'input_tokens', 0) or 0)
    p = final.choices.get('label')
    if p:
        diag['final'] = (p.choice, round(p.confidence, 3))
    if p and p.choice != NONE_OPTION and p.confidence >= JEV_MIN_CONFIDENCE:
        return ('use_existing', p.choice, p.confidence)
    return None


def classify_with_jev(client, senders, existing_labels, on_result=None, phase_timeout=None):
    """
    Returns (decisions, unresolved, stats).
      decisions:  {email: {'action': 'no_label'|'use_existing', 'label'?: str, 'confidence': float}}
      unresolved: list of the original sender items Jev could not decide confidently
    on_result(email, decision_or_None) is called as each sender finishes (used for live page updates).
    """
    phase_timeout = phase_timeout or JEV_PHASE_TIMEOUT
    labels = _label_names(existing_labels)
    chunks = [labels[i:i + CHUNK_SIZE] for i in range(0, len(labels), CHUNK_SIZE)]
    questions = {'personal': _PERSONAL_Q}
    for i, chunk in enumerate(chunks):
        questions[f'label_{i}'] = _label_question(chunk)
    if len(chunks) > 1:
        print(f'[jev] {len(labels)} labels -> {len(chunks)} chunks + finalist round')

    decisions, unresolved = {}, []
    stats = {'senders_answered': 0, 'jev_calls': 0, 'jev_errors': 0, 'jev_timeouts': 0,
             'finalist_rounds': 0, 'input_tokens': 0, 'model': None, 'label_chunks': len(chunks)}
    started = time.monotonic()

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=JEV_CONCURRENCY)
    futures = {}
    diags = {}
    for item in senders:
        email, state = _sender_state(item)
        diags[email] = {}
        futures[pool.submit(_decide_one, client, state, questions, len(chunks), stats, diags[email])] = (item, email)

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
                unresolved.append(item)
                continue
            if outcome is None:
                unresolved.append(item)
            elif outcome[0] == 'no_label':
                decisions[email] = {'action': 'no_label', 'confidence': round(outcome[1], 3)}
            else:
                decisions[email] = {'action': 'use_existing', 'label': outcome[1],
                                    'confidence': round(outcome[2], 3)}
            if JEV_DIAG_LOG:
                dg = diags.get(email, {})
                print(f"[jev-diag] {email} | personal={dg.get('personal')} | picks={dg.get('picks')} "
                      f"| final={dg.get('final')} | -> {decisions.get(email, {}).get('action', 'unknown')}")
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
        'jev_resolved': len(decisions),
        'llm_resolved': len(unresolved) if not llm_error else 0,
        'llm_error': llm_error,
        **stats,
    }
    print(f"[jev] done: {meta['jev_resolved']} by Jev, {len(unresolved)} to LLM, "
          f"{stats['jev_errors']} errors, {stats['input_tokens']} input tokens, {stats['seconds']}s, model={stats['model']}")
    return {'suggestions': suggestions, 'meta': meta}
