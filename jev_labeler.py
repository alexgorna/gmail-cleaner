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

NONE_OPTION   = '__none__'
MAX_OPTIONS   = 255          # Jev Choice limit, including NONE_OPTION
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


def classify_with_jev(client, senders, existing_labels):
    """
    Returns (decisions, unresolved, stats).
      decisions:  {email: {'action': 'no_label'|'use_existing', 'label'?: str, 'confidence': float}}
      unresolved: list of the original sender items Jev could not decide confidently
    """
    labels = _label_names(existing_labels)
    use_choice = 0 < len(labels) <= MAX_OPTIONS - 1
    questions = {'personal': _PERSONAL_Q}
    if use_choice:
        criteria = {name: None for name in labels}
        criteria[NONE_OPTION] = 'None of these labels fits this sender well.'
        questions['label'] = {'type': 'choice', 'instructions': _LABEL_INSTRUCTIONS, 'criteria': criteria}
    elif labels:
        print(f'[jev] {len(labels)} labels exceeds Choice limit; label matching left to the LLM')

    decisions, unresolved = {}, []
    stats = {'jev_calls': 0, 'jev_errors': 0, 'jev_timeouts': 0, 'input_tokens': 0, 'model': None}
    started = time.monotonic()

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=JEV_CONCURRENCY)
    futures = {}
    for item in senders:
        email, state = _sender_state(item)
        futures[pool.submit(_ask_jev, client, state, questions)] = (item, email)

    done_items = set()
    try:
        for fut in concurrent.futures.as_completed(futures, timeout=JEV_PHASE_TIMEOUT):
            item, email = futures[fut]
            done_items.add(fut)
            stats['jev_calls'] += 1
            try:
                resp = fut.result()
            except Exception as e:  # auth, rate limit after retries, network
                stats['jev_errors'] += 1
                if stats['jev_errors'] <= 3:
                    print(f'[jev] call failed for one sender: {type(e).__name__}: {e}')
                unresolved.append(item)
                continue
            stats['model'] = getattr(resp, 'model', None) or stats['model']
            usage = getattr(resp, 'usage', None)
            stats['input_tokens'] += (getattr(usage, 'input_tokens', 0) or 0)

            personal = resp.nouls.get('personal')
            if personal is not None and personal.noul >= JEV_PERSONAL_THRESHOLD:
                decisions[email] = {'action': 'no_label', 'confidence': round(personal.noul, 3)}
                continue
            pick = resp.choices.get('label') if use_choice else None
            if pick is not None and pick.choice != NONE_OPTION and pick.confidence >= JEV_MIN_CONFIDENCE:
                decisions[email] = {'action': 'use_existing', 'label': pick.choice,
                                    'confidence': round(pick.confidence, 3)}
                continue
            unresolved.append(item)
    except concurrent.futures.TimeoutError:
        for fut, (item, _email) in futures.items():
            if fut not in done_items:
                fut.cancel()
                stats['jev_timeouts'] += 1
                unresolved.append(item)
        print(f'[jev] phase timeout after {JEV_PHASE_TIMEOUT}s; {stats["jev_timeouts"]} senders sent to LLM')
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
    if stats['jev_calls'] and stats['jev_errors'] == stats['jev_calls']:
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
