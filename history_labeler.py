"""
History labeler: recommend labels from what the user ALREADY does in Gmail, before any AI.

Works the same for every user, in any language or folder style:
  1. Filters: the user's Gmail filters that add a label for a sender ("from:") are explicit rules.
     A sender matched by such a filter gets that label (source "filter").
  2. History: where the user filed earlier emails from the same sender. One search per sender
     (`from:<address> has:userlabels`), then the user labels on up to HISTORY_SAMPLE of those emails.
     The label on most of them wins if it covers at least HISTORY_MIN_SHARE of the sample (source "history").
Senders not decided here go on to Jev.

Gmail calls are sent in batches (HISTORY_BATCH per HTTP request) to stay fast and inside quota.
Env vars: HISTORY_ENABLED (true), HISTORY_SAMPLE (5), HISTORY_MIN_SHARE (0.6), HISTORY_BATCH (40).
"""

import os
import re
import time
from collections import Counter

HISTORY_ENABLED   = os.environ.get('HISTORY_ENABLED', 'true').lower() == 'true'
HISTORY_SAMPLE    = int(os.environ.get('HISTORY_SAMPLE', '5'))
HISTORY_MIN_SHARE = float(os.environ.get('HISTORY_MIN_SHARE', '0.6'))
HISTORY_BATCH     = int(os.environ.get('HISTORY_BATCH', '40'))
HISTORY_DIAG_LOG  = os.environ.get('JEV_DIAG_LOG', 'true').lower() == 'true'

# Filters with these criteria are not plain "this sender -> this label" rules
_NON_SENDER_CRITERIA = ('to', 'subject', 'query', 'negatedQuery', 'hasAttachment', 'size', 'sizeComparison')


def user_label_map(service):
    """{label_id: label_name} for the user's own labels."""
    res = service.users().labels().list(userId='me').execute()
    return {l['id']: l['name'] for l in res.get('labels', []) if l.get('type') == 'user'}


def _from_terms(expr):
    """'a@x.com OR b@y.com', '(x.com | y.com)', '{a b}' -> ['a@x.com', 'b@y.com', ...]"""
    expr = re.sub(r'[(){}"]', ' ', expr.lower())
    return [t for t in re.split(r'\s+|\bor\b|\|', expr) if t and t != 'or']


def load_sender_filters(service, id2name):
    """[(terms, label_name)] for filters that only look at the sender and add one of the user's labels."""
    try:
        res = service.users().settings().filters().list(userId='me').execute()
    except Exception as e:
        print(f'[history] could not read filters: {type(e).__name__}: {e}')
        return []
    rules = []
    for f in res.get('filter', []):
        crit, action = f.get('criteria', {}) or {}, f.get('action', {}) or {}
        if not crit.get('from') or any(crit.get(k) for k in _NON_SENDER_CRITERIA):
            continue
        labels = [id2name[i] for i in action.get('addLabelIds', []) if i in id2name]
        if len(labels) != 1:
            continue
        terms = _from_terms(crit['from'])
        if terms:
            rules.append((terms, labels[0]))
    return rules


def _term_matches(term, email):
    domain = email.partition('@')[2]
    if '@' in term and not term.startswith('@'):
        return email == term
    term = term.lstrip('@')
    if '.' in term:                                  # a domain: exact or sub-domain
        return domain == term or domain.endswith('.' + term)
    return len(term) >= 4 and term in email          # a bare word, e.g. from:amazon


def match_filter(email, rules):
    email = email.lower()
    for terms, label in rules:
        if any(_term_matches(t, email) for t in terms):
            return label
    return None


def _batched(service, requests, callback):
    """Run (key, request) pairs through Gmail batch HTTP; callback(key, response, exception)."""
    for i in range(0, len(requests), HISTORY_BATCH):
        chunk = requests[i:i + HISTORY_BATCH]
        batch = service.new_batch_http_request()
        for key, req in chunk:
            batch.add(req, callback=lambda _rid, resp, exc, key=key: callback(key, resp, exc), request_id=None)
        for attempt in range(3):
            try:
                batch.execute()
                break
            except Exception as e:
                if attempt == 2:
                    print(f'[history] batch failed: {type(e).__name__}: {e}')
                time.sleep(1 + attempt)


def history_votes(service, emails, id2name):
    """{email: Counter(label_name -> number of sampled past emails carrying it), '_sampled': n}"""
    ids_by_email, errors = {}, Counter()

    def on_list(email, resp, exc):
        if exc is not None:
            errors['list'] += 1
            return
        ids_by_email[email] = [m['id'] for m in (resp or {}).get('messages', [])][:HISTORY_SAMPLE]

    users = service.users()
    _batched(service, [
        (e, users.messages().list(userId='me', q=f'from:({e}) has:userlabels', maxResults=HISTORY_SAMPLE))
        for e in emails
    ], on_list)

    votes = {e: Counter() for e in emails}
    sampled = Counter()

    def on_get(key, resp, exc):
        email = key[0]
        if exc is not None:
            errors['get'] += 1
            return
        sampled[email] += 1
        for lid in (resp or {}).get('labelIds', []):
            if lid in id2name:
                votes[email][id2name[lid]] += 1

    gets = [((e, mid), users.messages().get(userId='me', id=mid, format='minimal'))
            for e, mids in ids_by_email.items() for mid in mids]
    _batched(service, gets, on_get)
    if errors:
        print(f'[history] Gmail errors: {dict(errors)}')
    return votes, sampled


def classify_from_history(service, senders, on_result=None):
    """
    Returns (decisions, remaining, stats).
      decisions: {email: {'action': 'use_existing', 'label', 'confidence', 'source': 'filter'|'history'}}
      remaining: sender items still undecided (for Jev)
    """
    started = time.monotonic()
    stats = {'filter': 0, 'history': 0, 'filters_read': 0}
    if not HISTORY_ENABLED or service is None:
        return {}, list(senders), stats

    def email_of(item):
        return (item.get('email') if isinstance(item, dict) else str(item)).lower()

    id2name = user_label_map(service)
    rules = load_sender_filters(service, id2name)
    stats['filters_read'] = len(rules)

    decisions, remaining = {}, []
    for item in senders:
        email = email_of(item)
        label = match_filter(email, rules)
        if label:
            decisions[email] = {'action': 'use_existing', 'label': label, 'confidence': 1.0, 'source': 'filter'}
            stats['filter'] += 1
            if on_result:
                on_result(email, decisions[email])
        else:
            remaining.append(item)

    votes, sampled = history_votes(service, [email_of(i) for i in remaining], id2name)
    still = []
    for item in remaining:
        email = email_of(item)
        v, n = votes.get(email), sampled.get(email, 0)
        if v and n:
            label, count = v.most_common(1)[0]
            share = count / n
            if share >= HISTORY_MIN_SHARE:
                decisions[email] = {'action': 'use_existing', 'label': label, 'confidence': round(share, 3),
                                    'source': 'history', 'evidence': f'{count} of {n}'}
                stats['history'] += 1
                if on_result:
                    on_result(email, decisions[email])
                if HISTORY_DIAG_LOG:
                    print(f'[history-diag] {email} | {dict(v)} of {n} -> {label}')
                continue
        if HISTORY_DIAG_LOG and v:
            print(f'[history-diag] {email} | {dict(v)} of {n} -> no clear label')
        still.append(item)

    stats['seconds'] = round(time.monotonic() - started, 2)
    return decisions, still, stats
