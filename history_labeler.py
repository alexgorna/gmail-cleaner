"""
History labeler: recommend labels from what the user ALREADY does in Gmail, before any AI.

Works the same for every user, in any language or folder style:
  1. Filters: the user's Gmail filters that add a label for a sender ("from:") are explicit rules.
     A sender matched by such a filter gets that label (source "filter").
  2. History: where the user filed earlier emails from the same sender. One search per sender
     (`from:<address> has:userlabels`), then the user labels on up to HISTORY_SAMPLE of those emails.
     The label on most of them wins if it covers at least HISTORY_MIN_SHARE of the sample (source "history").
Senders not decided here go on to Jev.

Lookups run on HISTORY_WORKERS parallel Gmail connections with backoff on rate limits
(Gmail batch requests were tried first and hit "too many concurrent requests" on a real account).
Env vars: HISTORY_ENABLED (true), HISTORY_SAMPLE (3), HISTORY_MIN_SHARE (0.6), HISTORY_WORKERS (5), HISTORY_RETRIES (4).
"""

import os
import re
import time
import threading
import concurrent.futures
from collections import Counter

HISTORY_ENABLED   = os.environ.get('HISTORY_ENABLED', 'true').lower() == 'true'
HISTORY_SAMPLE    = int(os.environ.get('HISTORY_SAMPLE', '3'))
HISTORY_MIN_SHARE = float(os.environ.get('HISTORY_MIN_SHARE', '0.6'))
HISTORY_WORKERS   = int(os.environ.get('HISTORY_WORKERS', '5'))   # parallel Gmail connections
HISTORY_RETRIES   = int(os.environ.get('HISTORY_RETRIES', '4'))
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


def _execute(req):
    """Run one Gmail request, backing off on rate limits (429 / 403 rateLimitExceeded) and server errors."""
    for attempt in range(HISTORY_RETRIES):
        try:
            return req.execute()
        except Exception as e:
            status = getattr(getattr(e, 'resp', None), 'status', None)
            text = str(e)
            retryable = status in (429, 500, 502, 503) or (status == 403 and 'ateLimit' in text)
            if not retryable or attempt == HISTORY_RETRIES - 1:
                raise
            time.sleep(min(0.5 * (2 ** attempt), 4))


def _sender_history(service, email, id2name):
    """(Counter of user labels on the sender's last HISTORY_SAMPLE labeled emails, number sampled)."""
    users = service.users()
    res = _execute(users.messages().list(userId='me', q=f'from:({email}) has:userlabels',
                                         maxResults=HISTORY_SAMPLE))
    votes, n = Counter(), 0
    for m in (res or {}).get('messages', [])[:HISTORY_SAMPLE]:
        msg = _execute(users.messages().get(userId='me', id=m['id'], format='minimal'))
        n += 1
        for lid in (msg or {}).get('labelIds', []):
            if lid in id2name:
                votes[id2name[lid]] += 1
    return votes, n


def history_votes(service_factory, emails, id2name, on_progress=None, cache=None):
    """
    {email: Counter}, {email: sampled}. Runs HISTORY_WORKERS senders in parallel, each worker with its own
    Gmail client (the Google client is not thread-safe). Failed senders are simply left out.
    """
    local = threading.local()

    def svc():
        if not hasattr(local, 'service'):
            local.service = service_factory()
        return local.service

    votes, sampled, errors = {}, {}, Counter()
    todo = []
    for e in emails:
        hit = cache.get(e) if cache else None
        if hit is not None:
            votes[e], sampled[e] = Counter(hit[0]), hit[1]
        else:
            todo.append(e)
    if cache and len(todo) < len(emails):
        print(f'[history] cache: {len(emails) - len(todo)} senders already known, {len(todo)} to look up')
    with concurrent.futures.ThreadPoolExecutor(max_workers=HISTORY_WORKERS) as pool:
        futs = {pool.submit(lambda e=e: _sender_history(svc(), e, id2name)): e for e in todo}
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            e = futs[fut]
            try:
                votes[e], sampled[e] = fut.result()
                if cache:
                    cache.set(e, dict(votes[e]), sampled[e])
            except Exception as ex:
                errors[type(ex).__name__] += 1
                if sum(errors.values()) <= 3:
                    print(f'[history] lookup failed for one sender: {type(ex).__name__}: {str(ex)[:200]}')
            if on_progress and (i % 5 == 0 or i == len(futs)):
                on_progress(i, len(futs))
    if errors:
        print(f'[history] Gmail errors after retries: {dict(errors)}')
    return votes, sampled


def classify_from_history(service_factory, senders, on_result=None, on_progress=None, cache=None):
    """
    Returns (decisions, remaining, stats).
      decisions: {email: {'action': 'use_existing', 'label', 'confidence', 'source': 'filter'|'history'}}
      remaining: sender items still undecided (for Jev)
    """
    started = time.monotonic()
    stats = {'filter': 0, 'history': 0, 'filters_read': 0}
    if not HISTORY_ENABLED or service_factory is None:
        return {}, list(senders), stats

    def email_of(item):
        return (item.get('email') if isinstance(item, dict) else str(item)).lower()

    service = service_factory()
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

    votes, sampled = history_votes(service_factory, [email_of(i) for i in remaining], id2name, on_progress, cache)
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
