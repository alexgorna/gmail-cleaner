"""
AI Label Suggester — pluggable email grouping & Gmail label suggestion.

Feature flag : AI_LABELING_ENABLED   (default: true)  — set to "false" to disable entirely
Provider      : AI_PROVIDER           (default: deepseek) — swap to "openai" or any key in PROVIDER_CONFIGS
Max senders   : AI_MAX_SENDERS        (default: 500)
Timeout       : AI_TIMEOUT_SECONDS    (default: 90)  — read timeout per chunk; connect timeout is fixed at 10s

To add a new provider: add an entry to PROVIDER_CONFIGS and set AI_PROVIDER=<key>.
To disable entirely:   set AI_LABELING_ENABLED=false — no API calls will be made.
"""

import os
import re
import json
import requests as _http

# ── Feature flag ───────────────────────────────────────────────────────────────
AI_LABELING_ENABLED = os.environ.get('AI_LABELING_ENABLED', 'true').lower() == 'true'

# ── Runtime config ─────────────────────────────────────────────────────────────
AI_PROVIDER        = os.environ.get('AI_PROVIDER', 'deepseek')
AI_MAX_SENDERS     = int(os.environ.get('AI_MAX_SENDERS', '500'))
AI_TIMEOUT_SECONDS = int(os.environ.get('AI_TIMEOUT_SECONDS', '90'))

# ── Provider registry ──────────────────────────────────────────────────────────
# To swap providers: add an entry here and set AI_PROVIDER=<key> in env.
PROVIDER_CONFIGS = {
    'deepseek': {
        'base_url':    'https://api.deepseek.com',
        'api_key_env': 'DEEPSEEK_API_KEY',
        'model':       'deepseek-chat',
    },
    'openai': {
        'base_url':    'https://api.openai.com/v1',
        'api_key_env': 'OPENAI_API_KEY',
        'model':       'gpt-4o-mini',
    },
}

# ── System prompt ──────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """You are an email organization assistant helping a user label their Gmail inbox.

You will receive:
1. A list of sender email addresses (with optional subject lines for context)
2. The user's existing Gmail labels (with "/" for nesting, e.g. "Finance/Banks")

Your job:
1. Group senders that belong to the same company or organization. Think broadly — use domain knowledge, brand recognition, and common sense. For example, billing@harvard.edu and alumni@harvard-education.com both belong to "Harvard". Senders like noreply@stripe.com, billing@stripe.com, and receipts@stripe.com all belong to "Stripe".
2. For each group, decide whether a label is worth applying. Use action "no_label" when the sender appears to be a real person sending ad-hoc, infrequent, or conversational messages rather than automated/transactional email. Signals for "no_label": personal Gmail/Yahoo/Outlook addresses, subject lines that look like one-off conversations, irregular contact that isn't a service or newsletter.
3. For groups that deserve a label, suggest the best Gmail label. Study the user's existing label names and structure, and follow the same style and hierarchy wherever it makes sense.

Return a JSON object following this exact schema — no markdown fences, no explanation:
{
  "suggestions": [
    {
      "senders": ["billing@stripe.com", "noreply@stripe.com"],
      "group_name": "Stripe",
      "action": "use_existing",
      "label": "Finance/Stripe"
    },
    {
      "senders": ["hello@newplace.com"],
      "group_name": "New Place",
      "action": "create_new",
      "label": "Newsletters/New Place",
      "parent": "Newsletters"
    },
    {
      "senders": ["john.doe@gmail.com"],
      "group_name": "John Doe",
      "action": "no_label"
    }
  ]
}

Rules:
- "action" must be "use_existing" when the exact label already appears in the user's label list; "create_new" when a new label should be created; "no_label" when labeling is not recommended
- "label" is the full label path using "/" for nesting (e.g. "Finance/Stripe") — omit entirely when action is "no_label"
- "parent" is only included when action is "create_new" and you recommend nesting — set to the parent label name only (e.g. "Finance"), omit otherwise
- Every sender in the input must appear in exactly one group — no sender may be omitted or duplicated
- Keep group_name short and recognizable (company or brand name, not domain)
- When the user has no existing labels or none seem relevant, invent sensible top-level category labels
- Return only valid JSON"""


def suggest_labels(senders: list, existing_labels: list) -> dict:
    """
    Call the configured AI provider to group senders and suggest Gmail labels.

    Args:
        senders:         list of sender email address strings, OR list of dicts
                         with keys 'email' (str) and 'subjects' (list[str])
        existing_labels: list of user label name strings (e.g. ["Finance", "Finance/Banks"])

    Returns:
        dict with key "suggestions" — list of group objects per the schema above

    Raises:
        RuntimeError:           AI disabled or provider misconfigured
        requests.HTTPError:     non-2xx from the AI API
        json.JSONDecodeError:   response content is not valid JSON
    """
    if not AI_LABELING_ENABLED:
        raise RuntimeError('AI labeling is disabled (AI_LABELING_ENABLED=false)')

    config = PROVIDER_CONFIGS.get(AI_PROVIDER)
    if not config:
        raise RuntimeError(
            f'Unknown AI_PROVIDER: "{AI_PROVIDER}". '
            f'Valid options: {list(PROVIDER_CONFIGS.keys())}'
        )

    api_key = os.environ.get(config['api_key_env'])
    if not api_key:
        raise RuntimeError(
            f'Missing API key — set the {config["api_key_env"]} environment variable.'
        )

    # Respect sender cap
    senders = senders[:AI_MAX_SENDERS]

    # First attempt with up to AI_MAX_SENDERS
    try:
        return _call_provider(config, api_key, senders, existing_labels)
    except (json.JSONDecodeError, ValueError) as e:
        # Malformed or truncated JSON — retry with half the senders
        half = max(50, len(senders) // 2)
        print(f"[ai_labeler] JSON parse failed ({e}), retrying with {half} senders (was {len(senders)})")
        return _call_provider(config, api_key, senders[:half], existing_labels)


def _clean_json(raw: str) -> str:
    """Strip markdown fences and extract the outermost JSON object."""
    text = raw.strip()
    # Strip ```json ... ``` or ``` ... ``` fences
    text = re.sub(r'^```[a-z]*\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    text = text.strip()
    # Find the outermost { ... }
    start = text.find('{')
    end   = text.rfind('}')
    if start != -1 and end > start:
        text = text[start:end + 1]
    return text


def _call_provider(config: dict, api_key: str, senders: list, existing_labels: list) -> dict:
    """Make one API call and return parsed JSON. Raises on HTTP or JSON error.

    senders may be a list of plain email strings, or a list of dicts with
    keys 'email' (str) and 'subjects' (list[str]).  Subject lines are included
    in the prompt when available so the model can make better grouping decisions.
    """
    # Build one line per sender; include up to 3 subjects when present.
    sender_lines = []
    for s in senders:
        if isinstance(s, dict):
            email    = s.get('email', '')
            subjects = s.get('subjects') or []
            if subjects:
                quoted = ', '.join(f'"{subj}"' for subj in subjects[:3])
                sender_lines.append(f"{email} | subjects: {quoted}")
            else:
                sender_lines.append(email)
        else:
            sender_lines.append(s)

    label_block = '\n'.join(existing_labels) if existing_labels else '(none)'
    user_message = (
        f"SENDER LIST ({len(senders)} senders):\n"
        + '\n'.join(sender_lines)
        + f"\n\nEXISTING LABELS ({len(existing_labels)}):\n"
        + label_block
        + "\n\nGroup these senders and return Gmail label suggestions as JSON."
    )

    payload = {
        'model': config['model'],
        'messages': [
            {'role': 'system', 'content': _SYSTEM_PROMPT},
            {'role': 'user',   'content': user_message},
        ],
        'response_format': {'type': 'json_object'},
        'max_tokens': 4000,
        'temperature': 0.3,
    }

    print(f"[ai_labeler] → {config['model']} | {len(senders)} senders | {len(existing_labels)} labels")

    # timeout=(connect_seconds, read_seconds) — read timeout fires if the server
    # goes silent for that many seconds between bytes, catching slow model responses.
    response = _http.post(
        f"{config['base_url']}/chat/completions",
        headers={
            'Authorization': f"Bearer {api_key}",
            'Content-Type': 'application/json',
        },
        json=payload,
        timeout=(10, AI_TIMEOUT_SECONDS),
    )
    response.raise_for_status()

    body          = response.json()
    choice        = body['choices'][0]
    finish_reason = choice.get('finish_reason', 'unknown')
    message       = choice.get('message', {})
    content       = message.get('content') or ''

    # Some thinking-mode responses put text in reasoning_content instead of content
    if not content.strip():
        content = message.get('reasoning_content') or ''

    usage = body.get('usage', {})
    print(
        f"[ai_labeler] ← finish_reason={finish_reason!r} | "
        f"content={len(content)} chars | "
        f"tokens in={usage.get('prompt_tokens','?')} out={usage.get('completion_tokens','?')}"
    )

    if finish_reason == 'length':
        raise ValueError(
            f"Response truncated (finish_reason=length) after {len(content)} chars — "
            f"try fewer senders (sent {len(senders)})"
        )

    if not content.strip():
        raise ValueError(
            f"Empty content from API (finish_reason={finish_reason!r}) — "
            f"DeepSeek JSON mode occasionally returns empty; will retry"
        )

    cleaned = _clean_json(content)
    return json.loads(cleaned)
