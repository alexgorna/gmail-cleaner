"""
AI Label Suggester — pluggable email grouping & Gmail label suggestion.

Feature flag : AI_LABELING_ENABLED   (default: true)  — set to "false" to disable entirely
Provider      : AI_PROVIDER           (default: deepseek) — swap to "openai" or any key in PROVIDER_CONFIGS
Max senders   : AI_MAX_SENDERS        (default: 1000)
Timeout       : AI_TIMEOUT_SECONDS    (default: 60)

To add a new provider: add an entry to PROVIDER_CONFIGS and set AI_PROVIDER=<key>.
To disable entirely:   set AI_LABELING_ENABLED=false — no API calls will be made.
"""

import os
import json
import requests as _http

# ── Feature flag ───────────────────────────────────────────────────────────────
AI_LABELING_ENABLED = os.environ.get('AI_LABELING_ENABLED', 'true').lower() == 'true'

# ── Runtime config ─────────────────────────────────────────────────────────────
AI_PROVIDER        = os.environ.get('AI_PROVIDER', 'deepseek')
AI_MAX_SENDERS     = int(os.environ.get('AI_MAX_SENDERS', '1000'))
AI_TIMEOUT_SECONDS = int(os.environ.get('AI_TIMEOUT_SECONDS', '60'))

# ── Provider registry ──────────────────────────────────────────────────────────
# To swap providers: add an entry here and set AI_PROVIDER=<key> in env.
PROVIDER_CONFIGS = {
    'deepseek': {
        'base_url':    'https://api.deepseek.com',
        'api_key_env': 'DEEPSEEK_API_KEY',
        'model':       'deepseek-v4-flash',
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
1. A list of sender email addresses
2. The user's existing Gmail labels (with "/" for nesting, e.g. "Finance/Banks")

Your job:
1. Group senders that belong to the same company or organization. Think broadly — use domain knowledge, brand recognition, and common sense. For example, billing@harvard.edu and alumni@harvard-education.com both belong to "Harvard". Senders like noreply@stripe.com, billing@stripe.com, and receipts@stripe.com all belong to "Stripe".
2. For each group, suggest the best Gmail label. Study the user's existing label names and structure, and follow the same style and hierarchy wherever it makes sense.

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
    }
  ]
}

Rules:
- "action" must be "use_existing" when the exact label already appears in the user's label list; otherwise "create_new"
- "label" is the full label path using "/" for nesting (e.g. "Finance/Stripe")
- "parent" is only included when action is "create_new" and you recommend nesting — set to the parent label name only (e.g. "Finance"), omit otherwise
- Every sender in the input must appear in exactly one group — no sender may be omitted or duplicated
- Keep group_name short and recognizable (company or brand name, not domain)
- When the user has no existing labels or none seem relevant, invent sensible top-level category labels
- Return only valid JSON"""


def suggest_labels(senders: list, existing_labels: list) -> dict:
    """
    Call the configured AI provider to group senders and suggest Gmail labels.

    Args:
        senders:         list of sender email address strings
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

    label_block = '\n'.join(existing_labels) if existing_labels else '(none)'
    user_message = (
        f"SENDER LIST ({len(senders)} addresses):\n"
        + '\n'.join(senders)
        + f"\n\nEXISTING LABELS ({len(existing_labels)}):\n"
        + label_block
        + "\n\nPlease group these senders and return Gmail label suggestions as JSON."
    )

    payload = {
        'model': config['model'],
        'messages': [
            {'role': 'system', 'content': _SYSTEM_PROMPT},
            {'role': 'user',   'content': user_message},
        ],
        'response_format': {'type': 'json_object'},
        'max_tokens': 8000,
        'temperature': 0.3,
    }

    response = _http.post(
        f"{config['base_url']}/chat/completions",
        headers={
            'Authorization': f"Bearer {api_key}",
            'Content-Type': 'application/json',
        },
        json=payload,
        timeout=AI_TIMEOUT_SECONDS,
    )
    response.raise_for_status()

    content = response.json()['choices'][0]['message']['content']
    return json.loads(content)
