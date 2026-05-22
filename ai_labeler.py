"""
AI Label Suggester — pluggable email grouping & Gmail label suggestion.

Feature flag : AI_LABELING_ENABLED   (default: true)  — set to "false" to disable entirely
Provider      : AI_PROVIDER           (default: deepseek) — swap to "openai" or any key in PROVIDER_CONFIGS
Max senders   : AI_MAX_SENDERS        (default: 500)
Timeout       : AI_TIMEOUT_SECONDS    (default: 90)

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
    """Make one API call and return parsed JSON. Raises on HTTP or JSON error."""
    label_block = '\n'.join(existing_labels) if existing_labels else '(none)'
    user_message = (
        f"SENDER LIST ({len(senders)} addresses):\n"
        + '\n'.join(senders)
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
        'max_tokens': 16000,
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

    body    = response.json()
    choice  = body['choices'][0]
    content = choice['message']['content']

    # Warn if the model hit its output token limit (response may be truncated)
    finish_reason = choice.get('finish_reason', '')
    if finish_reason == 'length':
        print(f"[ai_labeler] finish_reason=length — response truncated at {len(content)} chars. "
              f"Consider reducing AI_MAX_SENDERS (currently {len(senders)}).")

    cleaned = _clean_json(content)
    return json.loads(cleaned)
