"""llm-redact-secrets - redact API keys, tokens, JWTs, and credentials.

Scan LLM input or output for vendor-prefixed secrets (AWS, OpenAI,
Anthropic, GitHub, Stripe, Slack, Google, JWT, Bearer tokens) and replace
them with stable placeholders. Optional high-entropy heuristic catches
unknown-vendor secrets at the cost of a higher false positive rate.

    from llm_redact_secrets import SecretRedactor, SecretType

    r = SecretRedactor()
    redacted, hits = r.redact("export AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
    # redacted -> "export AWS_ACCESS_KEY=<AWS_KEY_0>"

Use `redact_safe(text)` when you do not need the raw secrets back. Use
`has_secrets(text)` for a non-destructive yes/no check.

This library targets secrets, NOT user PII. For user data (emails, phone
numbers, SSNs, credit cards) see the sibling library `llm-pii-redact`.
For wire-level capture and redaction of HTTP requests to LLM providers,
see `agenttap`.
"""

from llm_redact_secrets.redact import SecretRedactor
from llm_redact_secrets.types import SecretHit, SecretType

__version__ = "0.1.0"

__all__ = [
    "SecretHit",
    "SecretRedactor",
    "SecretType",
    "__version__",
]
