"""Shared types: SecretType enum and SecretHit dataclass."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SecretType(StrEnum):
    """Categories of secret the redactor knows how to find.

    A custom pattern registered via `SecretRedactor.add_pattern(...)` will
    appear in `SecretHit.type` as its string name (not one of these enum
    values), so downstream filters should be string-aware.
    """

    AWS_KEY = "AWS_KEY"
    AWS_SECRET = "AWS_SECRET"
    OPENAI_KEY = "OPENAI_KEY"
    ANTHROPIC_KEY = "ANTHROPIC_KEY"
    GITHUB_PAT = "GITHUB_PAT"
    STRIPE_KEY = "STRIPE_KEY"
    SLACK_TOKEN = "SLACK_TOKEN"
    JWT = "JWT"
    BEARER_TOKEN = "BEARER_TOKEN"
    GOOGLE_API_KEY = "GOOGLE_API_KEY"
    HIGH_ENTROPY = "HIGH_ENTROPY"


@dataclass(frozen=True)
class SecretHit:
    """A single detected secret in the input text.

    Attributes:
        type: the secret category as a string. For builtin patterns this is
            the `SecretType` value (e.g. `"AWS_KEY"`). For custom patterns
            it is the name passed to `add_pattern`.
        value: the raw secret. Callers should treat this as sensitive and
            avoid logging or persisting it unnecessarily. Use
            `SecretRedactor.redact_safe(...)` when the raw value is not
            needed.
        start: inclusive start offset into the original text.
        end: exclusive end offset into the original text.
    """

    type: str
    value: str
    start: int
    end: int
