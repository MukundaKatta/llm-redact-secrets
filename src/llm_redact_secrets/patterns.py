"""Built-in regex patterns for well-known secret prefixes.

Each pattern is anchored on a vendor-specific prefix so the false positive
rate stays low. The trade-off documented for each pattern:

* AWS access key:    `AKIA` + 16 base32 chars.
  False positives:   class B IAM users with `ASIA` prefix are NOT caught;
                     use a custom pattern if you need them.
* AWS secret key:    detected via `AWS_SECRET_ACCESS_KEY=` env-style line.
                     Bare 40-char base64 secret strings are not matched
                     because the false positive rate is too high.
* OpenAI:            `sk-` followed by 20+ url-safe chars. Also matches
                     `sk-proj-...` and `sk-svcacct-...` modern formats.
* Anthropic:         `sk-ant-` followed by 90+ url-safe chars.
* GitHub PAT:        `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` plus 36 chars.
* Stripe:            `sk_live_`, `sk_test_`, `pk_live_`, `pk_test_` plus
                     24+ chars.
* Slack:             `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-` plus the
                     `<digits>-<digits>-...` structure.
* JWT:               three base64url segments separated by dots, anchored
                     to `eyJ` which is the base64 prefix of `{"`.
* Bearer:            `Authorization: Bearer <token>` header style.
* Google API key:    `AIza` + 35 url-safe chars.
"""

from __future__ import annotations

import re

from .types import SecretType

# (type, compiled_regex, group_index_for_value)
# group_index 0 means the whole match is the secret. >=1 means we capture a
# subgroup (used for Bearer header where we strip the `Authorization: Bearer `
# prefix from the redacted value).
BUILTIN_PATTERNS: list[tuple[SecretType, re.Pattern[str], int]] = [
    (
        SecretType.AWS_KEY,
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        0,
    ),
    (
        SecretType.AWS_SECRET,
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        1,
    ),
    (
        SecretType.ANTHROPIC_KEY,
        # Must be checked before generic OpenAI `sk-` to win the prefix race.
        re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{90,}"),
        0,
    ),
    (
        SecretType.OPENAI_KEY,
        # `sk-` followed by 20+ url-safe chars. Also covers `sk-proj-`,
        # `sk-svcacct-`, `sk-None-` modern formats. Excludes `sk-ant-` via
        # negative lookahead so Anthropic keys are attributed to Anthropic.
        re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_\-]{20,}"),
        0,
    ),
    (
        SecretType.GITHUB_PAT,
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
        0,
    ),
    (
        SecretType.STRIPE_KEY,
        re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b"),
        0,
    ),
    (
        SecretType.SLACK_TOKEN,
        # xoxb-1234-5678-abcdefg, xoxp-..., etc. At least one dash-segment.
        re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
        0,
    ),
    (
        SecretType.GOOGLE_API_KEY,
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        0,
    ),
    (
        SecretType.JWT,
        # eyJ header . eyJ payload . signature
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
        0,
    ),
    (
        SecretType.BEARER_TOKEN,
        # Authorization: Bearer <token>. We capture only the token in group 1.
        # Internal `.` and `=` are allowed (JWT-style tokens and base64 `=`
        # padding), but the token may not END on a `.` so a trailing sentence
        # period is not swallowed into the redacted value.
        re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9_\-=]+(?:\.[A-Za-z0-9_\-=]+)*)"),
        1,
    ),
]


# Heuristic for HIGH_ENTROPY type. Only used when entropy_check=True.
# Matches 32+ char runs of base64/hex/url-safe alphabets. The entropy
# check is applied separately in redact.py to discard low-entropy hits.
HIGH_ENTROPY_CANDIDATE = re.compile(r"\b[A-Za-z0-9_\-+/=]{32,}\b")
