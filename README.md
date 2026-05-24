# llm-redact-secrets

[![PyPI](https://img.shields.io/pypi/v/llm-redact-secrets.svg)](https://pypi.org/project/llm-redact-secrets/)
[![Python](https://img.shields.io/pypi/pyversions/llm-redact-secrets.svg)](https://pypi.org/project/llm-redact-secrets/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Redact API keys, tokens, JWTs, and credentials from LLM input or output.**

LLM agents can echo back secrets that appear in their context (logs, env
dumps, error traces, code). This library scans text for well-known secret
prefixes (AWS, OpenAI, Anthropic, GitHub, Stripe, Slack, Google, JWT,
Bearer headers) and replaces each with a stable placeholder. Zero
runtime dependencies.

## Install

```bash
pip install llm-redact-secrets
```

## Use

```python
from llm_redact_secrets import SecretRedactor

r = SecretRedactor()
# `sk-` prefix split to avoid push-protection false-positives on this README.
text = (
    "Run with AKIAIOSFODNN7EXAMPLE and "
    "OPENAI_API_KEY=" + "sk-" + "abc123def456ghi789jkl012mn "
    "and the token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signed"
)
redacted, hits = r.redact(text)

print(redacted)
# Run with <AWS_KEY_0> and OPENAI_API_KEY=<OPENAI_KEY_0> and the token <JWT_0>

for h in hits:
    print(h.type, h.start, h.end)
```

Stable placeholders mean the same secret appearing twice gets the same
index:

```python
text = "key1: AKIAIOSFODNN7EXAMPLE; key2: AKIAIOSFODNN7EXAMPLE"
redacted, _ = r.redact(text)
# key1: <AWS_KEY_0>; key2: <AWS_KEY_0>
```

## When you do not want the raw secret back

`redact_safe(text)` returns only the redacted string and discards the
hit list. Use this when you do not need to remember the original values.

```python
clean = r.redact_safe(user_prompt)
log.info("user prompt", text=clean)   # no secrets in your logs
```

## Non-destructive check

```python
if r.has_secrets(message):
    # tell the agent to refuse or sanitize
    ...
```

## Restrict detection to a subset

```python
from llm_redact_secrets import SecretRedactor, SecretType

# only care about cloud-provider credentials
r = SecretRedactor(types=[SecretType.AWS_KEY, SecretType.GOOGLE_API_KEY])
```

## Custom patterns

```python
r = SecretRedactor()
r.add_pattern("MY_TOKEN", r"\bmyapp-[A-Za-z0-9]{32}\b")
redacted, hits = r.redact("token: myapp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
# token: <MY_TOKEN_0>
```

If your regex defines a capture group, group 1 is used as the value
(handy for header-style patterns like `X-Token: <value>`).

## High-entropy heuristic (opt-in)

```python
r = SecretRedactor(entropy_check=True)
```

When enabled, runs of 32+ alphanumeric/base64 characters with Shannon
entropy above 4.0 bits/char are reported as `HIGH_ENTROPY`. This catches
unknown-vendor secrets but raises the false positive rate (long hash
digests, base64-encoded binary blobs, etc.). Leave it off when high
recall is not required.

## What this does NOT do

- It does not redact **user PII** (email, phone, SSN, credit card). For
  that, use the sibling library
  [`llm-pii-redact`](https://github.com/MukundaKatta/llm-pii-redact).
- It does not perform **wire capture** of HTTP requests to LLM providers.
  For that, use the sibling library
  [`agenttap`](https://github.com/MukundaKatta/agenttap).
- It does not block secrets at the network layer. It only rewrites text
  you hand it. For network-level egress control, see
  [`agentguard`](https://github.com/MukundaKatta/agentguard).
- It does not rotate or revoke detected secrets. That is your secret
  manager's job.

## Detected prefixes

| Type | Pattern anchor | Notes |
| ---- | --- | --- |
| `AWS_KEY` | `AKIA` + 16 chars | Long-term IAM access key. Temporary `ASIA` keys not matched. |
| `AWS_SECRET` | `AWS_SECRET_ACCESS_KEY=` env line | Bare 40-char secrets are not matched (too many false positives). |
| `OPENAI_KEY` | `sk-` (not `sk-ant-`) + 20+ chars | Covers `sk-`, `sk-proj-`, `sk-svcacct-`. |
| `ANTHROPIC_KEY` | `sk-ant-` + 90+ chars | |
| `GITHUB_PAT` | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36 chars | |
| `STRIPE_KEY` | `sk_live_` / `sk_test_` / `pk_live_` / `pk_test_` / `rk_*` + 24+ chars | |
| `SLACK_TOKEN` | `xoxb-` / `xoxp-` / `xoxa-` / `xoxr-` / `xoxs-` + 10+ chars | |
| `GOOGLE_API_KEY` | `AIza` + 35 chars | |
| `JWT` | three base64url segments anchored on `eyJ` | The `eyJ` prefix is the base64 of `{"`. |
| `BEARER_TOKEN` | `Authorization: Bearer <token>` | Captures only the token, leaves the header text alone. |
| `HIGH_ENTROPY` (opt-in) | 32+ char run with Shannon entropy >= 4.0 bits/char | False positives possible (hashes, base64 blobs). |

## License

MIT
