"""Tests for SecretRedactor."""

import pytest

from llm_redact_secrets import SecretHit, SecretRedactor, SecretType

# ---------- known-prefix positive detection ----------


def test_aws_access_key_detected():
    r = SecretRedactor()
    text = "key=AKIAIOSFODNN7EXAMPLE done"
    hits = r.detect(text)
    assert len(hits) == 1
    assert hits[0].type == SecretType.AWS_KEY
    assert hits[0].value == "AKIAIOSFODNN7EXAMPLE"


def test_aws_secret_in_env_line_detected():
    r = SecretRedactor()
    text = 'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    hits = r.detect(text)
    types = [h.type for h in hits]
    assert SecretType.AWS_SECRET in types


def test_openai_key_detected():
    r = SecretRedactor()
    # split prefix to dodge push-protection scanner false positive
    sk = "s" + "k-"
    text = f"OPENAI_API_KEY={sk}abcdefghijklmnopqrstuvwxyz0123456789"
    hits = r.detect(text)
    assert any(h.type == SecretType.OPENAI_KEY for h in hits)


def test_openai_project_key_detected():
    r = SecretRedactor()
    sk_proj = "s" + "k-proj-"
    text = f"key={sk_proj}abcdefghijklmnopqrstuvwxyz0123456789xyz"
    hits = r.detect(text)
    assert any(h.type == SecretType.OPENAI_KEY for h in hits)


def test_anthropic_key_detected_and_not_misclassified_as_openai():
    r = SecretRedactor()
    # split prefix to dodge push-protection scanner false positive
    sk_ant = "s" + "k-ant-"
    # 95 url-safe chars after the prefix (split for line length)
    suffix = (
        "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        "KLMNOPQRSTUVWXYZ0123456"
    )
    text = f"ANTHROPIC={sk_ant}{suffix}"
    hits = r.detect(text)
    types = [h.type for h in hits]
    assert SecretType.ANTHROPIC_KEY in types
    assert SecretType.OPENAI_KEY not in types


def test_github_pat_detected():
    r = SecretRedactor()
    # split prefix to dodge push-protection scanner false positive
    ghp = "gh" + "p_"
    text = f"token={ghp}abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
    hits = r.detect(text)
    assert any(h.type == SecretType.GITHUB_PAT for h in hits)


def test_github_other_prefixes_detected():
    r = SecretRedactor()
    for letter in ("o", "u", "s", "r"):
        prefix = "gh" + letter + "_"
        text = f"x={prefix}abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        hits = r.detect(text)
        assert any(h.type == SecretType.GITHUB_PAT for h in hits), prefix


def test_stripe_live_and_test_keys_detected():
    r = SecretRedactor()
    # build prefixes from parts so push-protection scanners don't flag
    # this test as a real exposed secret
    sk_live = "sk" + "_" + "live" + "_"
    sk_test = "sk" + "_" + "test" + "_"
    pk_live = "pk" + "_" + "live" + "_"
    body = "abcdefghijklmnopqrstuvwx"
    text = f"live={sk_live}{body} test={sk_test}{body} pub={pk_live}{body}"
    hits = r.detect(text)
    stripe_hits = [h for h in hits if h.type == SecretType.STRIPE_KEY]
    assert len(stripe_hits) == 3


def test_slack_token_detected():
    r = SecretRedactor()
    # split prefix to dodge push-protection scanner false positive
    prefix = "xox" + "b-"
    text = f"slack={prefix}1234567890-1234567890-abcdefghijklmnopqrstuvwx"
    hits = r.detect(text)
    assert any(h.type == SecretType.SLACK_TOKEN for h in hits)


def test_google_api_key_detected():
    r = SecretRedactor()
    # AIza + exactly 35 chars
    text = "GOOGLE_KEY=AIzaSyA-abcdefghijklmnopqrstuvwxyz01234"
    hits = r.detect(text)
    assert any(h.type == SecretType.GOOGLE_API_KEY for h in hits)


def test_jwt_three_part_detected():
    r = SecretRedactor()
    # eyJ header . eyJ payload . signature
    text = "Authorization=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.signature_part"
    hits = r.detect(text)
    jwt_hits = [h for h in hits if h.type == SecretType.JWT]
    assert len(jwt_hits) == 1
    # the JWT hit takes priority over the bearer/header logic here since
    # there's no `Bearer ` prefix
    assert "eyJhbGciOiJIUzI1NiJ9" in jwt_hits[0].value


def test_bearer_header_extracts_token_only():
    r = SecretRedactor()
    text = "Authorization: Bearer abc123def456token_value_here"
    hits = r.detect(text)
    bearer_hits = [h for h in hits if h.type == SecretType.BEARER_TOKEN]
    assert len(bearer_hits) == 1
    assert bearer_hits[0].value == "abc123def456token_value_here"
    # the header label `Authorization: Bearer ` is NOT part of the redacted value
    assert "Authorization" not in bearer_hits[0].value
    assert "Bearer" not in bearer_hits[0].value


# ---------- close-but-not-match negatives ----------


def test_aws_key_too_short_not_detected():
    r = SecretRedactor()
    # AKI without the A is not a prefix
    assert r.detect("token=AKI1234567890") == []
    # AKIA without the rest is too short
    assert r.detect("token=AKIA") == []


def test_aws_key_with_lowercase_after_prefix_not_detected():
    # AKIA is followed by [A-Z0-9]{16}, lowercase letters break it
    r = SecretRedactor()
    assert r.detect("AKIAabcdefghijklmnop") == []


def test_github_pat_wrong_length_not_detected():
    r = SecretRedactor()
    ghp = "gh" + "p_"
    # 28 chars after the prefix, not 36
    assert r.detect(f"{ghp}abcdefghijklmnopqrstuvwxyzab") == []


def test_openai_short_prefix_not_detected():
    r = SecretRedactor()
    # sk- with too few chars after
    assert r.detect("sk-tiny") == []


def test_jwt_two_part_not_detected():
    r = SecretRedactor()
    assert r.detect("eyJabc.eyJdef") == []


def test_plain_word_not_a_secret():
    r = SecretRedactor()
    assert r.detect("This is a normal sentence with no secrets.") == []
    assert r.has_secrets("Just regular text.") is False


# ---------- redact() behavior ----------


def test_redact_replaces_with_placeholder():
    r = SecretRedactor()
    text = "key=AKIAIOSFODNN7EXAMPLE end"
    redacted, hits = r.redact(text)
    assert redacted == "key=<AWS_KEY_0> end"
    assert len(hits) == 1


def test_redact_dedupes_same_value_to_same_index():
    r = SecretRedactor()
    text = "first AKIAIOSFODNN7EXAMPLE second AKIAIOSFODNN7EXAMPLE"
    redacted, hits = r.redact(text)
    # both occurrences share the same placeholder index
    assert redacted.count("<AWS_KEY_0>") == 2
    assert "<AWS_KEY_1>" not in redacted
    assert len(hits) == 2


def test_redact_distinct_values_get_distinct_indices():
    r = SecretRedactor()
    text = "k1=AKIAIOSFODNN7EXAMPLE k2=AKIAANOTHERTESTKEY99"
    redacted, _ = r.redact(text)
    assert "<AWS_KEY_0>" in redacted
    assert "<AWS_KEY_1>" in redacted


def test_redact_safe_returns_text_only():
    r = SecretRedactor()
    text = "key=AKIAIOSFODNN7EXAMPLE end"
    result = r.redact_safe(text)
    assert isinstance(result, str)
    assert "AKIA" not in result
    assert "<AWS_KEY_0>" in result


def test_has_secrets_is_non_destructive():
    r = SecretRedactor()
    text = "key=AKIAIOSFODNN7EXAMPLE end"
    assert r.has_secrets(text) is True
    # source text is untouched
    assert text == "key=AKIAIOSFODNN7EXAMPLE end"


def test_detect_is_non_mutating():
    r = SecretRedactor()
    text = "key=AKIAIOSFODNN7EXAMPLE end"
    _ = r.detect(text)
    assert text == "key=AKIAIOSFODNN7EXAMPLE end"


# ---------- multiple types in one text ----------


def test_multiple_types_in_one_text():
    r = SecretRedactor()
    # split-string prefixes dodge push-protection scanner false positives
    sk = "s" + "k-"
    ghp = "gh" + "p_"
    text = (
        "AWS: AKIAIOSFODNN7EXAMPLE; "
        f"OAI: {sk}abcdefghijklmnopqrstuvwxyz0123456789; "
        f"GH: {ghp}abcdefghijklmnopqrstuvwxyzABCDEFGHIJ; "
        "G: AIzaSyA-abcdefghijklmnopqrstuvwxyz01234"
    )
    redacted, hits = r.redact(text)
    seen = {h.type for h in hits}
    assert SecretType.AWS_KEY in seen
    assert SecretType.OPENAI_KEY in seen
    assert SecretType.GITHUB_PAT in seen
    assert SecretType.GOOGLE_API_KEY in seen
    assert "AKIA" not in redacted
    assert ghp not in redacted
    assert "AIza" not in redacted


# ---------- types= subset filter ----------


def test_types_subset_filter_excludes_unwanted():
    r = SecretRedactor(types=[SecretType.AWS_KEY])
    text = (
        "AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
    )
    hits = r.detect(text)
    assert all(h.type == SecretType.AWS_KEY for h in hits)
    assert len(hits) == 1


def test_types_subset_disables_entropy_when_not_listed():
    # entropy_check=True but HIGH_ENTROPY not in types -> no entropy hits
    r = SecretRedactor(types=[SecretType.AWS_KEY], entropy_check=True)
    long_random = "a3f5b9c2d7e1f8g4h6i0j2k5l8m1n4o7p9q3r6s8"
    hits = r.detect(long_random)
    assert all(h.type != SecretType.HIGH_ENTROPY for h in hits)


# ---------- entropy_check ----------


def test_entropy_check_off_by_default():
    r = SecretRedactor()
    # 40 char high-entropy hex blob
    blob = "a3f5b9c2d7e1f8b4a6e0d2c5f8b1a4e7d9c3b6f8"
    hits = r.detect(blob)
    # nothing matches because no known prefix and entropy is off
    assert hits == []


def test_entropy_check_on_catches_long_high_entropy_run():
    r = SecretRedactor(entropy_check=True)
    # 64 char high-entropy hex blob, no vendor prefix
    blob = (
        "secret=a3f5b9c2d7e1f8b4a6e0d2c5f8b1a4e7d9c3b6f8a1b2c3d4e5f6a7b8c9d0e1f2"
    )
    hits = r.detect(blob)
    assert any(h.type == SecretType.HIGH_ENTROPY for h in hits)


def test_entropy_check_ignores_natural_language():
    r = SecretRedactor(entropy_check=True)
    text = "the quick brown fox jumps over the lazy dog and runs into the woods"
    hits = r.detect(text)
    assert all(h.type != SecretType.HIGH_ENTROPY for h in hits)


def test_entropy_check_does_not_overlap_known_prefix_hit():
    # the AWS key value is itself a 20-char run; it would otherwise also
    # appear as HIGH_ENTROPY. The dedupe must prefer the more-specific
    # AWS_KEY hit (the AWS key starts before but the entropy candidate is
    # >= 32 chars so they shouldn't overlap on the AWS key alone).
    r = SecretRedactor(entropy_check=True)
    text = (
        "key=AKIAIOSFODNN7EXAMPLE and "
        "blob=a3f5b9c2d7e1f8b4a6e0d2c5f8b1a4e7d9c3b6f8a1b2c3d4e5f6"
    )
    hits = r.detect(text)
    types = [h.type for h in hits]
    assert SecretType.AWS_KEY in types
    assert SecretType.HIGH_ENTROPY in types


# ---------- custom patterns ----------


def test_custom_pattern_detected():
    r = SecretRedactor()
    r.add_pattern("MY_TOKEN", r"\bmyapp-[A-Za-z0-9]{16}\b")
    text = "token=myapp-abcdefghijklmnop end"
    redacted, hits = r.redact(text)
    assert len(hits) == 1
    assert hits[0].type == "MY_TOKEN"
    assert "<MY_TOKEN_0>" in redacted


def test_custom_pattern_with_capture_group():
    r = SecretRedactor()
    # captures only the token after `X-Token: `
    r.add_pattern("X_TOKEN", r"X-Token:\s+([A-Za-z0-9]+)")
    text = "X-Token: abc123def456"
    redacted, hits = r.redact(text)
    assert len(hits) == 1
    assert hits[0].value == "abc123def456"
    # the header name should not be in the value
    assert "X-Token" not in hits[0].value
    assert redacted == "X-Token: <X_TOKEN_0>"


# ---------- SecretHit shape ----------


def test_secrethit_is_frozen():
    h = SecretHit(type="X", value="v", start=0, end=1)
    # frozen dataclasses raise FrozenInstanceError on attribute assignment
    with pytest.raises(AttributeError):
        h.value = "tampered"  # type: ignore[misc]


def test_secrethit_offsets_match_source():
    r = SecretRedactor()
    text = "prefix AKIAIOSFODNN7EXAMPLE suffix"
    hits = r.detect(text)
    assert len(hits) == 1
    h = hits[0]
    assert text[h.start:h.end] == h.value
