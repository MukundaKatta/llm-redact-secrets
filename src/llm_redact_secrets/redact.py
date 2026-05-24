"""Core SecretRedactor implementation."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable

from .patterns import BUILTIN_PATTERNS, HIGH_ENTROPY_CANDIDATE
from .types import SecretHit, SecretType

# Minimum Shannon entropy (bits/char) for the entropy_check heuristic to
# mark a long alphanumeric run as HIGH_ENTROPY. 4.0 bits/char is roughly
# the lower bound for base64-encoded random data; natural language English
# sits well below this on long runs.
ENTROPY_THRESHOLD_BITS_PER_CHAR = 4.0


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of string s in bits per character."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class SecretRedactor:
    """Find and redact API keys, tokens, JWTs, and credentials in text.

    By default the redactor uses built-in patterns anchored on well-known
    vendor prefixes (AWS, OpenAI, Anthropic, GitHub, Stripe, Slack, Google,
    JWT, Bearer). False positives are rare because each pattern requires
    the vendor prefix.

    Set `entropy_check=True` to additionally flag long high-entropy strings
    as `HIGH_ENTROPY`. This catches unknown-vendor secrets but has a higher
    false positive rate, so it is off by default.

    Use `types=[...]` to restrict detection to a subset of `SecretType`.

    Use `add_pattern(name, regex)` to register custom patterns.
    """

    def __init__(
        self,
        types: Iterable[SecretType] | None = None,
        entropy_check: bool = False,
    ) -> None:
        allowed = set(types) if types is not None else None
        self._patterns: list[tuple[str, re.Pattern[str], int]] = [
            (str(t), pat, grp)
            for (t, pat, grp) in BUILTIN_PATTERNS
            if allowed is None or t in allowed
        ]
        self._custom_patterns: list[tuple[str, re.Pattern[str], int]] = []
        self._entropy_check = entropy_check
        # honor types= filter for HIGH_ENTROPY too: if the caller restricted
        # the set and HIGH_ENTROPY is not in it, suppress entropy detection.
        if allowed is not None and SecretType.HIGH_ENTROPY not in allowed:
            self._entropy_check = False

    # ---- public API ----

    def add_pattern(
        self,
        name: str,
        regex: str | re.Pattern[str],
        kind: str = "custom",
    ) -> None:
        """Register a custom pattern. `name` shows up as `SecretHit.type`.

        `regex` may be a string or a compiled pattern. If the regex defines
        a capture group, group 1 is treated as the secret value; otherwise
        the whole match is the secret. `kind` is currently informational.
        """
        # `kind` is reserved for future grouping; reference it so linters
        # don't flag the unused arg.
        _ = kind
        pat = re.compile(regex) if isinstance(regex, str) else regex
        grp = 1 if pat.groups >= 1 else 0
        self._custom_patterns.append((name, pat, grp))

    def detect(self, text: str) -> list[SecretHit]:
        """Return all detected secret hits in order of appearance.

        Overlapping hits are resolved by preferring the earlier start
        offset; ties go to the longer match. Non-mutating.
        """
        hits: list[SecretHit] = []
        for type_name, pat, grp in self._patterns + self._custom_patterns:
            for m in pat.finditer(text):
                value = m.group(grp)
                start = m.start(grp)
                end = m.end(grp)
                hits.append(
                    SecretHit(type=type_name, value=value, start=start, end=end)
                )
        if self._entropy_check:
            hits.extend(self._detect_high_entropy(text, hits))
        return self._dedupe_overlaps(hits)

    def has_secrets(self, text: str) -> bool:
        """Return True if at least one secret is detected. Non-destructive.

        Short-circuits on the first hit so it is cheaper than `detect` when
        you only need a yes/no answer.
        """
        for type_name, pat, grp in self._patterns + self._custom_patterns:
            _ = type_name
            _ = grp
            if pat.search(text) is not None:
                return True
        if self._entropy_check:
            for m in HIGH_ENTROPY_CANDIDATE.finditer(text):
                if _shannon_entropy(m.group(0)) >= ENTROPY_THRESHOLD_BITS_PER_CHAR:
                    return True
        return False

    def redact(self, text: str) -> tuple[str, list[SecretHit]]:
        """Replace each detected secret with a stable placeholder.

        Returns (redacted_text, hits). Placeholders are of the form
        `<TYPE_N>` where `N` is a per-(type, value) stable index, so the
        same secret appearing twice gets the same placeholder.
        """
        hits = self.detect(text)
        if not hits:
            return text, hits

        # stable index per (type, value)
        index_map: dict[tuple[str, str], int] = {}
        next_index: dict[str, int] = {}
        for h in hits:
            key = (h.type, h.value)
            if key not in index_map:
                idx = next_index.get(h.type, 0)
                index_map[key] = idx
                next_index[h.type] = idx + 1

        # walk hits in source order; build the new string
        out_parts: list[str] = []
        cursor = 0
        for h in hits:
            if h.start < cursor:
                # already covered by an earlier hit (defensive; dedupe
                # should have removed these). skip.
                continue
            out_parts.append(text[cursor:h.start])
            placeholder = f"<{h.type}_{index_map[(h.type, h.value)]}>"
            out_parts.append(placeholder)
            cursor = h.end
        out_parts.append(text[cursor:])
        return "".join(out_parts), hits

    def redact_safe(self, text: str) -> str:
        """Same as `redact`, but discards the hit list.

        Prefer this when the caller does not need to keep the raw secret
        values in memory. Reduces accidental retention of secrets in logs
        or local variables.
        """
        redacted, hits = self.redact(text)
        # drop strong references so the GC can free the SecretHit objects
        del hits
        return redacted

    # ---- internal ----

    def _detect_high_entropy(
        self, text: str, existing: list[SecretHit]
    ) -> list[SecretHit]:
        """Find high-entropy runs that don't overlap an existing hit."""
        out: list[SecretHit] = []
        for m in HIGH_ENTROPY_CANDIDATE.finditer(text):
            start, end = m.start(), m.end()
            value = m.group(0)
            # skip if overlapping with an existing strong-pattern hit
            if any(not (end <= h.start or start >= h.end) for h in existing):
                continue
            if _shannon_entropy(value) < ENTROPY_THRESHOLD_BITS_PER_CHAR:
                continue
            out.append(
                SecretHit(
                    type=str(SecretType.HIGH_ENTROPY),
                    value=value,
                    start=start,
                    end=end,
                )
            )
        return out

    def _dedupe_overlaps(self, hits: list[SecretHit]) -> list[SecretHit]:
        """Sort hits by start, drop later hits that overlap an earlier one.

        Ties on start go to the longer match (more specific). Equal-length
        ties keep the first-registered pattern (built-in beats custom).
        """
        if not hits:
            return hits
        # stable sort: by start asc, length desc
        ordered = sorted(hits, key=lambda h: (h.start, -(h.end - h.start)))
        result: list[SecretHit] = []
        cursor = -1
        for h in ordered:
            if h.start < cursor:
                continue
            result.append(h)
            cursor = h.end
        return result
