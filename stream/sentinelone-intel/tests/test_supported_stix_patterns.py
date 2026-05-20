"""Regression tests for ``SUPPORTED_STIX_PATTERNS`` in ``client.py``.

Pins the file-hash filter contract tracked by issue #5428:

* The connector must accept every shape OpenCTI is known to emit for
  file-hash indicators — STIX 2.1 canonical (``SHA-256``), single-
  quoted algorithm (``'SHA-256'``), lower-case (``sha-256``), the
  legacy non-hyphenated form (``SHA256``) — because SentinelOne
  itself accepts every variant on the wire.
* The connector must continue to reject hash algorithms it cannot
  push (``SHA-512``), patterns with unbalanced algorithm quotes
  (e.g. ``[file:hashes.'SHA-256 = ...]``), non-file STIX object
  types in the file-hash branch, and malformed patterns.
* The other supported branches (``domain-name``, ``url``,
  ``ipv4-addr``) remain case-sensitive — STIX object type names are
  lower-case-only per spec, and matching ``IPV4-ADDR`` would mask a
  malformed upstream payload.
"""

import pytest
from sentinelone_services.client import SUPPORTED_STIX_PATTERNS


def _is_supported(pattern: str) -> bool:
    """Mirror ``SentinelOneClient._is_valid_pattern`` semantics."""
    return any(rx.match(pattern) for rx in SUPPORTED_STIX_PATTERNS)


# Every file-hash shape OpenCTI is known to emit and SentinelOne accepts.
_FILE_HASH_ACCEPTED = [
    # STIX 2.1 canonical form:
    "[file:hashes.SHA-256 = 'aa']",
    "[file:hashes.SHA-1 = 'aa']",
    "[file:hashes.MD5 = 'aa']",
    # Single-quoted algorithm name (emitted when the algorithm key is
    # not a valid ``hash-algorithm-ov`` literal in STIX 2.1):
    "[file:hashes.'SHA-256' = 'aa']",
    "[file:hashes.'SHA-1' = 'aa']",
    "[file:hashes.'md5' = 'aa']",
    "[file:hashes.'sha-256' = 'aa']",
    "[file:hashes.'sha-1' = 'aa']",
    # Lower-case unquoted (also emitted by OpenCTI):
    "[file:hashes.sha256 = 'aa']",
    "[file:hashes.sha1 = 'aa']",
    "[file:hashes.md5 = 'aa']",
    # Legacy non-hyphenated form — what the previous (buggy) regex
    # actually matched. Kept so an upstream regression to the legacy
    # form does not silently drop indicators.
    "[file:hashes.SHA256 = 'aa']",
    "[file:hashes.SHA1 = 'aa']",
    # Padding-whitespace tolerance (matches the existing ``\s*`` slop):
    "  [file:hashes.SHA-256 = 'aa']  ",
    "[file:hashes.SHA-256   =   'aa']",
]


# Patterns the file-hash branch must reject.
_FILE_HASH_REJECTED = [
    # SHA-512 is not in SentinelOne's supported list:
    "[file:hashes.SHA-512 = 'aa']",
    "[file:hashes.'SHA-512' = 'aa']",
    "[file:hashes.sha512 = 'aa']",
    # Unbalanced algorithm-name quotes — the regex must not accept a
    # mix of quoted-open and unquoted-close (or vice-versa). The
    # backreference in the file-hash pattern is what enforces this;
    # an earlier shape used independent ``'?`` quantifiers and would
    # silently swallow these malformed payloads.
    "[file:hashes.'SHA-256 = 'aa']",
    "[file:hashes.SHA-256' = 'aa']",
    "[file:hashes.'sha-1 = 'aa']",
    "[file:hashes.md5' = 'aa']",
    # Malformed (no value quotes):
    "[file:hashes.SHA-256 = aa]",
    # Wrong operator:
    "[file:hashes.SHA-256 == 'aa']",
    # Bare junk:
    "garbage",
    "",
]


@pytest.mark.parametrize("pattern", _FILE_HASH_ACCEPTED)
def test_file_hash_shapes_are_accepted(pattern):
    """Every shape OpenCTI emits for file-hash indicators must match."""
    assert _is_supported(pattern), pattern


@pytest.mark.parametrize("pattern", _FILE_HASH_REJECTED)
def test_unsupported_or_malformed_patterns_are_rejected(pattern):
    """Patterns outside the documented support matrix must be dropped."""
    assert not _is_supported(pattern), pattern


@pytest.mark.parametrize(
    "pattern",
    [
        "[domain-name:value = 'evil.example.com']",
        "[url:value = 'http://evil.example.com/x']",
        "[ipv4-addr:value = '203.0.113.1']",
    ],
)
def test_non_hash_branches_still_match(pattern):
    """Domain / URL / IPv4 patterns must still be accepted unchanged."""
    assert _is_supported(pattern), pattern


@pytest.mark.parametrize(
    "pattern",
    [
        # STIX object type names are lower-case-only per spec; the
        # other three branches must stay case-sensitive so a malformed
        # upstream payload is not silently accepted.
        "[DOMAIN-NAME:value = 'evil.example.com']",
        "[URL:value = 'http://x/']",
        "[IPV4-ADDR:value = '1.2.3.4']",
        # Compound / multi-element patterns must be rejected — only
        # the file-hash branch's algorithm token is case-insensitive,
        # not the whole pattern.
        "[file:hashes.SHA-256 = 'aa'] AND [file:size = 1]",
    ],
)
def test_other_object_types_stay_case_sensitive(pattern):
    """Only the algorithm token in the file-hash branch is case-insensitive."""
    assert not _is_supported(pattern), pattern
