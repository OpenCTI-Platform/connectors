"""Regression tests for the dedup key normalisation contract.

Pins the behaviour of the planner's ``key_from_def`` and
``key_from_candidate`` helpers (lifted from a nested ``run()`` scope
to module scope so they are testable in isolation):

* hash-based Defender indicator types (``FileSha1``, ``FileSha256``,
  ``FileMd5``, ``CertificateThumbprint``) MUST collapse to a
  case-insensitive value — otherwise a tenant that previously ran
  with an uppercase-emitting pipeline would have its Defender
  response come back as ``ABCDEF…`` while the connector now emits
  ``abcdef…``, the two would key to different buckets, and the
  planner would re-create a duplicate indicator on every sync cycle
  until the 15k tenant quota was burnt through;
* non-hash indicator types (``DomainName``, ``Url``, ``IpAddress``)
  must NOT be case-folded — those values are already canonicalised
  upstream by ``utils.indicator_value`` (hosts are lowered, URL
  paths are intentionally case-preserving) and a second
  ``.lower()`` here would silently break URL dedup;
* ``rbacGroupIds`` on the Defender side and ``rbac_scope_pair`` on
  the candidate side must collapse to the same sorted ``tuple[int]``
  shape so a scope key built from either side is comparable;
* missing / blank / non-coercible inputs collapse to the
  "tenant-wide" empty-tuple sentinel without raising.
"""

import pytest
from microsoft_defender_intel_synchronizer_connector.connector import (
    key_from_candidate,
    key_from_def,
)

_SHA256_LOWER = "a" * 64
_SHA256_UPPER = "A" * 64
_SHA1_LOWER = "b" * 40
_SHA1_UPPER = "B" * 40
_THUMBPRINT_LOWER = "c" * 40
_THUMBPRINT_UPPER = "C" * 40


class TestKeyFromDefHashCaseInsensitive:
    """Defender-side dedup key folds hash hex values to lower-case."""

    @pytest.mark.parametrize(
        ("indicator_type", "value"),
        [
            ("FileSha256", _SHA256_UPPER),
            ("FileSha1", _SHA1_UPPER),
            ("FileMd5", "F" * 32),
            ("CertificateThumbprint", _THUMBPRINT_UPPER),
        ],
    )
    def test_uppercase_hash_collapses_to_lowercase(self, indicator_type, value):
        defender_indicator = {
            "indicatorType": indicator_type,
            "indicatorValue": value,
            "rbacGroupIds": [],
        }
        key = key_from_def(defender_indicator)
        assert key == (indicator_type, value.lower(), ())

    def test_uppercase_and_lowercase_defender_indicators_share_a_key(self):
        upper = {
            "indicatorType": "FileSha256",
            "indicatorValue": _SHA256_UPPER,
            "rbacGroupIds": [],
        }
        lower = {
            "indicatorType": "FileSha256",
            "indicatorValue": _SHA256_LOWER,
            "rbacGroupIds": [],
        }
        assert key_from_def(upper) == key_from_def(lower)

    def test_surrounding_whitespace_is_stripped_for_hashes(self):
        # Defender has been observed round-tripping trailing whitespace
        # on indicator values in some tenants; the dedup key should not
        # see that as a different indicator.
        defender_indicator = {
            "indicatorType": "FileSha1",
            "indicatorValue": f"  {_SHA1_UPPER}  ",
            "rbacGroupIds": [],
        }
        key = key_from_def(defender_indicator)
        assert key == ("FileSha1", _SHA1_LOWER, ())


class TestKeyFromDefNonHashPreserved:
    """Non-hash Defender values keep their original casing."""

    @pytest.mark.parametrize(
        ("indicator_type", "value"),
        [
            ("DomainName", "Example.COM"),
            ("Url", "https://Example.COM/Path"),
            ("IpAddress", "192.0.2.1"),
        ],
    )
    def test_non_hash_value_is_not_case_folded(self, indicator_type, value):
        defender_indicator = {
            "indicatorType": indicator_type,
            "indicatorValue": value,
            "rbacGroupIds": [],
        }
        key = key_from_def(defender_indicator)
        # The value passes through verbatim — earlier normalisation
        # in ``utils.indicator_value`` is the canonical source of
        # truth for host / URL casing.
        assert key == (indicator_type, value, ())


class TestKeyFromDefScopeIdNormalisation:
    """``rbacGroupIds`` collapses to a sorted ``tuple[int, ...]``."""

    def test_unsorted_ids_collapse_to_sorted_tuple(self):
        defender_indicator = {
            "indicatorType": "FileSha256",
            "indicatorValue": _SHA256_LOWER,
            "rbacGroupIds": [3, 1, 2],
        }
        assert key_from_def(defender_indicator) == (
            "FileSha256",
            _SHA256_LOWER,
            (1, 2, 3),
        )

    def test_missing_ids_collapse_to_empty_tuple(self):
        for missing in ({}, {"rbacGroupIds": None}, {"rbacGroupIds": []}):
            defender_indicator = {
                "indicatorType": "FileSha256",
                "indicatorValue": _SHA256_LOWER,
                **missing,
            }
            assert key_from_def(defender_indicator)[2] == ()

    def test_non_coercible_ids_fall_back_to_empty_tuple(self):
        # A malformed Defender response with string ids must NOT
        # blow up the planner — the scope falls back to "tenant-wide"
        # so the indicator still participates in dedup at the
        # (type, value) layer.
        defender_indicator = {
            "indicatorType": "FileSha256",
            "indicatorValue": _SHA256_LOWER,
            "rbacGroupIds": ["not-a-number"],
        }
        assert key_from_def(defender_indicator)[2] == ()


class TestKeyFromCandidateMatchesKeyFromDef:
    """Candidate-side and Defender-side keys MUST be comparable."""

    def test_uppercase_candidate_matches_lowercase_def(self):
        # The planner emits lower-case hashes (see
        # ``_convert_indicator_to_observables`` and
        # ``defender_file_dedup_key`` in ``utils``), but historic
        # Defender state can carry upper-case values. The two sides
        # of the dedup must agree.
        defender_indicator = {
            "indicatorType": "FileSha256",
            "indicatorValue": _SHA256_UPPER,
            "rbacGroupIds": [],
        }
        candidate_key = key_from_candidate("FileSha256", _SHA256_LOWER, None)
        assert key_from_def(defender_indicator) == candidate_key

    def test_lowercase_candidate_matches_uppercase_def(self):
        # Symmetric: a lower-case Defender value matches an
        # upper-case candidate (defensive — the connector itself
        # always emits lower-case, but third-party tooling pushing
        # into the same tenant might not).
        defender_indicator = {
            "indicatorType": "CertificateThumbprint",
            "indicatorValue": _THUMBPRINT_LOWER,
            "rbacGroupIds": [],
        }
        candidate_key = key_from_candidate(
            "CertificateThumbprint", _THUMBPRINT_UPPER, None
        )
        assert key_from_def(defender_indicator) == candidate_key

    def test_non_hash_candidate_is_not_case_folded(self):
        candidate_key = key_from_candidate("Url", "https://Example.COM/x", None)
        assert candidate_key == ("Url", "https://Example.COM/x", ())


class TestKeyFromCandidateScope:
    """``rbac_scope_pair`` is normalised the same way as ``rbacGroupIds``."""

    def test_scope_pair_collapses_to_sorted_tuple(self):
        scope_pair = (["names", "ignored"], [5, 2, 9])
        key = key_from_candidate("FileSha256", _SHA256_LOWER, scope_pair)
        assert key == ("FileSha256", _SHA256_LOWER, (2, 5, 9))

    def test_none_scope_pair_collapses_to_empty_tuple(self):
        key = key_from_candidate("FileSha256", _SHA256_LOWER, None)
        assert key == ("FileSha256", _SHA256_LOWER, ())

    def test_non_coercible_scope_ids_fall_back_to_empty_tuple(self):
        scope_pair = ([], ["nan", 1])
        key = key_from_candidate("FileSha256", _SHA256_LOWER, scope_pair)
        assert key[2] == ()


class TestNonStringInputsCollapseSafely:
    """The helpers must not raise on missing / malformed inputs."""

    def test_missing_indicator_value_collapses_to_empty_string(self):
        defender_indicator = {
            "indicatorType": "FileSha256",
            "rbacGroupIds": [],
        }
        assert key_from_def(defender_indicator) == ("FileSha256", "", ())

    def test_non_string_indicator_value_collapses_to_empty_string(self):
        defender_indicator = {
            "indicatorType": "FileSha256",
            "indicatorValue": 12345,
            "rbacGroupIds": [],
        }
        assert key_from_def(defender_indicator) == ("FileSha256", "", ())
