"""Regression tests for the score → action mapping and the file dedup key.

This suite pins three behavioural contracts that earlier regressions
had silently broken — the rationale is captured here so future
maintainers know what each test guards against:

* :func:`microsoft_defender_intel_synchronizer_connector.utils.get_action` —
  ``score == 0`` (or a missing ``x_opencti_score``) must fall back to the
  safe ``"Audit"`` action and NEVER produce ``"Allowed"`` automatically,
  otherwise un-scored observables would silently allow-list IOCs in
  Defender. The override / default-action precedence chain is also pinned.
* :func:`microsoft_defender_intel_synchronizer_connector.utils.defender_file_dedup_key`
  derives a ``(indicatorType, hash_value)`` dedup key from a STIX file
  observable so multiple OpenCTI indicators sharing the same hash do not
  produce duplicate Defender entries (and accelerate hitting the 15k tenant
  quota). The helper must:
  - prefer SHA-256 over SHA-1;
  - ignore MD5 (the Defender Indicators API rejects ``FileMd5``);
  - return :data:`None` when no usable hash is present so the caller can
    fall back to the ``externalId`` path.
* :func:`microsoft_defender_intel_synchronizer_connector.config_variables.ConfigConnector._parse_taxii_collections`
  must not crash startup on a non-numeric ``expire_time`` /
  ``max_indicators`` override; the offending key is dropped (so the
  connector default takes over) and a warning is logged.
"""

import logging

import pytest
from microsoft_defender_intel_synchronizer_connector.config_variables import (
    ConfigConnector,
)
from microsoft_defender_intel_synchronizer_connector.utils import (
    defender_certificate_dedup_key,
    defender_file_dedup_key,
    get_action,
)


class TestGetActionScoreMapping:
    """Score-based action precedence and safe defaults."""

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (95, "Block"),
            (60, "Block"),
            (59, "Warn"),
            (45, "Warn"),
            (31, "Warn"),
            (30, "Audit"),
            (29, "Audit"),
            (1, "Audit"),
            (0, "Audit"),
        ],
    )
    def test_score_to_action_mapping_falls_back_to_audit(self, score, expected):
        assert get_action({"x_opencti_score": score}) == expected

    def test_missing_score_does_not_unintentionally_allow_list(self):
        # An observable imported without ``x_opencti_score`` (e.g. a feed
        # that does not score its IOCs) must NOT be quietly allow-listed
        # in Defender. The defensive default is ``Audit``.
        assert get_action({}) == "Audit"
        assert get_action({"x_opencti_score": None}) == "Audit"
        assert get_action({"x_opencti_score": "not-a-number"}) == "Audit"

    def test_per_observable_override_wins_over_score(self):
        # ``__policy_action`` is the per-collection override carried on
        # the observable; it MUST take precedence over the score mapping
        # so a high-score observable in an audit-only collection stays
        # an Audit indicator in Defender.
        assert (
            get_action({"x_opencti_score": 95, "__policy_action": "Audit"}) == "Audit"
        )

    def test_default_action_wins_over_score_when_no_override(self):
        # The connector-level ``MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_DEFAULT_ACTION``
        # value is applied when there is no per-observable override.
        assert get_action({"x_opencti_score": 95}, default_action="Warn") == "Warn"

    def test_override_wins_over_default_action(self):
        assert (
            get_action(
                {"x_opencti_score": 95, "__policy_action": "Block"},
                default_action="Warn",
            )
            == "Block"
        )


class TestDefenderFileDedupKey:
    """Hash priority + MD5 rejection contract for the file dedup key."""

    def test_no_hashes_returns_none(self):
        assert defender_file_dedup_key({"type": "file"}) is None
        assert defender_file_dedup_key({"type": "file", "hashes": None}) is None
        assert defender_file_dedup_key({"type": "file", "hashes": {}}) is None

    def test_sha256_is_preferred_over_sha1(self):
        observable = {
            "type": "file",
            "hashes": {
                "SHA-1": "1111111111111111111111111111111111111111",
                "SHA-256": (
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
            },
        }
        assert defender_file_dedup_key(observable) == (
            "FileSha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )

    def test_sha1_used_when_sha256_missing(self):
        observable = {
            "type": "file",
            "hashes": {"SHA-1": "1111111111111111111111111111111111111111"},
        }
        assert defender_file_dedup_key(observable) == (
            "FileSha1",
            "1111111111111111111111111111111111111111",
        )

    def test_md5_is_ignored(self):
        # Defender rejects ``FileMd5`` create requests, so an MD5-only
        # observable must NOT produce a dedup key — the caller falls
        # back to the externalId fast-path.
        observable = {
            "type": "file",
            "hashes": {"MD5": "ffffffffffffffffffffffffffffffff"},
        }
        assert defender_file_dedup_key(observable) is None

    @pytest.mark.parametrize(
        "algo_key",
        ["sha-256", "Sha-256", "SHA256", "sha256"],
    )
    def test_hash_algorithm_label_is_case_insensitive(self, algo_key):
        observable = {
            "type": "file",
            "hashes": {
                algo_key: (
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
            },
        }
        assert defender_file_dedup_key(observable) == (
            "FileSha256",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )

    def test_empty_hash_value_is_skipped(self):
        # A blank SHA-256 value must not produce a dedup key — fall
        # back to SHA-1 if present, otherwise ``None``.
        observable = {
            "type": "file",
            "hashes": {
                "SHA-256": "",
                "SHA-1": "1111111111111111111111111111111111111111",
            },
        }
        assert defender_file_dedup_key(observable) == (
            "FileSha1",
            "1111111111111111111111111111111111111111",
        )


class TestDefenderCertificateDedupKey:
    """``defender_certificate_dedup_key`` derives the thumbprint from ``hashes``.

    STIX ``x509-certificate`` observables carry the fingerprint in
    ``hashes`` rather than in ``value``. The previous planner code
    keyed off ``observable_data["value"]``, which was always empty
    for certificate observables — the result was that certificate
    indicators were silently dropped from the planning pass and
    never staged for create. This test class pins the new helper so
    a regression cannot reintroduce that behaviour.

    The helper must use the same hash preference (``sha1`` first,
    then ``sha256``, then ``md5``) as ``api_handler._build_request_body``,
    otherwise the planner and the POST builder would pick different
    thumbprints and Defender would treat them as two different
    indicators.
    """

    def test_prefers_sha1_over_sha256(self):
        observable = {
            "type": "x509-certificate",
            "hashes": {
                "SHA-1": "1111111111111111111111111111111111111111",
                "SHA-256": (
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
            },
        }
        assert defender_certificate_dedup_key(observable) == (
            "CertificateThumbprint",
            "1111111111111111111111111111111111111111",
        )

    def test_falls_back_to_sha256_when_sha1_missing(self):
        observable = {
            "type": "x509-certificate",
            "hashes": {
                "SHA-256": (
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
            },
        }
        assert defender_certificate_dedup_key(observable) == (
            "CertificateThumbprint",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )

    def test_falls_back_to_md5_when_no_better_hash(self):
        # Certificates can be keyed on MD5 in legacy environments,
        # so the helper accepts it as the final fallback.
        observable = {
            "type": "x509-certificate",
            "hashes": {"MD5": "ffffffffffffffffffffffffffffffff"},
        }
        assert defender_certificate_dedup_key(observable) == (
            "CertificateThumbprint",
            "ffffffffffffffffffffffffffffffff",
        )

    def test_no_hashes_returns_none(self):
        # When the observable carries no usable hash the planner falls
        # back to the ``externalId`` fast-path — the helper signals
        # that with ``None``.
        assert defender_certificate_dedup_key({"type": "x509-certificate"}) is None
        assert (
            defender_certificate_dedup_key({"type": "x509-certificate", "hashes": {}})
            is None
        )
        assert (
            defender_certificate_dedup_key(
                {"type": "x509-certificate", "hashes": "not-a-dict"}
            )
            is None
        )

    @pytest.mark.parametrize(
        "algo_key",
        ["sha-1", "Sha-1", "SHA1", "sha1"],
    )
    def test_hash_algorithm_label_is_case_insensitive(self, algo_key):
        observable = {
            "type": "x509-certificate",
            "hashes": {
                algo_key: "1111111111111111111111111111111111111111",
            },
        }
        assert defender_certificate_dedup_key(observable) == (
            "CertificateThumbprint",
            "1111111111111111111111111111111111111111",
        )


class TestNormalizePolicyInvalidIntegers:
    """``_parse_taxii_collections`` must not crash on bad per-collection ints."""

    def test_non_numeric_expire_time_is_dropped_with_warning(self, caplog):
        raw = {"col-a": {"expire_time": "forever", "action": "Audit"}}
        with caplog.at_level(logging.WARNING):
            order, overrides = ConfigConnector._parse_taxii_collections(raw)
        assert order == ["col-a"]
        # The offending key was dropped so the connector-level default
        # takes over downstream; the rest of the policy is preserved.
        assert "expire_time" not in overrides["col-a"]
        assert overrides["col-a"].get("action") == "Audit"
        assert any("expire_time" in rec.message for rec in caplog.records)

    def test_non_numeric_max_indicators_is_dropped_with_warning(self, caplog):
        raw = {"col-b": {"max_indicators": "unlimited"}}
        with caplog.at_level(logging.WARNING):
            order, overrides = ConfigConnector._parse_taxii_collections(raw)
        assert order == ["col-b"]
        assert "max_indicators" not in overrides["col-b"]
        assert any("max_indicators" in rec.message for rec in caplog.records)

    def test_max_indicators_is_clamped_to_valid_range(self):
        raw = {"big": {"max_indicators": 99999}, "small": {"max_indicators": 0}}
        _, overrides = ConfigConnector._parse_taxii_collections(raw)
        assert overrides["big"]["max_indicators"] == 15000
        assert overrides["small"]["max_indicators"] == 1
