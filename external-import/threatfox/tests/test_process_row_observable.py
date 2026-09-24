"""Tests for ThreatFox.process_row_observable() and process_row_malware().

process_row_observable() only touches self.identity_id, self.create_indicators,
self._score_override_by_type/default_x_opencti_score (via _resolve_score(), see
test_score_resolution.py) and self.helper's logging calls -- none of which
require a live OpenCTI instance -- so these tests build a bare ThreatFox
instance via __new__() instead of going through __init__ (which does talk to a
live OpenCTI instance).
"""

from unittest.mock import MagicMock

import pytest
from src.__main__ import FeedRow, ThreatFox


def _row(
    ioc_type: str,
    value: str,
    confidence_level: int = 75,
    reference: str = "None",
    threat_type: str = "botnet_cc",
    fk_malware: str = "win.example_malware",
    malware_aliases: str = "ExampleAlias",
    malware_printable: str = "Example Malware",
) -> FeedRow:
    return FeedRow(
        (
            "2024-01-01 00:00:00",
            "12345",
            value,
            ioc_type,
            threat_type,
            fk_malware,
            malware_aliases,
            malware_printable,
            "",
            str(confidence_level),
            "false",
            reference,
            "None",
            "0",
            "abuse_ch",
        )
    )


def _connector(create_indicators: bool = False, score_overrides=None) -> ThreatFox:
    connector = ThreatFox.__new__(ThreatFox)
    connector.identity_id = "identity--d7f1c1a0-0000-4000-8000-000000000000"
    connector.create_indicators = create_indicators
    connector.default_x_opencti_score = 50
    connector._score_override_by_type = score_overrides or {
        "ip:port": None,
        "domain": None,
        "url": None,
        "md5_hash": None,
        "sha1_hash": None,
        "sha256_hash": None,
    }
    connector.helper = MagicMock()
    return connector


@pytest.mark.parametrize(
    "ioc_type,value,expected_observable_type,expected_hash_field",
    [
        ("ip:port", "1.2.3.4:8080", "IPv4-Addr", None),
        ("domain", "bad.example.com", "Domain-Name", None),
        ("url", "http://bad.example.com/x", "Url", None),
        ("md5_hash", "d41d8cd98f00b204e9800998ecf8427e", "StixFile", "hashes.MD5"),
        (
            "sha1_hash",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "StixFile",
            "hashes.SHA-1",
        ),
        (
            "sha256_hash",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "StixFile",
            "hashes.SHA-256",
        ),
    ],
)
def test_process_row_observable_maps_score_onto_each_type(
    ioc_type, value, expected_observable_type, expected_hash_field
):
    connector = _connector()
    ioc = _row(ioc_type, value, confidence_level=77)

    stix_observable, stix_indicator, obs_metadata = connector.process_row_observable(
        ioc
    )

    assert obs_metadata["observable_type"] == expected_observable_type
    assert obs_metadata["hash_field"] == expected_hash_field
    assert stix_observable["x_opencti_score"] == 77
    assert stix_indicator is None


def test_process_row_observable_applies_type_override_to_observable_and_indicator():
    connector = _connector(
        create_indicators=True,
        score_overrides={
            "domain": 95,
            "ip:port": None,
            "url": None,
            "md5_hash": None,
            "sha1_hash": None,
            "sha256_hash": None,
        },
    )
    ioc = _row("domain", "bad.example.com", confidence_level=10)

    stix_observable, stix_indicator, _ = connector.process_row_observable(ioc)

    assert stix_observable["x_opencti_score"] == 95
    assert stix_indicator["x_opencti_score"] == 95
    assert stix_indicator["x_opencti_main_observable_type"] == "Domain-Name"


def test_process_row_observable_returns_none_for_unrecognized_type():
    connector = _connector()
    ioc = _row("unknown_type", "whatever")

    assert connector.process_row_observable(ioc) is None
    connector.helper.log_warning.assert_called_once()


def test_process_row_observable_no_indicator_when_disabled():
    connector = _connector(create_indicators=False)
    ioc = _row("url", "http://bad.example.com/x")

    _, stix_indicator, _ = connector.process_row_observable(ioc)

    assert stix_indicator is None


class TestProcessRowMalware:
    """Tests for ThreatFox.process_row_malware()."""

    def test_returns_none_without_a_family_name(self):
        connector = _connector()
        ioc = _row(
            "domain",
            "bad.example.com",
            fk_malware="unknown",
            malware_printable="Unknown malware",
            malware_aliases="None",
        )

        assert connector.process_row_malware(ioc) is None

    def test_builds_malware_with_aliases_and_botnet_type(self):
        connector = _connector()
        ioc = _row(
            "domain",
            "bad.example.com",
            threat_type="botnet_cc",
            fk_malware="win.example_malware",
            malware_aliases="ExampleAlias",
            malware_printable="Example Malware",
        )

        stix_malware = connector.process_row_malware(ioc)

        assert stix_malware["name"] == "Example Malware"
        assert "win.example_malware" in stix_malware["aliases"]
        assert stix_malware["malware_types"] == ["bot"]
        assert stix_malware["is_family"] is True

    def test_payload_delivery_maps_to_dropper(self):
        connector = _connector()
        ioc = _row(
            "domain",
            "bad.example.com",
            threat_type="payload_delivery",
            fk_malware="win.example_malware",
        )

        stix_malware = connector.process_row_malware(ioc)

        assert stix_malware["malware_types"] == ["dropper"]

    def test_unrecognized_threat_type_has_no_malware_types(self):
        connector = _connector()
        ioc = _row(
            "domain",
            "bad.example.com",
            threat_type="other",
            fk_malware="win.example_malware",
        )

        stix_malware = connector.process_row_malware(ioc)

        assert "malware_types" not in stix_malware
