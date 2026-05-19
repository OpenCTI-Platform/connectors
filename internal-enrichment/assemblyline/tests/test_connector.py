"""Unit tests for the OpenCTI AssemblyLine connector.

These tests exercise the actual connector implementation. We bypass
``AssemblyLineConnector.__init__`` (which would try to connect to
OpenCTI and AssemblyLine) by constructing an instance via
``object.__new__`` and pinning only the attributes the method under
test reads. This keeps the tests fast and dependency-free while
still calling the real production code.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from main import AssemblyLineConnector, _coerce_bool  # noqa: E402


def _make_connector(**overrides: Any) -> AssemblyLineConnector:
    """Return a connector instance with a mocked helper and sane defaults."""
    connector = AssemblyLineConnector.__new__(AssemblyLineConnector)
    connector.helper = MagicMock()
    connector.assemblyline_url = "https://al.example.com"
    connector.assemblyline_user = "user"
    connector.assemblyline_apikey = "apikey"
    connector.assemblyline_verify_ssl = True
    connector.assemblyline_submission_profile = "static_with_dynamic"
    connector.assemblyline_classification = "TLP:C"
    connector.assemblyline_timeout = 600
    connector.assemblyline_force_resubmit = False
    connector.assemblyline_max_file_size_mb = 1
    connector.assemblyline_include_suspicious = False
    connector.assemblyline_create_attack_patterns = True
    connector.assemblyline_create_malware_analysis = True
    connector.assemblyline_create_observables = True
    connector.assemblyline_sequential_mode = False
    connector.assemblyline_poll_interval = 0
    connector.assemblyline_max_tlp = "TLP:AMBER"
    connector.opencti_url = "https://opencti.example.com"
    connector.opencti_token = "token"
    connector.assemblyline_author = "identity--abc"
    connector.assemblyline_identity_standard_id = "identity--abc"
    connector.al_client = MagicMock()
    for key, value in overrides.items():
        setattr(connector, key, value)
    return connector


class TestCoerceBool:
    """Boolean coercion for environment-variable config values."""

    @pytest.mark.parametrize(
        "value, default, expected",
        [
            (True, False, True),
            (False, True, False),
            (1, False, True),
            (0, True, False),
            ("true", False, True),
            ("TRUE", False, True),
            ("False", True, False),
            ("0", True, False),
            ("1", False, True),
            ("yes", False, True),
            ("no", True, False),
            ("on", False, True),
            ("off", True, False),
            ("", True, True),
            ("bogus", False, False),
            (None, True, True),
        ],
    )
    def test_coerce_bool(self, value: Any, default: bool, expected: bool) -> None:
        assert _coerce_bool(value, default=default) is expected


class TestMaliciousIOCExtraction:
    """Tests for malicious IOC extraction from AssemblyLine tags."""

    @pytest.fixture
    def sample_tags(self) -> Dict[str, Any]:
        return {
            "ioc": {
                "network.dynamic.domain": [
                    ["malware.com", "malicious", False, "TLP:C"],
                    ["safe.com", "info", False, "TLP:C"],
                    ["suspicious.net", "suspicious", False, "TLP:C"],
                ],
                "network.dynamic.ip": [
                    ["192.168.1.100", "malicious", False, "TLP:C"],
                    ["2001:db8::1", "malicious", False, "TLP:C"],
                    ["10.0.0.1", "info", False, "TLP:C"],
                ],
                "network.dynamic.uri": [
                    ["http://evil.com/malware.exe", "malicious", False, "TLP:C"]
                ],
            },
            "attribution": {
                "attribution.family": [
                    ["EMOTET", "malicious", False, "TLP:C"],
                    ["EMOTET", "malicious", False, "TLP:C"],  # duplicate
                ]
            },
        }

    def test_extract_only_malicious_by_default(
        self, sample_tags: Dict[str, Any]
    ) -> None:
        connector = _make_connector(assemblyline_include_suspicious=False)
        iocs = connector._extract_malicious_iocs(sample_tags)
        assert iocs["domains"] == ["malware.com"]
        assert iocs["ips"] == ["192.168.1.100", "2001:db8::1"]
        assert iocs["urls"] == ["http://evil.com/malware.exe"]
        assert iocs["families"] == ["EMOTET"]

    def test_include_suspicious(self, sample_tags: Dict[str, Any]) -> None:
        connector = _make_connector(assemblyline_include_suspicious=True)
        iocs = connector._extract_malicious_iocs(sample_tags)
        assert iocs["domains"] == ["malware.com", "suspicious.net"]

    def test_empty_tags(self) -> None:
        connector = _make_connector()
        assert connector._extract_malicious_iocs(None) == {
            "domains": [],
            "ips": [],
            "urls": [],
            "families": [],
        }
        assert connector._extract_malicious_iocs({}) == {
            "domains": [],
            "ips": [],
            "urls": [],
            "families": [],
        }

    def test_dedup_within_category(self, sample_tags: Dict[str, Any]) -> None:
        connector = _make_connector()
        iocs = connector._extract_malicious_iocs(sample_tags)
        assert iocs["families"].count("EMOTET") == 1


class TestScoreConversion:
    """``_score_to_result_name`` covers the AL → STIX vocabulary mapping."""

    @pytest.mark.parametrize(
        "score, expected",
        [
            (2000, "malicious"),
            (500, "malicious"),
            (499, "suspicious"),
            (100, "suspicious"),
            (99, "unknown"),
            (1, "unknown"),
            (0, "benign"),
            (-1, "benign"),
        ],
    )
    def test_score_buckets(self, score: int, expected: str) -> None:
        assert AssemblyLineConnector._score_to_result_name(score) == expected


class TestStixPatternEscaping:
    """STIX-pattern escaping must handle quotes *and* backslashes."""

    def test_escape_single_quote(self) -> None:
        assert (
            AssemblyLineConnector._escape_stix_string("path?param='value'")
            == "path?param=\\'value\\'"
        )

    def test_escape_backslash(self) -> None:
        assert AssemblyLineConnector._escape_stix_string("file\\path") == "file\\\\path"

    def test_escape_quote_and_backslash(self) -> None:
        assert AssemblyLineConnector._escape_stix_string("a\\b'c") == "a\\\\b\\'c"

    def test_url_indicator_pattern_uses_escape(self) -> None:
        """Indicators built by the connector use the escaped value."""
        connector = _make_connector()
        connector.helper.api.indicator.create = MagicMock(return_value={"id": "ind-1"})
        connector.helper.api.stix_core_relationship.create = MagicMock()
        connector.helper.api.stix_cyber_observable.create = MagicMock(
            return_value={"id": "obs-1"}
        )
        connector.helper.api.stix_cyber_observable.add_label = MagicMock()
        connector.helper.api.stix2.format_date = MagicMock(return_value="2024-01-01")

        connector._create_indicator_observable(
            observable_id="obs-root",
            ioc_value="http://evil.com/a\\b?param='x'",
            stix_observable_type="url",
            opencti_observable_type="Url",
            max_score=900,
            description="URL contacted during malware analysis",
        )
        call_kwargs = connector.helper.api.indicator.create.call_args.kwargs
        assert "\\\\b" in call_kwargs["pattern"]
        assert "\\'x\\'" in call_kwargs["pattern"]


class TestIPVersionDispatch:
    """IPv6 IOCs must produce the right STIX type."""

    @pytest.mark.parametrize(
        "value, ipv6",
        [
            ("192.168.1.100", False),
            ("10.0.0.1", False),
            ("2001:db8::1", True),
            ("::1", True),
        ],
    )
    def test_is_ipv6(self, value: str, ipv6: bool) -> None:
        assert AssemblyLineConnector._is_ipv6(value) is ipv6


class TestAttackPatterns:
    """ATT&CK phase names must keep the official hyphenated form."""

    def test_phase_name_keeps_hyphens(self) -> None:
        connector = _make_connector()
        results = {
            "attack_matrix": {
                "defense-evasion": [
                    ["T1027", "Obfuscated Files or Information", "malicious"],
                ],
                "initial-access": [
                    ["T1566.001", "Spearphishing Attachment", "malicious"],
                ],
            }
        }
        patterns = connector._extract_attack_patterns(results)
        assert len(patterns) == 2
        phases = {p["kill_chain_phase"] for p in patterns}
        assert phases == {"defense-evasion", "initial-access"}

    def test_empty_attack_matrix(self) -> None:
        connector = _make_connector()
        assert connector._extract_attack_patterns({}) == []
        assert connector._extract_attack_patterns({"attack_matrix": {}}) == []
        assert connector._extract_attack_patterns(None) == []


class TestTlpGate:
    """The TLP gate must block over-restricted observables."""

    def test_allows_within_max(self) -> None:
        connector = _make_connector(assemblyline_max_tlp="TLP:AMBER")
        observable = {
            "objectMarking": [
                {"definition_type": "TLP", "definition": "TLP:GREEN"},
            ]
        }
        connector._check_tlp(observable)  # should not raise

    def test_blocks_above_max(self) -> None:
        connector = _make_connector(assemblyline_max_tlp="TLP:AMBER")
        observable = {
            "objectMarking": [
                {"definition_type": "TLP", "definition": "TLP:RED"},
            ]
        }
        with pytest.raises(ValueError):
            connector._check_tlp(observable)

    def test_default_clear_when_no_marking(self) -> None:
        connector = _make_connector(assemblyline_max_tlp="TLP:CLEAR")
        connector._check_tlp({"objectMarking": []})  # should not raise


class TestSafeObservableRef:
    """Error logs must never embed the full observable payload."""

    def test_minimal_reference(self) -> None:
        connector = _make_connector()
        ref = connector._safe_observable_ref(
            {
                "id": "artifact--abc",
                "entity_type": "Artifact",
                "payload_bin": "SECRET",
            }
        )
        assert "SECRET" not in ref
        assert "artifact--abc" in ref
        assert "Artifact" in ref


class TestExternalReference:
    """The external reference must be attached to the enriched observable."""

    def test_attach_external_reference(self) -> None:
        connector = _make_connector()
        connector.helper.api.external_reference.create = MagicMock(
            return_value={"id": "ref-1"}
        )
        connector.helper.api.stix_cyber_observable.add_external_reference = MagicMock()
        connector._attach_external_reference("obs-1", "sid-123", 1500)
        connector.helper.api.external_reference.create.assert_called_once()
        connector.helper.api.stix_cyber_observable.add_external_reference.assert_called_once_with(
            id="obs-1", external_reference_id="ref-1"
        )


class TestSequentialModeDeadline:
    """Sequential-mode wait must honour ``ASSEMBLYLINE_TIMEOUT``."""

    def test_returns_immediately_when_disabled(self) -> None:
        connector = _make_connector(assemblyline_sequential_mode=False)
        connector._wait_for_al_ready(deadline=0)  # should not raise

    def test_returns_when_idle(self) -> None:
        connector = _make_connector(assemblyline_sequential_mode=True)
        connector.al_client.search.submission = MagicMock(return_value={"total": 0})
        import time

        connector._wait_for_al_ready(deadline=time.monotonic() + 30)

    def test_raises_on_deadline(self) -> None:
        connector = _make_connector(
            assemblyline_sequential_mode=True, assemblyline_poll_interval=0
        )
        connector.al_client.search.submission = MagicMock(return_value={"total": 5})
        import time

        with pytest.raises(Exception, match="Timed out"):
            connector._wait_for_al_ready(deadline=time.monotonic() - 1)


class TestIndicatorsRespectCreateObservablesFlag:
    """When ``create_observables`` is False, no observables / based-on links emerge."""

    def _setup(self, *, create_observables: bool) -> AssemblyLineConnector:
        connector = _make_connector(assemblyline_create_observables=create_observables)
        connector.helper.api.indicator.create = MagicMock(return_value={"id": "ind-1"})
        connector.helper.api.stix_core_relationship.create = MagicMock()
        connector.helper.api.stix_cyber_observable.create = MagicMock(
            return_value={"id": "obs-1"}
        )
        connector.helper.api.stix_cyber_observable.add_label = MagicMock()
        connector.helper.api.malware.create = MagicMock(return_value={"id": "mal-1"})
        connector.helper.api.stix2.format_date = MagicMock(return_value="2024-01-01")
        return connector

    def test_create_observables_false(self) -> None:
        connector = self._setup(create_observables=False)
        counts, indicator_ids = connector._create_indicators(
            "obs-root",
            900,
            {
                "domains": ["evil.com"],
                "ips": [],
                "urls": [],
                "families": [],
            },
        )
        connector.helper.api.stix_cyber_observable.create.assert_not_called()
        assert counts["observables"] == 0
        assert counts["indicators"] == 1
        assert indicator_ids == ["ind-1"]

    def test_create_observables_true(self) -> None:
        connector = self._setup(create_observables=True)
        counts, _ = connector._create_indicators(
            "obs-root",
            900,
            {
                "domains": ["evil.com"],
                "ips": [],
                "urls": [],
                "families": [],
            },
        )
        connector.helper.api.stix_cyber_observable.create.assert_called_once()
        assert counts["observables"] == 1
        assert counts["indicators"] == 1


class TestMalwareFamilyHasNoTrojanLabel:
    """Malware families must not be hard-coded to the ``trojan`` label."""

    def test_no_hardcoded_label(self) -> None:
        connector = _make_connector()
        connector.helper.api.malware.create = MagicMock(return_value={"id": "mal-1"})
        connector.helper.api.indicator.create = MagicMock(return_value={"id": "ind"})
        connector.helper.api.stix_core_relationship.create = MagicMock()

        connector._create_indicators(
            "obs-root",
            500,
            {"domains": [], "ips": [], "urls": [], "families": ["EMOTET"]},
        )
        call_kwargs = connector.helper.api.malware.create.call_args.kwargs
        # No "labels" kwarg is fine; if one is present it must not contain "trojan"
        labels = call_kwargs.get("labels") or []
        assert "trojan" not in [str(label).lower() for label in labels]


class TestAttackPatternRelationship:
    """ATT&CK patterns link to indicators with ``related-to``."""

    def test_links_attack_pattern_to_indicators(self) -> None:
        connector = _make_connector()
        attack_patterns = [
            {
                "technique_id": "T1027",
                "technique_name": "Obfuscated Files or Information",
                "tactic": "defense-evasion",
                "confidence": "malicious",
                "kill_chain_phase": "defense-evasion",
            }
        ]
        connector.helper.api.attack_pattern.create = MagicMock(
            return_value={"id": "ap-1"}
        )
        ids = connector._create_attack_patterns(attack_patterns)
        assert ids == ["ap-1"]
        create_kwargs = connector.helper.api.attack_pattern.create.call_args.kwargs
        assert create_kwargs["kill_chain_phases"] == [
            {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
        ]


class TestParseAlTimestamp:
    """Defensive parsing of AssemblyLine timestamps."""

    def test_parse_iso8601_with_microseconds(self) -> None:
        connector = _make_connector()
        import datetime as _dt

        fallback = _dt.datetime(1970, 1, 1)
        parsed = connector._parse_al_timestamp("2024-05-04T10:11:12.345Z", fallback)
        assert parsed == _dt.datetime(2024, 5, 4, 10, 11, 12, 345000)

    def test_parse_iso8601_without_microseconds(self) -> None:
        connector = _make_connector()
        import datetime as _dt

        fallback = _dt.datetime(1970, 1, 1)
        parsed = connector._parse_al_timestamp("2024-05-04T10:11:12", fallback)
        assert parsed == _dt.datetime(2024, 5, 4, 10, 11, 12)

    def test_invalid_falls_back(self) -> None:
        connector = _make_connector()
        import datetime as _dt

        fallback = _dt.datetime(1970, 1, 1)
        assert connector._parse_al_timestamp("not a date", fallback) == fallback
        assert connector._parse_al_timestamp(None, fallback) == fallback
        assert connector._parse_al_timestamp(12345, fallback) == fallback


class TestUnsupportedEntityType:
    """``_process_message`` short-circuits unsupported entity types."""

    def test_skip_indicator(self) -> None:
        connector = _make_connector()
        result = connector._process_message(
            {"enrichment_entity": {"entity_type": "Indicator", "id": "ind"}}
        )
        assert "not supported" in result


class TestUnpinnedFileFetch:
    """``_fetch_attached_file`` must hit the canonical ``/storage/get/`` URL."""

    def test_uses_storage_url(self) -> None:
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"data")
        connector._fetch_attached_file("file-123")
        connector.helper.api.fetch_opencti_file.assert_called_once_with(
            "https://opencti.example.com/storage/get/file-123", binary=True
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
