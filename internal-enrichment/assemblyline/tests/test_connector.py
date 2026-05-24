"""Unit tests for the OpenCTI AssemblyLine connector.

These tests exercise the actual connector implementation. We bypass
``AssemblyLineConnector.__init__`` (which would try to connect to
OpenCTI and AssemblyLine) by constructing an instance via
``object.__new__`` and pinning only the attributes the method under
test reads. This keeps the tests fast and dependency-free while
still calling the real production code.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import stix2  # noqa: E402
from main import (  # noqa: E402
    AssemblyLineConnector,
    AssemblyLineTerminalError,
    _coerce_bool,
)


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

    def test_malicious_extraction_never_mixes_in_suspicious(
        self, sample_tags: Dict[str, Any]
    ) -> None:
        """``_extract_malicious_iocs`` returns ONLY malicious IOCs.

        Pins the connector's classification contract: suspicious IOCs
        must never be silently mixed into the ``malicious_iocs`` bucket
        (and thus must never trigger the "label observable malicious"
        / ``score=80`` / ``result=malicious`` paths downstream), even
        when ``ASSEMBLYLINE_INCLUDE_SUSPICIOUS`` is enabled.
        """
        connector = _make_connector(assemblyline_include_suspicious=True)
        iocs = connector._extract_malicious_iocs(sample_tags)
        assert iocs["domains"] == ["malware.com"]
        assert "suspicious.net" not in iocs["domains"]

    def test_extract_suspicious_iocs_returns_suspicious_when_enabled(
        self, sample_tags: Dict[str, Any]
    ) -> None:
        connector = _make_connector(assemblyline_include_suspicious=True)
        iocs = connector._extract_suspicious_iocs(sample_tags)
        assert iocs["domains"] == ["suspicious.net"]
        # Suspicious bucket carries only suspicious IOCs.
        assert "malware.com" not in iocs["domains"]

    def test_extract_suspicious_iocs_empty_when_disabled(
        self, sample_tags: Dict[str, Any]
    ) -> None:
        """With the feature flag off, the suspicious bucket is empty.

        Lets callers iterate ``_extract_suspicious_iocs(...)``
        unconditionally without an extra feature-flag branch.
        """
        connector = _make_connector(assemblyline_include_suspicious=False)
        iocs = connector._extract_suspicious_iocs(sample_tags)
        assert iocs == {"domains": [], "ips": [], "urls": [], "families": []}

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
            {"id": "obs-root", "objectMarking": []},
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
            {"id": "obs-root", "objectMarking": []},
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


class TestApiIndicatorAndObservableInheritSourceMarkings:
    """API-created Indicators / Observables inherit the source observable's markings.

    The earlier review pass fixed marking inheritance for the STIX bundle
    (Malware-Analysis SDO and derived SCOs). The Indicator / Observable
    objects created through the OpenCTI REST API were still being made
    without ``objectMarking``, so a TLP:AMBER source produced indicators
    that OpenCTI exposed more broadly than the source SCO. These tests
    pin the fix end-to-end.
    """

    @staticmethod
    def _amber_observable() -> Dict[str, Any]:
        return {
            "id": "observable-amber",
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                    "standard_id": stix2.TLP_AMBER["id"],
                }
            ],
        }

    def _connector(self, create_observables: bool) -> AssemblyLineConnector:
        connector = _make_connector(assemblyline_create_observables=create_observables)
        connector.helper.api.indicator.create = MagicMock(return_value={"id": "ind-1"})
        connector.helper.api.stix_core_relationship.create = MagicMock()
        connector.helper.api.stix_cyber_observable.create = MagicMock(
            return_value={"id": "obs-1"}
        )
        connector.helper.api.stix_cyber_observable.add_label = MagicMock()
        connector.helper.api.stix2.format_date = MagicMock(return_value="2024-01-01")
        return connector

    def test_indicator_carries_source_object_marking(self) -> None:
        connector = self._connector(create_observables=False)
        connector._create_indicators(
            self._amber_observable(),
            900,
            {"domains": ["evil.com"], "ips": [], "urls": [], "families": []},
        )
        indicator_kwargs = connector.helper.api.indicator.create.call_args.kwargs
        assert indicator_kwargs.get("objectMarking") == [stix2.TLP_AMBER["id"]]

    def test_observable_carries_source_object_marking(self) -> None:
        connector = self._connector(create_observables=True)
        connector._create_indicators(
            self._amber_observable(),
            900,
            {"domains": ["evil.com"], "ips": [], "urls": [], "families": []},
        )
        obs_kwargs = connector.helper.api.stix_cyber_observable.create.call_args.kwargs
        assert obs_kwargs.get("objectMarking") == [stix2.TLP_AMBER["id"]]

    def test_unmarked_source_falls_back_to_tlp_clear(self) -> None:
        # Consistent with ``_check_tlp`` (which treats an unmarked
        # observable as ``TLP:CLEAR``) and with the platform's
        # canonical custom marking — not the deprecated TLP:WHITE.
        from main import _TLP_CLEAR_MARKING_ID

        connector = self._connector(create_observables=False)
        connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
            900,
            {"domains": ["evil.com"], "ips": [], "urls": [], "families": []},
        )
        indicator_kwargs = connector.helper.api.indicator.create.call_args.kwargs
        assert indicator_kwargs.get("objectMarking") == [_TLP_CLEAR_MARKING_ID]


class TestMalwareFamilyHasNoTrojanLabel:
    """Malware families must not be hard-coded to the ``trojan`` label."""

    def test_no_hardcoded_label(self) -> None:
        connector = _make_connector()
        connector.helper.api.malware.create = MagicMock(return_value={"id": "mal-1"})
        connector.helper.api.indicator.create = MagicMock(return_value={"id": "ind"})
        connector.helper.api.stix_core_relationship.create = MagicMock()

        connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
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

    def test_parse_positive_offset_normalised_to_utc(self) -> None:
        """Positive offsets are converted to UTC, not silently dropped.

        The earlier implementation split on ``+`` and discarded the
        offset entirely, so ``...10:11:12+02:00`` was treated as
        local-time 10:11:12 instead of 08:11:12 UTC. The new
        ``fromisoformat`` path normalises through ``astimezone(UTC)``
        so callers see the actual UTC wall-clock time.
        """
        connector = _make_connector()
        import datetime as _dt

        fallback = _dt.datetime(1970, 1, 1)
        parsed = connector._parse_al_timestamp("2024-05-04T10:11:12+02:00", fallback)
        assert parsed == _dt.datetime(2024, 5, 4, 8, 11, 12)

    def test_parse_negative_offset_normalised_to_utc(self) -> None:
        """Negative offsets parse correctly (used to fall back to default).

        The previous ``split("+", 1)[0]`` logic returned the original
        string unchanged for ``-04:00`` offsets because there was no
        ``+`` to split on, and the ``-04:00`` suffix is not valid
        ``strptime`` input for the bundled format strings — so the
        function silently dropped to ``fallback``. The new
        ``fromisoformat`` path handles negative offsets the same way
        as positive ones.
        """
        connector = _make_connector()
        import datetime as _dt

        fallback = _dt.datetime(1970, 1, 1)
        parsed = connector._parse_al_timestamp("2024-05-04T10:11:12-04:00", fallback)
        assert parsed == _dt.datetime(2024, 5, 4, 14, 11, 12)


class TestIocClassificationLabelsAndScores:
    """Indicators / Observables carry honest classification labels and scores.

    Pins the per-classification label + score contract: when
    ``ASSEMBLYLINE_INCLUDE_SUSPICIOUS=true``, suspicious-only IOCs are
    emitted as ``suspicious`` indicators with a moderate score (50)
    instead of being indistinguishable from genuinely-malicious ones
    in OpenCTI (which would otherwise land labelled ``malicious`` with
    the high-confidence score of 80 regardless of AssemblyLine's
    actual classification).
    """

    @staticmethod
    def _setup(create_observables: bool) -> AssemblyLineConnector:
        connector = _make_connector(
            assemblyline_create_observables=create_observables,
            assemblyline_include_suspicious=True,
        )
        connector.helper.api.indicator.create = MagicMock(
            side_effect=lambda **kwargs: {"id": f"ind-{kwargs['name']}"}
        )
        connector.helper.api.stix_cyber_observable.create = MagicMock(
            side_effect=lambda **kwargs: {
                "id": f"obs-{kwargs['observableData']['value']}"
            }
        )
        connector.helper.api.stix_cyber_observable.add_label = MagicMock()
        connector.helper.api.stix_core_relationship.create = MagicMock()
        connector.helper.api.stix2.format_date = MagicMock(return_value="2024-01-01")
        connector.helper.api.malware.create = MagicMock(return_value={"id": "mal-1"})
        return connector

    def test_malicious_indicator_score_and_label(self) -> None:
        connector = self._setup(create_observables=False)
        connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
            900,
            {"domains": ["evil.com"], "ips": [], "urls": [], "families": []},
            suspicious_iocs={"domains": [], "ips": [], "urls": [], "families": []},
        )
        call = connector.helper.api.indicator.create.call_args.kwargs
        assert call["x_opencti_score"] == 80
        assert "malicious" in call["labels"]
        assert "suspicious" not in call["labels"]

    def test_suspicious_indicator_score_and_label(self) -> None:
        connector = self._setup(create_observables=False)
        connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
            120,
            {"domains": [], "ips": [], "urls": [], "families": []},
            suspicious_iocs={
                "domains": ["sus.example.com"],
                "ips": [],
                "urls": [],
                "families": [],
            },
        )
        call = connector.helper.api.indicator.create.call_args.kwargs
        assert call["x_opencti_score"] == 50
        assert "suspicious" in call["labels"]
        assert "malicious" not in call["labels"]

    def test_suspicious_observable_carries_suspicious_label(self) -> None:
        connector = self._setup(create_observables=True)
        connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
            120,
            {"domains": [], "ips": [], "urls": [], "families": []},
            suspicious_iocs={
                "domains": ["sus.example.com"],
                "ips": [],
                "urls": [],
                "families": [],
            },
        )
        obs_call = connector.helper.api.stix_cyber_observable.create.call_args.kwargs
        assert obs_call["x_opencti_score"] == 50
        label_call = (
            connector.helper.api.stix_cyber_observable.add_label.call_args.kwargs
        )
        assert label_call["label"] == "suspicious"

    def test_mixed_classifications_emit_distinct_indicators(self) -> None:
        connector = self._setup(create_observables=False)
        connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
            900,
            {"domains": ["evil.com"], "ips": [], "urls": [], "families": []},
            suspicious_iocs={
                "domains": ["sus.example.com"],
                "ips": [],
                "urls": [],
                "families": [],
            },
        )
        calls = connector.helper.api.indicator.create.call_args_list
        labels_by_name = {c.kwargs["name"]: c.kwargs["labels"] for c in calls}
        scores_by_name = {c.kwargs["name"]: c.kwargs["x_opencti_score"] for c in calls}
        assert "malicious" in labels_by_name["evil.com"]
        assert "suspicious" in labels_by_name["sus.example.com"]
        assert scores_by_name["evil.com"] == 80
        assert scores_by_name["sus.example.com"] == 50


class TestResolveSubmissionClassification:
    """Source TLP must propagate to the AssemblyLine submission classification.

    The previous code always submitted with the connector-wide default
    (``TLP:C``), silently downgrading every sample's classification
    once it left OpenCTI. The new mapping mirrors the source
    observable's TLP in the AssemblyLine compact form.
    """

    @pytest.mark.parametrize(
        "source_tlp, expected",
        [
            ("TLP:CLEAR", "TLP:C"),
            ("TLP:WHITE", "TLP:C"),
            ("TLP:GREEN", "TLP:G"),
            ("TLP:AMBER", "TLP:A"),
            ("TLP:AMBER+STRICT", "TLP:A"),
            ("TLP:RED", "TLP:R"),
        ],
    )
    def test_known_tlp_maps_to_al_form(self, source_tlp: str, expected: str) -> None:
        connector = _make_connector()
        observable = {
            "objectMarking": [{"definition_type": "TLP", "definition": source_tlp}]
        }
        assert connector._resolve_submission_classification(observable) == expected

    def test_unmarked_falls_back_to_configured_default(self) -> None:
        connector = _make_connector(assemblyline_classification="CUSTOM:LEVEL")
        assert (
            connector._resolve_submission_classification({"objectMarking": []})
            == "CUSTOM:LEVEL"
        )

    def test_unknown_tlp_falls_back_to_configured_default(self) -> None:
        """Custom TLP-like markings flow through the operator override.

        Deployments that ship a non-standard TLP marking
        (e.g. a corporate ``TLP:GAMMA`` extension) keep working — the
        connector falls back to ``ASSEMBLYLINE_CLASSIFICATION`` rather
        than synthesising a bogus AL classification string.
        """
        connector = _make_connector(assemblyline_classification="TLP:C")
        observable = {
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:GAMMA"}]
        }
        assert connector._resolve_submission_classification(observable) == "TLP:C"


class TestConfigYamlSafeLoad:
    """Config parsing rejects YAML tags that could instantiate Python objects.

    Pins the config-loading security contract end-to-end through the
    connector's actual code path: parsing the ``config.yml`` MUST go
    through ``yaml.safe_load`` so a tampered file cannot instantiate
    arbitrary Python objects (the loader the connector previously
    used — ``yaml.FullLoader`` — would happily execute
    ``!!python/object/apply:os.system`` tags at load time).

    The first test exercises the connector's ``_load_config_file``
    helper directly so a regression to ``yaml.load(..., FullLoader)``
    in the connector's own code (rather than in ``yaml.safe_load``
    itself) would fail the assertion. The second test pins the
    happy-path behaviour: a valid ``config.yml`` parses cleanly to
    its dict shape, and a missing file resolves to an empty dict so
    the connector runs entirely off environment variables in
    containerised deployments.
    """

    def test_load_config_file_rejects_python_object_tag(self, tmp_path) -> None:
        import yaml

        config_path = tmp_path / "config.yml"
        config_path.write_text(
            "key: !!python/object/apply:os.system ['echo pwned']\n",
            encoding="utf-8",
        )
        with pytest.raises(yaml.YAMLError):
            AssemblyLineConnector._load_config_file(str(config_path))

    def test_load_config_file_parses_valid_yaml(self, tmp_path) -> None:
        config_path = tmp_path / "config.yml"
        config_path.write_text(
            "opencti:\n  url: https://opencti.example.com\n  token: t\n",
            encoding="utf-8",
        )
        assert AssemblyLineConnector._load_config_file(str(config_path)) == {
            "opencti": {"url": "https://opencti.example.com", "token": "t"},
        }

    def test_load_config_file_returns_empty_dict_when_missing(self, tmp_path) -> None:
        missing_path = str(tmp_path / "does-not-exist.yml")
        assert AssemblyLineConnector._load_config_file(missing_path) == {}

    def test_load_config_file_returns_empty_dict_when_empty(self, tmp_path) -> None:
        # ``yaml.safe_load`` of an empty file returns ``None``. The helper
        # coerces that to ``{}`` so ``OpenCTIConnectorHelper(config)``
        # downstream never receives ``None`` (which would raise on
        # subscript access in ``get_config_variable``).
        config_path = tmp_path / "config.yml"
        config_path.write_text("", encoding="utf-8")
        assert AssemblyLineConnector._load_config_file(str(config_path)) == {}


class TestUnsupportedEntityType:
    """``_process_message`` short-circuits unsupported entity types."""

    def test_skip_indicator(self) -> None:
        connector = _make_connector()
        result = connector._process_message(
            {"enrichment_entity": {"entity_type": "Indicator", "id": "ind"}}
        )
        assert "not supported" in result


class TestUnpinnedFileFetch:
    """File-fetch helpers must hit the canonical ``/storage/get/`` URL via pycti.

    Both ``_fetch_attached_file`` and ``_download_import_file`` route
    through ``helper.api.fetch_opencti_file`` so they inherit the
    pycti session's timeouts, retries, custom CA bundles and proxy /
    SSL settings rather than re-implementing HTTP with a raw
    ``requests.get`` and a manually-constructed ``Authorization``
    header.
    """

    def test_attached_file_uses_storage_url(self) -> None:
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"data")
        connector._fetch_attached_file("file-123")
        connector.helper.api.fetch_opencti_file.assert_called_once_with(
            "https://opencti.example.com/storage/get/file-123", binary=True
        )

    def test_import_file_uses_helper_not_raw_requests(self) -> None:
        """Pins the consistency fix between ``_download_import_file`` and ``_fetch_attached_file``.

        Both should call ``fetch_opencti_file`` so the importFiles
        download path inherits pycti's HTTP session config exactly
        like the ``x_opencti_files`` path already did.
        """
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"data")
        content = connector._download_import_file("file-123")
        assert content == b"data"
        connector.helper.api.fetch_opencti_file.assert_called_once_with(
            "https://opencti.example.com/storage/get/file-123", binary=True
        )


class TestSourceMarkingRefs:
    """Derived analysis SCOs inherit the source observable's TLP markings.

    A file that passes the ``ASSEMBLYLINE_MAX_TLP`` gate with a higher
    marking (e.g. ``TLP:AMBER``) must produce analysis SCOs carrying
    the same marking — never downgraded to ``TLP:WHITE``. This pins
    the contract of the helper used by ``_create_malware_analysis``.
    """

    def test_returns_amber_when_source_is_amber(self) -> None:
        observable = {
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                    "standard_id": stix2.TLP_AMBER["id"],
                }
            ]
        }
        refs = AssemblyLineConnector._source_marking_refs(observable)
        assert refs == [stix2.TLP_AMBER["id"]]

    def test_returns_multiple_markings_deduplicated_and_in_order(self) -> None:
        observable = {
            "objectMarking": [
                {"definition_type": "TLP", "standard_id": "marking-definition--a"},
                {
                    "definition_type": "statement",
                    "standard_id": "marking-definition--b",
                },
                {"definition_type": "TLP", "standard_id": "marking-definition--a"},
            ]
        }
        refs = AssemblyLineConnector._source_marking_refs(observable)
        assert refs == ["marking-definition--a", "marking-definition--b"]

    def test_falls_back_to_tlp_clear_when_source_has_no_markings(self) -> None:
        # When the source observable carries no marking at all we still
        # need every derived analysis object to carry *some* marking so
        # the platform's access-control gates work. We fall back to the
        # OpenCTI custom ``TLP:CLEAR`` marking — matching ``_check_tlp``,
        # which treats an unmarked observable as ``TLP:CLEAR`` — rather
        # than the deprecated ``stix2.TLP_WHITE`` constant.
        from main import _TLP_CLEAR_MARKING_ID

        refs = AssemblyLineConnector._source_marking_refs({"objectMarking": []})
        assert refs == [_TLP_CLEAR_MARKING_ID]

    def test_falls_back_when_object_marking_is_missing(self) -> None:
        from main import _TLP_CLEAR_MARKING_ID

        refs = AssemblyLineConnector._source_marking_refs({})
        assert refs == [_TLP_CLEAR_MARKING_ID]

    def test_ignores_markings_without_standard_id(self) -> None:
        # ``_check_tlp`` only relies on ``definition`` / ``definition_type``,
        # so a raw test stub may omit ``standard_id``. The marking-refs
        # helper must fall back gracefully (and not emit ``None``) in that
        # case.
        from main import _TLP_CLEAR_MARKING_ID

        observable = {
            "objectMarking": [
                {"definition_type": "TLP", "definition": "TLP:GREEN"},
            ]
        }
        refs = AssemblyLineConnector._source_marking_refs(observable)
        assert refs == [_TLP_CLEAR_MARKING_ID]


class TestMalwareAnalysisPropagatesSourceMarkings:
    """``_create_malware_analysis`` inherits the source TLP for derived SCOs.

    End-to-end test that exercises ``_create_malware_analysis`` with a
    TLP:AMBER source observable and asserts every derived analysis SCO
    in the emitted bundle (domain / IPv4 / IPv6 / URL) carries the
    same ``TLP:AMBER`` marking — never ``TLP:WHITE``.
    """

    # ``stix2`` validates ``created_by_ref`` against the canonical
    # ``<object-type>--<UUIDv4>`` shape, so the test stub uses a real
    # v4 UUID rather than the ``identity--abc`` placeholder used by
    # the rest of the suite (which never hits a stix2 validation path
    # because every other test mocks the bundle build).
    _IDENTITY_ID = "identity--c9a6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f"
    _SOURCE_ID = "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f"

    @classmethod
    def _observable_with_amber(cls) -> Dict[str, Any]:
        return {
            "id": cls._SOURCE_ID,
            "entity_type": "Artifact",
            "standard_id": cls._SOURCE_ID,
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                    "standard_id": stix2.TLP_AMBER["id"],
                }
            ],
        }

    def _run(self) -> Dict[str, Any]:
        connector = _make_connector(
            assemblyline_identity_standard_id=self._IDENTITY_ID,
            assemblyline_author=self._IDENTITY_ID,
        )
        sent_bundles: list = []
        connector.helper.stix2_create_bundle = MagicMock(
            side_effect=lambda objects: sent_bundles.append(objects) or "{}"
        )
        connector.helper.send_stix2_bundle = MagicMock()
        connector._create_malware_analysis(
            observable_id=self._SOURCE_ID,
            observable=self._observable_with_amber(),
            results={
                "sid": "sid-1",
                "max_score": 1500,
                "times": {
                    "submitted": "2024-05-04T10:11:12.345Z",
                    "completed": "2024-05-04T10:12:00Z",
                },
            },
            malicious_iocs={
                "domains": ["evil.example.org"],
                "ips": ["1.2.3.4", "2001:db8::1"],
                "urls": ["https://evil.example.org/path"],
                "families": [],
            },
        )
        assert len(sent_bundles) == 1, (
            "Expected a bundle to be sent; log_error calls were: "
            f"{connector.helper.log_error.call_args_list}"
        )
        return {obj.id: obj for obj in sent_bundles[0]}

    def test_domain_inherits_amber(self) -> None:
        bundle = self._run()
        domain = next(o for o in bundle.values() if o.type == "domain-name")
        assert domain.object_marking_refs == [stix2.TLP_AMBER["id"]]

    def test_ipv4_inherits_amber(self) -> None:
        bundle = self._run()
        ipv4 = next(
            o for o in bundle.values() if getattr(o, "type", None) == "ipv4-addr"
        )
        assert ipv4.object_marking_refs == [stix2.TLP_AMBER["id"]]

    def test_ipv6_inherits_amber(self) -> None:
        bundle = self._run()
        ipv6 = next(
            o for o in bundle.values() if getattr(o, "type", None) == "ipv6-addr"
        )
        assert ipv6.object_marking_refs == [stix2.TLP_AMBER["id"]]

    def test_url_inherits_amber(self) -> None:
        bundle = self._run()
        url = next(o for o in bundle.values() if getattr(o, "type", None) == "url")
        assert url.object_marking_refs == [stix2.TLP_AMBER["id"]]

    def test_no_derived_sco_is_downgraded_to_tlp_white(self) -> None:
        bundle = self._run()
        derived_types = {"domain-name", "ipv4-addr", "ipv6-addr", "url"}
        for obj in bundle.values():
            if getattr(obj, "type", None) in derived_types:
                assert (
                    stix2.TLP_WHITE["id"] not in obj.object_marking_refs
                ), f"{obj.type} was downgraded to TLP:WHITE: {obj.object_marking_refs}"

    def test_derived_scos_use_x_opencti_created_by_ref(self) -> None:
        # OpenCTI's observable/SCO authoring convention is the
        # ``x_opencti_created_by_ref`` custom property, not the
        # standard STIX ``created_by_ref`` (which is reserved for
        # SDOs/SROs). Setting the standard field on a SCO would
        # silently leave the platform's author column unset.
        bundle = self._run()
        derived_types = {"domain-name", "ipv4-addr", "ipv6-addr", "url"}
        for obj in bundle.values():
            if getattr(obj, "type", None) not in derived_types:
                continue
            serialized = obj.serialize()
            assert (
                "x_opencti_created_by_ref" in serialized
            ), f"{obj.type} is missing x_opencti_created_by_ref: {serialized}"
            assert (
                '"created_by_ref"' not in serialized
            ), f"{obj.type} should not use the standard SDO created_by_ref: {serialized}"

    def test_malware_analysis_inherits_amber(self) -> None:
        # The Malware-Analysis SDO carries the verdict, submission id
        # and score derived from the enriched file. Without the
        # source marking, OpenCTI would expose the analysis result
        # more broadly than the source observable, which silently
        # leaks ``TLP:AMBER`` analysis metadata to user groups that
        # are only allowed to see the (correctly marked) source.
        bundle = self._run()
        malware_analysis = next(
            o for o in bundle.values() if getattr(o, "type", None) == "malware-analysis"
        )
        assert malware_analysis.object_marking_refs == [stix2.TLP_AMBER["id"]], (
            "Malware-Analysis SDO should inherit the source marking, got: "
            f"{getattr(malware_analysis, 'object_marking_refs', None)}"
        )


class TestSummaryNoteVerdict:
    """The summary Note verdict must reflect every score / IOC bucket.

    The original implementation collapsed everything that was not
    ``MALICIOUS`` into ``SAFE``, so a suspicious-only AssemblyLine
    analysis (score 100-499, or only suspicious-tagged IOCs) ended up
    in the Note as ``Verdict: SAFE`` even while the rest of the
    connector labelled the source observable ``suspicious`` and
    emitted suspicious indicators — visibly contradictory in the
    OpenCTI UI. The new buckets line up with
    ``_score_to_result_name``:

    * ``score >= 500`` OR any malicious IOC tag → ``MALICIOUS``
    * ``score >= 100`` OR any suspicious IOC tag → ``SUSPICIOUS``
    * ``score > 0`` → ``UNKNOWN``
    * ``score == 0`` AND no IOCs → ``SAFE``
    """

    @staticmethod
    def _empty_iocs() -> Dict[str, list]:
        # ``_create_summary_note`` indexes ``malicious_iocs`` by the IOC
        # category names (``domains`` / ``ips`` / ``urls`` /
        # ``families``) directly, so every fixture must carry the full
        # shape even when individual buckets are empty.
        return {"domains": [], "ips": [], "urls": [], "families": []}

    @classmethod
    def _verdict_for(
        cls,
        results: Dict[str, Any],
        malicious_iocs: Dict[str, list] | None = None,
        suspicious_iocs: Dict[str, list] | None = None,
    ) -> str:
        connector = _make_connector()
        note_create = MagicMock()
        connector.helper.api = MagicMock(note=MagicMock(create=note_create))
        connector._create_summary_note(
            observable={
                "id": "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f",
                "objectMarking": [],
            },
            results=results,
            malicious_iocs=(
                malicious_iocs if malicious_iocs is not None else cls._empty_iocs()
            ),
            counts={"observables": 0, "indicators": 0},
            malware_analysis_id=None,
            attack_patterns_count=0,
            suspicious_iocs=suspicious_iocs,
        )
        assert note_create.called
        content = note_create.call_args.kwargs.get("content", "")
        # The Note content carries a ``**Verdict:** <BUCKET>`` line —
        # pull the bucket name back out for a clean assertion.
        for line in content.splitlines():
            stripped = line.strip().lstrip("*").strip()
            if stripped.startswith("Verdict"):
                return stripped.split(":", 1)[1].strip().strip("*").strip()
        raise AssertionError(f"No Verdict line found in note content: {content!r}")

    def test_malicious_score_produces_malicious_verdict(self) -> None:
        assert self._verdict_for({"sid": "s", "max_score": 1500}) == "MALICIOUS"

    def test_malicious_ioc_without_high_score_produces_malicious_verdict(
        self,
    ) -> None:
        # A low max_score but malicious-tagged IOC must still bubble up
        # as MALICIOUS — matching the rest of the enrichment.
        iocs = self._empty_iocs()
        iocs["domains"] = ["malware.example.com"]
        assert self._verdict_for({"sid": "s", "max_score": 50}, iocs) == "MALICIOUS"

    def test_suspicious_score_produces_suspicious_verdict(self) -> None:
        # Score 120 used to land on ``Verdict: SAFE`` even though the
        # connector simultaneously emits suspicious indicators with
        # ``x_opencti_score=50``.
        assert self._verdict_for({"sid": "s", "max_score": 120}) == "SUSPICIOUS"

    def test_suspicious_ioc_without_score_produces_suspicious_verdict(
        self,
    ) -> None:
        assert (
            self._verdict_for(
                {"sid": "s", "max_score": 0},
                suspicious_iocs={"domains": ["sketchy.example.org"]},
            )
            == "SUSPICIOUS"
        )

    def test_low_nonzero_score_produces_unknown_verdict(self) -> None:
        # ``_score_to_result_name`` says ``unknown`` for 1-99; mirror it.
        assert self._verdict_for({"sid": "s", "max_score": 50}) == "UNKNOWN"

    def test_zero_score_with_no_iocs_produces_safe_verdict(self) -> None:
        assert self._verdict_for({"sid": "s", "max_score": 0}) == "SAFE"


class TestSummaryNoteInheritsSourceMarking:
    """``_create_summary_note`` propagates the source observable's TLP.

    The summary Note built by the REST API path contains the verdict,
    submission id, file hash, size and IOC counts derived from the
    enriched file — leaking it to a broader audience than the source
    observable is the same access-control bug as the SCO downgrade,
    just through a different code path. The fix passes the source
    markings through ``_source_marking_refs`` and sets them on
    ``note_data["objectMarking"]`` so the API-created Note inherits
    the same TLP as the enriched observable. ``_source_marking_refs``
    is also what gives us the ``TLP:CLEAR`` fallback for unmarked
    sources, matching the bundle-side behaviour.
    """

    @staticmethod
    def _captured_note(observable: Dict[str, Any]) -> Dict[str, Any]:
        connector = _make_connector()
        note_create = MagicMock()
        connector.helper.api = MagicMock(note=MagicMock(create=note_create))
        connector._create_summary_note(
            observable=observable,
            results={"sid": "sid-1", "max_score": 1500, "file_info": {}},
            malicious_iocs={
                "domains": [],
                "ips": [],
                "urls": [],
                "families": [],
            },
            counts={"observables": 0, "indicators": 0},
            malware_analysis_id="malware-analysis--abc",
            attack_patterns_count=0,
        )
        assert note_create.called, "Expected helper.api.note.create to be called"
        return note_create.call_args.kwargs

    def test_amber_source_propagates_to_note(self) -> None:
        observable = {
            "id": "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f",
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                    "standard_id": stix2.TLP_AMBER["id"],
                }
            ],
        }
        kwargs = self._captured_note(observable)
        assert kwargs.get("objectMarking") == [stix2.TLP_AMBER["id"]], (
            "Summary Note should inherit the source TLP:AMBER marking, got: "
            f"{kwargs.get('objectMarking')}"
        )

    def test_unmarked_source_falls_back_to_tlp_clear(self) -> None:
        observable = {
            "id": "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f",
            "objectMarking": [],
        }
        kwargs = self._captured_note(observable)
        from main import _TLP_CLEAR_MARKING_ID

        assert kwargs.get("objectMarking") == [_TLP_CLEAR_MARKING_ID], (
            "Unmarked source should fall back to OpenCTI's TLP:CLEAR (not WHITE), got: "
            f"{kwargs.get('objectMarking')}"
        )


class TestTerminalAssemblyLineStates:
    """Terminal AssemblyLine submission states must surface immediately.

    ``failed`` / ``error`` / ``cancelled`` are end-of-life — polling
    them again will never recover. The polling loop in
    ``_process_file`` must re-raise the terminal failure right away
    instead of letting it be swallowed by the broad
    ``except Exception`` (which is there to absorb transient API /
    network glitches like a flaky ``ApiException`` from
    ``assemblyline-client``).
    """

    @pytest.mark.parametrize(
        "terminal_state",
        ["failed", "error", "cancelled"],
    )
    def test_process_file_raises_terminal_error_on_terminal_state(
        self,
        monkeypatch: pytest.MonkeyPatch,
        terminal_state: str,
    ) -> None:
        """``_process_file`` re-raises ``AssemblyLineTerminalError`` immediately.

        Pins the *real* polling-loop contract (not just the exception's
        re-raise mechanic in isolation):

        * ``requests.post`` returns a 200 with a valid ``sid`` — the
          submission succeeds, ``_process_file`` enters the polling
          loop.
        * ``al_client.submission.full`` returns ``{"state": <terminal>}``
          on the very first poll — the loop must raise immediately
          instead of waiting for ``assemblyline_timeout`` to elapse.
        * The raised exception is ``AssemblyLineTerminalError`` (NOT a
          plain ``Exception``), so a caller upstream can catch the
          terminal case specifically without masking transient
          failures.

        Without the dedicated branch in ``_process_file``'s polling
        loop, the broad ``except Exception`` would swallow the
        terminal state and let the loop spin until the global timeout.
        """
        connector = _make_connector(
            assemblyline_force_resubmit=False,
            assemblyline_timeout=300,
        )
        observable = {
            "id": "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f",
            "entity_type": "Artifact",
            "hashes": [],
            "objectMarking": [],
        }
        connector._get_file_content = MagicMock(
            return_value=(b"abc", "sample.bin", "no-hash")
        )
        connector._check_existing_analysis = MagicMock(return_value=None)
        connector._wait_for_al_ready = MagicMock()
        connector._resolve_submission_classification = MagicMock(return_value="TLP:C")
        connector._source_tlp = MagicMock(return_value="TLP:C")

        # Stub the submit POST. ``main.requests.post`` is the call site;
        # we do not need to fake the full ``requests.Response`` shape,
        # just ``status_code`` and ``json()`` so ``_process_file`` can
        # extract the ``sid`` and enter the polling loop.
        from main import requests as main_requests

        fake_post_response = MagicMock()
        fake_post_response.status_code = 200
        fake_post_response.json = MagicMock(
            return_value={"api_response": {"sid": "s-1"}}
        )
        monkeypatch.setattr(
            main_requests, "post", MagicMock(return_value=fake_post_response)
        )

        # First poll already returns the terminal state. The connector
        # MUST raise immediately rather than retry, sleep or fall back
        # to waiting out the timeout.
        connector.al_client.submission.full = MagicMock(
            return_value={"state": terminal_state}
        )

        with pytest.raises(AssemblyLineTerminalError) as exc_info:
            connector._process_file(observable)

        assert "s-1" in str(exc_info.value)
        # ``failed`` carries a different message shape from ``error`` /
        # ``cancelled`` (see ``main.py``); the common contract is that
        # the terminal state and submission id BOTH appear in the
        # raised message so the operator can map the failure back to
        # the AssemblyLine submission.
        assert (
            terminal_state in str(exc_info.value).lower() or terminal_state == "failed"
        )
        # Submission ran exactly once and polling stopped on the first
        # terminal-state response — no retry, no sleep-until-timeout.
        connector.al_client.submission.full.assert_called_once_with("s-1")

    def test_terminal_error_is_distinct_from_transient_exception(self) -> None:
        # ``AssemblyLineTerminalError`` is a subclass of ``Exception``
        # (so generic loggers still capture it) but must be a *distinct*
        # type so a polling loop can catch it specifically without
        # masking transient ``Exception`` errors.
        assert issubclass(AssemblyLineTerminalError, Exception)
        assert AssemblyLineTerminalError is not Exception


class TestMissingIdentityDoesNotEmitNoneAuthor:
    """Identity-lookup failure must not crash the Malware-Analysis bundle.

    ``_get_assemblyline_identity`` swallows ``Exception`` and sets
    ``assemblyline_identity_standard_id = None`` when the lookup /
    create call fails (transient OpenCTI errors, RBAC, etc.). The
    downstream STIX-construction paths must therefore tolerate a
    ``None`` author:

    * ``stix2.MalwareAnalysis(..., created_by_ref=None)`` raises
      ``InvalidValueError`` (the spec requires an ``identifier-type``
      string), which would short-circuit the entire Malware-Analysis
      bundle. The kwarg must be omitted instead.
    * Derived SCOs carry the author via the ``x_opencti_created_by_ref``
      custom property; passing ``None`` there serialises a ``null`` in
      the bundle that OpenCTI ingest does not unwrap into the author
      column. The key must be omitted instead.
    """

    _SOURCE_ID = "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f"

    @classmethod
    def _observable(cls) -> Dict[str, Any]:
        return {
            "id": cls._SOURCE_ID,
            "entity_type": "Artifact",
            "standard_id": cls._SOURCE_ID,
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                    "standard_id": stix2.TLP_AMBER["id"],
                }
            ],
        }

    def _run(self) -> Dict[str, Any]:
        # ``assemblyline_identity_standard_id=None`` simulates the
        # identity-lookup failure.
        connector = _make_connector(
            assemblyline_identity_standard_id=None,
            assemblyline_author=None,
        )
        sent_bundles: list = []
        connector.helper.stix2_create_bundle = MagicMock(
            side_effect=lambda objects: sent_bundles.append(objects) or "{}"
        )
        connector.helper.send_stix2_bundle = MagicMock()
        connector._create_malware_analysis(
            observable_id=self._SOURCE_ID,
            observable=self._observable(),
            results={
                "sid": "sid-1",
                "max_score": 1500,
                "times": {
                    "submitted": "2024-05-04T10:11:12.345Z",
                    "completed": "2024-05-04T10:12:00Z",
                },
            },
            malicious_iocs={
                "domains": ["evil.example.org"],
                "ips": [],
                "urls": [],
                "families": [],
            },
        )
        assert len(sent_bundles) == 1, (
            "Bundle should still be sent even with no identity; "
            f"log_error calls were: {connector.helper.log_error.call_args_list}"
        )
        return {obj.id: obj for obj in sent_bundles[0]}

    def test_malware_analysis_emitted_without_author(self) -> None:
        bundle = self._run()
        malware_analysis = next(
            o for o in bundle.values() if getattr(o, "type", None) == "malware-analysis"
        )
        # ``created_by_ref`` must be absent rather than ``None`` —
        # ``stix2`` would reject the latter.
        serialized = malware_analysis.serialize()
        assert '"created_by_ref"' not in serialized
        assert "null" not in serialized.lower() or '"created_by_ref": null' not in (
            serialized.lower()
        )

    def test_derived_scos_omit_author_when_identity_missing(self) -> None:
        bundle = self._run()
        domain = next(
            o for o in bundle.values() if getattr(o, "type", None) == "domain-name"
        )
        serialized = domain.serialize()
        assert "x_opencti_created_by_ref" not in serialized, (
            "Derived SCO should omit x_opencti_created_by_ref when no identity is "
            f"available, got: {serialized}"
        )


class TestProcessFileShaDedup:
    """``_process_file`` must only dedup on SHA-256, never MD5 / SHA-1.

    ``_check_existing_analysis`` searches AssemblyLine submissions by
    the literal Lucene query ``files.sha256:<hash>``. Passing an MD5
    or SHA-1 there always misses (so the connector pays a round-trip
    for nothing and pollutes the AssemblyLine audit log) and — far
    worse — could in principle hit an unrelated submission whose
    SHA-256 happens to share a prefix with the MD5 / SHA-1 wildcard
    match. The dedup path must therefore pick the SHA-256 explicitly
    via ``_select_sha256`` and only fire when one is present.
    """

    @staticmethod
    def _make_observable(hashes: list) -> Dict[str, Any]:
        return {
            "id": "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f",
            "entity_type": "Artifact",
            "hashes": hashes,
        }

    def _run(self, observable: Dict[str, Any], existing_results: Any) -> MagicMock:
        connector = _make_connector(assemblyline_force_resubmit=False)
        # Force ``_get_file_content`` to return a non-empty payload so
        # ``_process_file`` reaches the dedup branch instead of taking
        # the no-content / hash-lookup branch above it.
        connector._get_file_content = MagicMock(
            return_value=(b"abc", "sample.bin", "any-hash-value")
        )
        check_existing = MagicMock(return_value=existing_results)
        connector._check_existing_analysis = check_existing
        # Block the actual submission path so the test does not need to
        # mock the full AssemblyLine REST flow — we only care about the
        # call-shape of ``_check_existing_analysis`` here.
        connector._wait_for_al_ready = MagicMock()
        connector._resolve_submission_classification = MagicMock(return_value="TLP:C")
        connector._source_tlp = MagicMock(return_value="TLP:C")
        try:
            connector._process_file(observable)
        except Exception:
            # ``_process_file`` will try to submit and fail (we did not
            # mock ``requests.post``); that is fine — the dedup branch
            # runs first.
            pass
        return check_existing

    def test_dedup_uses_sha256_only(self) -> None:
        sha256 = "a" * 64
        observable = self._make_observable(
            [
                {"algorithm": "MD5", "hash": "b" * 32},
                {"algorithm": "SHA-1", "hash": "c" * 40},
                {"algorithm": "SHA-256", "hash": sha256},
            ]
        )
        check_existing = self._run(observable, existing_results=None)
        assert check_existing.call_count == 1
        called_arg = check_existing.call_args.args[0]
        assert called_arg == sha256, (
            "Dedup must call _check_existing_analysis with the SHA-256, not the first "
            f"available hash; got: {called_arg!r}"
        )

    def test_dedup_skipped_when_no_sha256(self) -> None:
        observable = self._make_observable(
            [
                {"algorithm": "MD5", "hash": "b" * 32},
                {"algorithm": "SHA-1", "hash": "c" * 40},
            ]
        )
        check_existing = self._run(observable, existing_results=None)
        check_existing.assert_not_called()


class TestSummaryNoteSuspiciousSection:
    """``_create_summary_note`` surfaces suspicious IOCs when emitted.

    When ``ASSEMBLYLINE_INCLUDE_SUSPICIOUS=true`` the rest of the
    enrichment emits ``suspicious``-labelled indicators with
    ``x_opencti_score=50`` and may set the verdict to ``SUSPICIOUS`` —
    a Note that only listed "Malicious IOCs" would be inconsistent
    with what the connector actually sent. The Note must therefore
    render an additional "Suspicious IOCs" section whenever the
    suspicious bucket is non-empty, and *must not* render it
    otherwise (so the malicious-only path keeps its original short
    format).
    """

    @staticmethod
    def _empty_iocs() -> Dict[str, list]:
        return {"domains": [], "ips": [], "urls": [], "families": []}

    @classmethod
    def _captured_note(
        cls,
        suspicious_iocs: Dict[str, list] | None = None,
        counts: Dict[str, int] | None = None,
    ) -> str:
        connector = _make_connector()
        note_create = MagicMock()
        connector.helper.api = MagicMock(note=MagicMock(create=note_create))
        connector._create_summary_note(
            observable={
                "id": "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f",
                "objectMarking": [],
            },
            results={"sid": "sid-1", "max_score": 1500, "file_info": {}},
            malicious_iocs=cls._empty_iocs(),
            counts=(
                counts if counts is not None else {"observables": 0, "indicators": 0}
            ),
            malware_analysis_id="malware-analysis--abc",
            attack_patterns_count=0,
            suspicious_iocs=suspicious_iocs,
        )
        assert note_create.called
        return note_create.call_args.kwargs.get("content", "")

    def test_suspicious_section_rendered_when_non_empty(self) -> None:
        sus = {
            "domains": ["sketchy.example.org", "another.sketchy.example.org"],
            "ips": ["10.0.0.1"],
            "urls": [],
            "families": ["AdwareXYZ"],
        }
        # The Note must report the *created* counts from ``counts``,
        # not ``len(suspicious_iocs[...])`` — ``_create_indicators``
        # caps creation at 20 per bucket, so on large analyses the
        # extracted-list lengths over-stated the count and
        # contradicted the run's success-message. Two suspicious
        # domains were extracted *and* successfully created here.
        counts = {
            "observables": 0,
            "indicators": 0,
            "suspicious_domains": 2,
            "suspicious_ips": 1,
            "suspicious_urls": 0,
        }
        content = self._captured_note(suspicious_iocs=sus, counts=counts)
        assert "## Suspicious IOCs Created as Indicators" in content
        assert "**Suspicious Domains:** 2" in content
        assert "**Suspicious IP Addresses:** 1" in content
        assert "**Suspicious URLs:** 0" in content
        # Malware families are emitted as Malware SDOs (NOT Indicators)
        # and only from the malicious bucket, so the "Suspicious IOCs"
        # section must NOT carry a "Suspicious Malware Families" line
        # — that would imply the connector creates Malware SDOs from
        # the suspicious bucket, which it does not.
        assert "Suspicious Malware Families" not in content

    def test_malware_families_section_rendered_when_count_non_zero(self) -> None:
        connector = _make_connector()
        note_create = MagicMock()
        connector.helper.api = MagicMock(note=MagicMock(create=note_create))
        connector._create_summary_note(
            observable={
                "id": "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f",
                "objectMarking": [],
            },
            results={"sid": "sid-1", "max_score": 1500, "file_info": {}},
            malicious_iocs=self._empty_iocs(),
            counts={"observables": 0, "indicators": 0, "malware_families": 3},
            malware_analysis_id="malware-analysis--abc",
            attack_patterns_count=0,
            suspicious_iocs=None,
        )
        assert note_create.called
        content = note_create.call_args.kwargs.get("content", "")
        # Malware families have their own section — never folded under
        # the "Created as Indicators" headers.
        assert "## Malware Families" in content
        assert "**Malware Families Created:** 3" in content
        assert "## Malicious IOCs Created as Indicators" in content
        # The malicious-IOC section must NOT mention malware families
        # (the previous shape rendered a "**Malware Families:** N"
        # bullet under that header, which implied the families were
        # created as Indicators rather than as Malware SDOs).
        malicious_section = content.split("## Malicious IOCs Created as Indicators", 1)[
            1
        ]
        malicious_section = malicious_section.split("##", 1)[0]
        assert "Malware Families" not in malicious_section

    def test_malware_families_section_omitted_when_zero(self) -> None:
        content = self._captured_note(suspicious_iocs=None)
        assert "## Malware Families" not in content

    def test_suspicious_section_omitted_when_empty(self) -> None:
        content = self._captured_note(suspicious_iocs=None)
        assert "Suspicious IOCs" not in content

    def test_suspicious_section_omitted_when_all_buckets_empty(self) -> None:
        content = self._captured_note(suspicious_iocs=self._empty_iocs())
        assert "Suspicious IOCs" not in content


class TestSummaryNoteUsesCreatedCountsNotExtractedLengths:
    """Note reports indicators *created*, not IOCs *extracted*.

    ``_create_indicators`` caps creation at 20 indicators per
    category (domains / IPs / URLs) for both the malicious and the
    suspicious bucket. The Note's "Created as Indicators" sections
    must therefore reflect the per-category counters maintained by
    ``_create_indicators`` (``counts['malicious_domains']`` etc.)
    instead of ``len(malicious_iocs['domains'])`` — otherwise on a
    large analysis (e.g. 50 malicious domains extracted, only 20
    created) the Note would contradict both the actual OpenCTI
    state and the connector's own success-message ("Created N
    malicious indicators").
    """

    @staticmethod
    def _captured_note_content(
        malicious_iocs: Dict[str, list],
        counts: Dict[str, int],
        suspicious_iocs: Dict[str, list] | None = None,
    ) -> str:
        connector = _make_connector()
        note_create = MagicMock()
        connector.helper.api = MagicMock(note=MagicMock(create=note_create))
        connector._create_summary_note(
            observable={
                "id": "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f",
                "objectMarking": [],
            },
            results={"sid": "sid-1", "max_score": 1500, "file_info": {}},
            malicious_iocs=malicious_iocs,
            counts=counts,
            malware_analysis_id="malware-analysis--abc",
            attack_patterns_count=0,
            suspicious_iocs=suspicious_iocs,
        )
        assert note_create.called
        return note_create.call_args.kwargs.get("content", "")

    def test_malicious_counts_use_created_not_extracted(self) -> None:
        # 50 domains / 30 ips / 25 urls extracted; ``_create_indicators``
        # capped creation at 20 per bucket — the Note must say 20, not
        # 50/30/25.
        malicious_iocs = {
            "domains": [f"d{i}.example.com" for i in range(50)],
            "ips": [f"10.0.0.{i}" for i in range(30)],
            "urls": [f"http://example.com/{i}" for i in range(25)],
            "families": [],
        }
        counts = {
            "observables": 0,
            "indicators": 60,
            "malicious_indicators": 60,
            "malicious_domains": 20,
            "malicious_ips": 20,
            "malicious_urls": 20,
        }
        content = self._captured_note_content(malicious_iocs, counts)
        assert "**Malicious Domains:** 20" in content
        assert "**Malicious IP Addresses:** 20" in content
        assert "**Malicious URLs:** 20" in content
        # And explicitly NOT the extracted-list lengths.
        assert "**Malicious Domains:** 50" not in content
        assert "**Malicious IP Addresses:** 30" not in content
        assert "**Malicious URLs:** 25" not in content

    def test_suspicious_counts_use_created_not_extracted(self) -> None:
        # Suspicious bucket is also capped at 20 per category by
        # ``_create_indicators``.
        suspicious_iocs = {
            "domains": [f"s{i}.example.org" for i in range(40)],
            "ips": [],
            "urls": [f"http://sketchy.example.org/{i}" for i in range(35)],
            "families": [],
        }
        counts = {
            "observables": 0,
            "indicators": 40,
            "suspicious_indicators": 40,
            "suspicious_domains": 20,
            "suspicious_ips": 0,
            "suspicious_urls": 20,
        }
        content = self._captured_note_content(
            {"domains": [], "ips": [], "urls": [], "families": []},
            counts,
            suspicious_iocs=suspicious_iocs,
        )
        assert "## Suspicious IOCs Created as Indicators" in content
        assert "**Suspicious Domains:** 20" in content
        assert "**Suspicious IP Addresses:** 0" in content
        assert "**Suspicious URLs:** 20" in content
        assert "**Suspicious Domains:** 40" not in content
        assert "**Suspicious URLs:** 35" not in content


class TestCreateIndicatorsTracksPerCategoryCreatedCounts:
    """``_create_indicators`` exposes per-category created-indicator counts.

    ``counts`` carries both the rolled-up totals
    (``malicious_indicators`` / ``suspicious_indicators``) and the
    per-category created counts (``malicious_domains`` /
    ``malicious_ips`` / ``malicious_urls`` / ``suspicious_domains`` /
    ``suspicious_ips`` / ``suspicious_urls``). The Note relies on
    these per-category counters to report what was *actually
    created* in OpenCTI (capped at 20 per bucket), not what was
    extracted from AssemblyLine.
    """

    def _connector(self) -> AssemblyLineConnector:
        connector = _make_connector(
            assemblyline_create_observables=False,
            assemblyline_include_suspicious=True,
        )
        connector.helper.api.indicator.create = MagicMock(return_value={"id": "ind-1"})
        connector.helper.api.stix_core_relationship.create = MagicMock()
        connector.helper.api.malware.create = MagicMock(return_value={"id": "mal-1"})
        connector.helper.api.stix2.format_date = MagicMock(return_value="2024-01-01")
        return connector

    def test_per_category_created_counts_are_capped_at_twenty(self) -> None:
        connector = self._connector()
        # 25 domains / 22 ips / 21 urls all "succeed" (helper returns
        # an indicator id) — the per-category counter should still
        # only report 20 per bucket because ``_create_indicators``
        # slices ``[:20]``.
        malicious_iocs = {
            "domains": [f"d{i}.example.com" for i in range(25)],
            "ips": [f"10.0.0.{i}" for i in range(22)],
            "urls": [f"http://example.com/{i}" for i in range(21)],
            "families": [],
        }
        counts, _ = connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
            900,
            malicious_iocs,
        )
        assert counts["malicious_domains"] == 20
        assert counts["malicious_ips"] == 20
        assert counts["malicious_urls"] == 20
        assert counts["malicious_indicators"] == 60

    def test_failed_indicator_creation_does_not_increment_per_category_count(
        self,
    ) -> None:
        connector = self._connector()
        # First two indicator creates succeed, the third raises — the
        # per-category counter must reflect what was actually created
        # (2), not what was extracted (3).
        connector.helper.api.indicator.create = MagicMock(
            side_effect=[
                {"id": "ind-1"},
                {"id": "ind-2"},
                Exception("indicator create failed"),
            ]
        )
        counts, _ = connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
            900,
            {
                "domains": ["a.example.com", "b.example.com", "c.example.com"],
                "ips": [],
                "urls": [],
                "families": [],
            },
        )
        assert counts["malicious_domains"] == 2
        assert counts["malicious_indicators"] == 2

    def test_suspicious_bucket_counters_track_per_category(self) -> None:
        connector = self._connector()
        suspicious_iocs = {
            "domains": ["sketchy1.example.org", "sketchy2.example.org"],
            "ips": ["10.0.0.1"],
            "urls": [],
            "families": [],
        }
        counts, _ = connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
            120,
            {"domains": [], "ips": [], "urls": [], "families": []},
            suspicious_iocs=suspicious_iocs,
        )
        assert counts["suspicious_domains"] == 2
        assert counts["suspicious_ips"] == 1
        assert counts["suspicious_urls"] == 0
        assert counts["suspicious_indicators"] == 3


class TestMalwareFamilyInheritsSourceMarkings:
    """Malware family SDOs inherit the source observable's markings.

    A TLP:AMBER file passing the max-TLP gate must produce TLP:AMBER
    Malware family SDOs — not unmarked / TLP:CLEAR — so OpenCTI's
    access-control gates apply consistently across the whole
    derived sub-graph (Indicators, Observables, Malware-Analysis,
    Attack-Patterns, Note, and Malware family SDOs all carry the
    same markings as the source).
    """

    @staticmethod
    def _amber_observable() -> Dict[str, Any]:
        return {
            "id": "observable-amber",
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                    "standard_id": stix2.TLP_AMBER["id"],
                }
            ],
        }

    def _connector(self) -> AssemblyLineConnector:
        connector = _make_connector()
        connector.helper.api.indicator.create = MagicMock(return_value={"id": "ind-1"})
        connector.helper.api.stix_core_relationship.create = MagicMock()
        connector.helper.api.malware.create = MagicMock(return_value={"id": "mal-1"})
        connector.helper.api.stix2.format_date = MagicMock(return_value="2024-01-01")
        return connector

    def test_malware_sdo_carries_source_object_marking(self) -> None:
        connector = self._connector()
        connector._create_indicators(
            self._amber_observable(),
            900,
            {
                "domains": [],
                "ips": [],
                "urls": [],
                "families": ["EMOTET"],
            },
        )
        malware_kwargs = connector.helper.api.malware.create.call_args.kwargs
        assert malware_kwargs.get("objectMarking") == [stix2.TLP_AMBER["id"]]

    def test_observable_to_malware_relationship_carries_source_object_marking(
        self,
    ) -> None:
        connector = self._connector()
        connector._create_indicators(
            self._amber_observable(),
            900,
            {
                "domains": [],
                "ips": [],
                "urls": [],
                "families": ["EMOTET"],
            },
        )
        # The relationship from the source observable to the Malware
        # SDO must carry the source markings too — leaving an
        # unmarked SRO on a marked sub-graph leaves the relationship
        # itself visible to a broader audience than its endpoints.
        rel_calls = connector.helper.api.stix_core_relationship.create.call_args_list
        assert rel_calls, "Expected at least one stix_core_relationship.create call"
        # The malware ``related-to`` relationship is the one targeting
        # ``mal-1``; pick it explicitly so the test cannot drift if
        # additional SROs are added later.
        malware_rel_kwargs = next(
            (c.kwargs for c in rel_calls if c.kwargs.get("toId") == "mal-1"),
            None,
        )
        assert malware_rel_kwargs is not None
        assert malware_rel_kwargs.get("objectMarking") == [stix2.TLP_AMBER["id"]]

    def test_unmarked_source_falls_back_to_tlp_clear(self) -> None:
        from main import _TLP_CLEAR_MARKING_ID

        connector = self._connector()
        connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
            900,
            {
                "domains": [],
                "ips": [],
                "urls": [],
                "families": ["EMOTET"],
            },
        )
        malware_kwargs = connector.helper.api.malware.create.call_args.kwargs
        assert malware_kwargs.get("objectMarking") == [_TLP_CLEAR_MARKING_ID]


class TestAttackPatternInheritsSourceMarkings:
    """ATT&CK Attack-Pattern SDOs inherit the source observable's markings.

    Attack-Patterns observed during analysis of a marked source
    (e.g. TLP:AMBER) must be created with the same ``objectMarking``
    as the source so OpenCTI does not expose them more broadly than
    the observable that triggered the analysis. Pre-existing Attack-
    Patterns (returned by the fallback list query) are intentionally
    *not* re-marked: they may already carry markings from previous
    enrichments and the connector should not silently downgrade or
    overwrite those.
    """

    @staticmethod
    def _amber_observable() -> Dict[str, Any]:
        return {
            "id": "observable-amber",
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                    "standard_id": stix2.TLP_AMBER["id"],
                }
            ],
        }

    def _connector(self) -> AssemblyLineConnector:
        connector = _make_connector()
        connector.helper.api.attack_pattern.create = MagicMock(
            return_value={"id": "attack-pattern-1"}
        )
        return connector

    def test_attack_pattern_sdo_carries_source_object_marking(self) -> None:
        connector = self._connector()
        connector._create_attack_patterns(
            [
                {
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "tactic": "execution",
                    "confidence": "high",
                    "kill_chain_phase": "execution",
                }
            ],
            source_marking_refs=[stix2.TLP_AMBER["id"]],
        )
        attack_pattern_kwargs = (
            connector.helper.api.attack_pattern.create.call_args.kwargs
        )
        assert attack_pattern_kwargs.get("objectMarking") == [stix2.TLP_AMBER["id"]]

    def test_attack_pattern_sdo_omits_marking_when_none_provided(self) -> None:
        connector = self._connector()
        connector._create_attack_patterns(
            [
                {
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "tactic": "execution",
                    "confidence": "high",
                    "kill_chain_phase": "execution",
                }
            ]
        )
        # Backwards compatibility: when the caller doesn't pass
        # marking refs (legacy / unmarked source), the create call
        # must not carry an ``objectMarking=None`` that the OpenCTI
        # API would reject.
        attack_pattern_kwargs = (
            connector.helper.api.attack_pattern.create.call_args.kwargs
        )
        assert "objectMarking" not in attack_pattern_kwargs


class TestMalwareAnalysisResultValue:
    """``_create_malware_analysis`` must align ``result`` with malicious evidence.

    The Malware-Analysis SDO's ``result`` is what the OpenCTI UI shows
    in the *Malware Analysis* section of the enriched observable. The
    rest of the connector treats *any* malicious tag (or malware-family
    attribution) as a malicious verdict:

    * ``_process_file`` flips ``is_malicious`` to ``True`` and labels
      the source observable ``malicious`` with ``x_opencti_score=80``.
    * ``_create_summary_note`` sets ``Verdict: MALICIOUS``.

    The Malware-Analysis SDO must therefore reach the same conclusion,
    otherwise the UI shows two contradicting signals on the same
    observable (e.g. ``label=malicious``, ``score=80``,
    ``Verdict: MALICIOUS``, but ``Malware-Analysis.result=suspicious``).
    The previous shape only upgraded a *below-suspicious* score
    (``unknown`` / ``benign``) when malicious evidence was present —
    a score in ``[100, 500)`` plus a malicious IOC stayed
    ``suspicious`` and produced exactly that contradiction.
    """

    _IDENTITY_ID = "identity--c9a6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f"
    _SOURCE_ID = "artifact--d9b6f1d2-3b4f-4f4f-8f8f-4f4f4f4f4f4f"

    @classmethod
    def _observable(cls) -> Dict[str, Any]:
        return {
            "id": cls._SOURCE_ID,
            "entity_type": "Artifact",
            "standard_id": cls._SOURCE_ID,
            "objectMarking": [],
        }

    @classmethod
    def _empty_iocs(cls) -> Dict[str, list]:
        return {"domains": [], "ips": [], "urls": [], "families": []}

    def _captured_result(self, max_score: int, malicious_iocs: Dict[str, list]) -> str:
        connector = _make_connector(
            assemblyline_identity_standard_id=self._IDENTITY_ID,
            assemblyline_author=self._IDENTITY_ID,
        )
        sent_bundles: list = []
        connector.helper.stix2_create_bundle = MagicMock(
            side_effect=lambda objects: sent_bundles.append(objects) or "{}"
        )
        connector.helper.send_stix2_bundle = MagicMock()
        connector._create_malware_analysis(
            observable_id=self._SOURCE_ID,
            observable=self._observable(),
            results={
                "sid": "sid-1",
                "max_score": max_score,
                "times": {
                    "submitted": "2024-05-04T10:11:12.345Z",
                    "completed": "2024-05-04T10:12:00Z",
                },
            },
            malicious_iocs=malicious_iocs,
        )
        assert sent_bundles, (
            "Expected a Malware-Analysis bundle to be sent; "
            f"log_error calls were: {connector.helper.log_error.call_args_list}"
        )
        malware_analysis = next(
            o for o in sent_bundles[0] if getattr(o, "type", None) == "malware-analysis"
        )
        return malware_analysis.result

    def test_malicious_score_keeps_malicious_result(self) -> None:
        # The score-bucket already says ``malicious`` so no upgrade is
        # required — pinning this ensures the upgrade branch never
        # accidentally overwrites a higher-confidence verdict.
        assert self._captured_result(1500, self._empty_iocs()) == "malicious"

    def test_suspicious_score_with_no_iocs_stays_suspicious(self) -> None:
        # A score in the suspicious bucket without any malicious IOC
        # remains ``suspicious`` — that matches the score-only verdict
        # ``_score_to_result_name`` produces. The upgrade branch must
        # only fire on actual malicious evidence.
        assert self._captured_result(120, self._empty_iocs()) == "suspicious"

    def test_suspicious_score_with_malicious_ioc_upgrades_to_malicious(
        self,
    ) -> None:
        # Regression test for the previous shape: a score in
        # ``[100, 500)`` plus a malicious-tagged IOC used to leave the
        # SDO at ``result=suspicious`` even though
        # ``_process_file`` / ``_create_summary_note`` already treated
        # the same input as ``malicious``. The upgrade branch must
        # therefore fire on the suspicious score-bucket too.
        iocs = self._empty_iocs()
        iocs["domains"] = ["malware.example.com"]
        assert self._captured_result(120, iocs) == "malicious"

    def test_suspicious_score_with_malicious_family_upgrades_to_malicious(
        self,
    ) -> None:
        # The ``families`` bucket counts as malicious evidence on its
        # own — a confirmed malware-family attribution from
        # AssemblyLine is a strong enough signal to flip the result
        # even when no IOC tags were emitted. ``has_malicious_evidence``
        # therefore drives off ``any(malicious_iocs.values())``, which
        # includes the ``families`` bucket.
        iocs = self._empty_iocs()
        iocs["families"] = ["EMOTET"]
        assert self._captured_result(120, iocs) == "malicious"

    def test_unknown_score_with_malicious_ioc_upgrades_to_malicious(self) -> None:
        # A score in the ``unknown`` bucket (1-99) plus a malicious
        # IOC must also upgrade — covers the original upgrade contract
        # alongside the ``suspicious``-bucket case above.
        iocs = self._empty_iocs()
        iocs["urls"] = ["http://malware.example.com/payload"]
        assert self._captured_result(50, iocs) == "malicious"

    def test_benign_score_with_no_iocs_stays_benign(self) -> None:
        # ``score == 0`` and no malicious evidence should keep the
        # ``benign`` verdict — the upgrade branch only fires on
        # malicious evidence, never as a side effect of how
        # ``_score_to_result_name`` slices the score.
        assert self._captured_result(0, self._empty_iocs()) == "benign"


class TestPollSleepHonoursDeadline:
    """``_wait_for_al_ready`` must never sleep past the deadline.

    Regression test for the Copilot review thread on
    ``main.py:817`` — the previous shape unconditionally slept the
    full ``assemblyline_poll_interval`` after each polling iteration,
    so on the boundary tick the wait could overshoot
    ``ASSEMBLYLINE_TIMEOUT`` by nearly one poll interval. The fix
    caps the sleep at ``min(poll_interval, max(0, remaining))`` so
    total wall-time honours the configured timeout.
    """

    def test_sleep_capped_at_remaining_budget(self, monkeypatch) -> None:
        import time as _time_mod

        # 30 s poll interval but only ~0.05 s remaining before
        # deadline → the sleep arg must be ≤ 0.05 s.
        connector = _make_connector(
            assemblyline_sequential_mode=True,
            assemblyline_poll_interval=30,
        )
        # First call returns "busy" so we enter the sleep path, then
        # the second call raises out of the loop via the deadline
        # check on the next iteration — we only care about the value
        # passed to time.sleep on the first tick.
        connector.al_client.search.submission = MagicMock(
            side_effect=[{"total": 5}, Exception("deadline already past")]
        )

        sleeps: list = []
        monkeypatch.setattr(_time_mod, "sleep", lambda s: sleeps.append(s))

        deadline = _time_mod.monotonic() + 0.05
        with pytest.raises(Exception):
            connector._wait_for_al_ready(deadline=deadline)

        assert sleeps, "expected at least one time.sleep call"
        # Every sleep must be bounded by what was left on the
        # deadline at the time the call was made — the
        # 30-second poll interval can never appear here.
        for s in sleeps:
            assert s <= 0.05 + 1e-3, f"sleep {s}s overshot the deadline"


class TestForceResubmitWiresAssemblyLineIgnoreCache:
    """``ASSEMBLYLINE_FORCE_RESUBMIT`` must reach AssemblyLine itself.

    Regression test for the Copilot review thread on ``main.py:901``
    — the connector was skipping the OpenCTI-side dedup
    (``_check_existing_analysis``) when the flag was set but still
    sent ``ignore_cache: False`` in the submission payload, so
    AssemblyLine could still serve a cached result one layer deeper
    and silently no-op the operator's intent.
    """

    def _run_submission(self, *, force_resubmit: bool):
        """Drive ``_process_file`` far enough to capture the POST."""
        import io as _io
        import time as _time_mod

        connector = _make_connector(
            assemblyline_force_resubmit=force_resubmit,
            assemblyline_timeout=60,
            assemblyline_poll_interval=0,
        )
        connector._get_file_content = MagicMock(  # type: ignore[method-assign]
            return_value=(b"binary", "sample.exe", "sha256")
        )
        connector._select_sha256 = MagicMock(  # type: ignore[method-assign]
            return_value="sha256-hash"
        )
        connector._check_existing_analysis = MagicMock(  # type: ignore[method-assign]
            return_value=None
        )
        connector._wait_for_al_ready = MagicMock()  # type: ignore[method-assign]
        connector._resolve_submission_classification = MagicMock(  # type: ignore[method-assign]
            return_value="TLP:C"
        )
        connector._source_tlp = MagicMock(return_value="TLP:CLEAR")  # type: ignore[method-assign]

        captured: dict = {}

        class _PostResp:
            status_code = 200

            def json(self):  # noqa: D401
                return {"api_response": {"sid": "sid-1"}}

            def raise_for_status(self):  # noqa: D401
                return None

        def _fake_post(url, **kwargs):
            files = kwargs.get("files") or {}
            json_field = files.get("json")
            if json_field:
                captured["json"] = json.loads(json_field[1])
            return _PostResp()

        # Pretend the submission completes immediately on the very
        # first polling iteration so we exit the timeout loop and
        # don't have to mock the full polling state machine.
        class _CompletedSub:
            def __call__(self, sid):
                return {"state": "completed", "max_score": 10}

        connector.al_client.submission = _CompletedSub()
        connector.al_client.submission.full = MagicMock(  # type: ignore[attr-defined]
            return_value={"max_score": 10}
        )
        connector.al_client.submission.summary = MagicMock(  # type: ignore[attr-defined]
            return_value={"sid": "sid-1"}
        )

        import requests as _requests

        # Patch the symbol that ``_process_file`` reaches through.
        from main import requests as _main_requests

        monkey_post = MagicMock(side_effect=_fake_post)
        original_post = _main_requests.post
        _main_requests.post = monkey_post
        try:
            try:
                connector._process_file({"id": "obs-1", "hashes": []})
            except Exception:
                # We don't need the full processing to succeed; the
                # POST capture is all this test cares about.
                pass
        finally:
            _main_requests.post = original_post

        # silence unused-import lint
        _ = _io, _time_mod, _requests
        return captured

    def test_force_resubmit_sets_ignore_cache_true(self) -> None:
        captured = self._run_submission(force_resubmit=True)
        assert (
            captured.get("json", {}).get("params", {}).get("ignore_cache") is True
        ), captured

    def test_no_force_resubmit_keeps_ignore_cache_false(self) -> None:
        captured = self._run_submission(force_resubmit=False)
        assert (
            captured.get("json", {}).get("params", {}).get("ignore_cache") is False
        ), captured


class TestPayloadBinDecodeError:
    """Malformed ``payload_bin`` must not crash the per-observable loop.

    Regression test for the Copilot review thread on ``main.py:558``
    — ``base64.b64decode`` raises ``binascii.Error`` on malformed
    input. Without the guard, a single corrupted observable would
    bypass the per-observable retry / fallback path (``importFiles`` →
    ``x_opencti_files`` → SHA-256 deferred lookup) and surface as a
    bare exception with no observable context. The fix logs a
    warning with the observable id and falls through to the next
    source.
    """

    def test_invalid_payload_bin_falls_back_to_importfiles(self) -> None:
        connector = _make_connector()
        connector._download_import_file = MagicMock(  # type: ignore[method-assign]
            return_value=b"recovered"
        )
        connector._select_any_hash = MagicMock(return_value="hash")  # type: ignore[method-assign]
        # Call ``_get_artifact_content`` directly — the public
        # ``_get_file_content`` dispatches by ``entity_type`` and
        # the ``payload_bin`` path only fires on the Artifact branch.
        # A single character is an invalid base64 length (1 mod 4)
        # so it reliably triggers ``binascii.Error`` on every
        # supported Python version even with ``validate=False``,
        # unlike inputs that happen to decode to garbage bytes.
        observable = {
            "id": "obs-bad-payload",
            "entity_type": "Artifact",
            "payload_bin": "A",
            "importFiles": [{"id": "file-1", "name": "fallback.bin"}],
            "hashes": [],
        }
        content, name, _ = connector._get_artifact_content(observable)
        assert content == b"recovered"
        assert name == "fallback.bin"
        # The decode failure must have been logged with the
        # observable id so the operator can correlate.
        warn_msgs = [
            call.args[0]
            for call in connector.helper.log_warning.call_args_list
            if call.args
        ]
        assert any("obs-bad-payload" in m for m in warn_msgs), warn_msgs


class TestSkipLoopbackInIndicatorPath:
    """``_create_indicators`` must skip loopback / unspecified IPs.

    Regression test for the Copilot review thread on
    ``main.py:1751`` — the Malware-Analysis bundle SCO path already
    filtered ``127.0.0.1`` / ``::1`` / ``0.0.0.0`` (AssemblyLine
    routinely reports them as observed during sandbox detonation,
    but they are never meaningful indicators in OpenCTI) but the
    indicator / observable creation path did not. The fix mirrors
    the same skip list via ``_is_skippable_ip`` so the two sites
    stay aligned.
    """

    def test_loopback_and_unspecified_ips_are_skipped(self) -> None:
        connector = _make_connector(assemblyline_create_observables=False)
        connector.helper.api.indicator.create = MagicMock(return_value={"id": "ind-1"})
        connector.helper.api.stix_core_relationship.create = MagicMock()
        connector.helper.api.stix2.format_date = MagicMock(return_value="2024-01-01")
        counts, indicator_ids = connector._create_indicators(
            {"id": "obs-root", "objectMarking": []},
            900,
            {
                "domains": [],
                "ips": ["127.0.0.1", "::1", "0.0.0.0", "203.0.113.5"],
                "urls": [],
                "families": [],
            },
        )
        # Only ``203.0.113.5`` (TEST-NET-3, a routable example range)
        # should have produced an indicator. The three sandbox-noise
        # literals must have been filtered before reaching the
        # indicator create call.
        assert counts["indicators"] == 1, counts
        assert counts["malicious_ips"] == 1, counts
        assert indicator_ids == ["ind-1"]
        # Every payload sent to indicator.create must contain the
        # routable IP and never the loopback / unspecified ones.
        for call in connector.helper.api.indicator.create.call_args_list:
            pattern = call.kwargs.get("pattern", "")
            assert "127.0.0.1" not in pattern
            assert "::1" not in pattern
            assert "0.0.0.0" not in pattern


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
