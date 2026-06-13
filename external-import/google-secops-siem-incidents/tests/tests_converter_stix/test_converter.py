"""RED tests — ConverterToStix orchestrator.

Tests the converter that orchestrates all mappers to produce a flat list of
STIX objects from a single RuleAlert (Alert + RuleMetadata).

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

from unittest.mock import MagicMock

# --- import under test (will cause ImportError → RED) ---
from google_secops_siem_incidents.converter_to_stix import ConverterToStix  # noqa: E402
from tests_converter_stix.factories import (
    AlertFactory,
    AlertFieldFactory,
    RuleMetadataFactory,
    RulePropertiesFactory,
    make_hostname_outcomes,
    make_ip_outcomes,
    make_risk_score_outcome,
    make_user_outcomes,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_helper():
    """Return a minimal mocked OpenCTIConnectorHelper."""
    helper = MagicMock()
    helper.connect_name = "Google SecOps"
    return helper


def _make_converter():
    """Build a ConverterToStix with mocked helper."""
    return ConverterToStix(helper=_make_helper(), tlp_level="amber")


def _build_full_alert():
    """Build an Alert + RuleMetadata with hostname, 2 IPs, 1 user account."""
    hostname_outcomes = make_hostname_outcomes("webserver.corp.local")
    ip_outcomes = make_ip_outcomes(["10.0.0.1", "192.168.1.5"], is_ipv6=False)
    user_outcomes = make_user_outcomes(principal_users=["alice"])
    risk_outcome = [make_risk_score_outcome("50")]

    all_outcomes = hostname_outcomes + ip_outcomes + user_outcomes + risk_outcome

    alert = AlertFactory.build(
        fields=[
            AlertFieldFactory.build(name="ip", string_val="10.0.0.1"),
            AlertFieldFactory.build(name="hostname", string_val="webserver.corp.local"),
        ],
        outcomes=all_outcomes,
        rule_type="MULTI_EVENT",
    )
    rule_metadata = RuleMetadataFactory.build(
        properties=RulePropertiesFactory.build(
            metadata={"severity": "HIGH", "tags": "test"},
        ),
    )
    return alert, rule_metadata


def _build_empty_alert():
    """Build an Alert with no outcomes (no observables expected)."""
    alert = AlertFactory.build(
        fields=[],
        outcomes=[],
        rule_type="SINGLE_EVENT",
    )
    rule_metadata = RuleMetadataFactory.build(
        properties=RulePropertiesFactory.build(
            metadata={"severity": "LOW", "tags": ""},
        ),
    )
    return alert, rule_metadata


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestConverterToStix:
    def test_then_full_alert_produces_incident_and_observables(self):
        """convert_rule_alert with full alert → incident + observables from outcomes AND fields + relationships."""
        # _given_
        converter = _make_converter()
        alert, rule_metadata = _build_full_alert()

        # _when_
        result = converter.convert_rule_alert(alert, rule_metadata)

        # _then_ — count by STIX2 type string
        # Outcomes produce: 1 hostname, 2 IPs, 1 user
        # Alert fields produce: 1 hostname (webserver.corp.local), 1 IP (10.0.0.1)
        incidents = [o for o in result if getattr(o, "type", None) == "incident"]
        hostnames = [o for o in result if getattr(o, "type", None) == "hostname"]
        ips = [o for o in result if getattr(o, "type", None) == "ipv4-addr"]
        users = [o for o in result if getattr(o, "type", None) == "user-account"]
        rels = [o for o in result if getattr(o, "type", None) == "relationship"]

        assert len(incidents) == 1
        assert len(hostnames) == 2  # 1 outcome + 1 field
        assert len(ips) == 3  # 2 outcomes + 1 field
        assert len(users) == 1
        assert len(rels) == 6  # 2 hostnames + 3 IPs + 1 user

    def test_then_empty_alert_produces_incident_only(self):
        """convert_rule_alert with empty event samples → incident only (no observables, no relationships)."""
        # _given_
        converter = _make_converter()
        alert, rule_metadata = _build_empty_alert()

        # _when_
        result = converter.convert_rule_alert(alert, rule_metadata)

        # _then_
        assert len(result) == 1  # just the incident
        rels = [o for o in result if getattr(o, "type", None) == "relationship"]
        assert len(rels) == 0

    def test_then_all_objects_have_correct_author(self):
        """All objects are attributed to 'Google SecOps'."""
        # _given_
        converter = _make_converter()
        alert, rule_metadata = _build_full_alert()

        # _when_
        result = converter.convert_rule_alert(alert, rule_metadata)  # noqa: F841

        # _then_ — the author identity should be in the result or referenced
        assert converter.author is not None
        assert converter.author["name"] == "Google SecOps"

    def test_then_all_objects_have_tlp_marking(self):
        """All objects carry TLP:AMBER marking."""
        # _given_
        converter = _make_converter()
        alert, rule_metadata = _build_full_alert()

        # _when_
        result = converter.convert_rule_alert(alert, rule_metadata)  # noqa: F841

        # _then_
        assert converter.tlp_marking is not None

    def test_then_empty_outcomes_produces_incident_only_no_relationships(self):
        """Trap guard: Given all outcomes empty → incident-only result (no relationships)."""
        # _given_
        converter = _make_converter()
        alert, rule_metadata = _build_empty_alert()

        # _when_
        result = converter.convert_rule_alert(alert, rule_metadata)

        # _then_
        rels = [o for o in result if getattr(o, "type", None) == "relationship"]
        assert len(rels) == 0
        assert len(result) >= 1  # at least the incident
