import json
from unittest.mock import MagicMock, patch

import pytest
from rflib.constants import RISK_RULES_MAPPER
from rflib.risk_list import RiskList

# ── Tests for RISK_RULES_MAPPER ───────────────────────────────────────────────


# Scenario: RISK_RULES_MAPPER contains all criticality levels 0 through 5
def test_risk_rules_mapper_contains_all_criticality_levels():
    expected_scores = [0, 1, 2, 3, 4, 5]
    actual_scores = [rule["rule_score"] for rule in RISK_RULES_MAPPER]
    assert actual_scores == expected_scores


# Scenario: Criticality level 5 is mapped to "Very Critical" with risk score "100"
def test_risk_rules_mapper_level_5_is_very_critical():
    level_5 = next(r for r in RISK_RULES_MAPPER if r["rule_score"] == 5)
    assert level_5["severity"] == "Very Critical"
    assert level_5["risk_score"] == "100"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _mock_helper():
    helper = MagicMock()
    helper.get_state.return_value = {}
    helper.connect_id = "test-id"
    helper.connect_name = "Test"
    helper.api.work.initiate_work.return_value = "work-1"
    return helper


def _build_risk_list(helper=None):
    if helper is None:
        helper = _mock_helper()
    rfapi = MagicMock()
    rfapi.check_vul_entitlement.return_value = True
    return RiskList(
        helper=helper,
        rfapi=rfapi,
        tlp="white",
        risk_list_threshold=None,
        risklist_related_entities=[],
        riskrules_as_label=True,
        ta_to_intrusion_set=False,
    )


# ── Tests for RiskList.run() Vuln processing ──────────────────────────────────


class TestRiskListRunVuln:
    """Tests exercising real RiskList.run() code for the Vuln branch."""

    def _run_vuln_with_evidences(self, evidences, helper=None):
        """Run the RiskList with a Vuln-type CSV containing given evidences."""
        if helper is None:
            helper = _mock_helper()

        risk_list = _build_risk_list(helper=helper)

        # Mock stix object returned by the class
        mock_stix_obj = MagicMock()
        mock_stix_obj.to_stix_bundle.return_value = MagicMock(
            objects=[1], serialize=MagicMock(return_value="{}")
        )

        evidence_json = json.dumps(evidences)
        # Build a proper CSV as list of strings for DictReader
        csv_rows = [
            {
                "Name": "CVE-2025-66376",
                "Risk": "99",
                "FirstSeen": "2025-01-01T00:00:00.000Z",
                "LastSeen": "2025-04-01T00:00:00.000Z",
                "EvidenceDetails": evidence_json,
            }
        ]

        # Patch RISK_LIST_TYPE_MAPPER to only include Vuln
        mock_class = MagicMock(return_value=mock_stix_obj)
        vuln_mapper = {
            "Vuln": {
                "class": mock_class,
                "path": "/public/opencti/opencti_default_vulnerability_v2.csv",
            }
        }

        with patch("rflib.risk_list.RISK_LIST_TYPE_MAPPER", vuln_mapper), patch(
            "csv.DictReader", return_value=iter(csv_rows)
        ):
            risk_list.run()

        return helper, mock_stix_obj

    # Scenario: Vuln with criticality 5 is matched and added to description/labels
    def test_vuln_criticality_5_matched(self):
        evidences = [
            {
                "rule": "Active Exploitation",
                "criticality": "5",
                "evidenceString": "Evidence of exploitation",
                "mitigationString": "Apply patch",
            }
        ]
        helper, mock_stix_obj = self._run_vuln_with_evidences(evidences)

        # Check description was added with "Very Critical"
        add_description_call = mock_stix_obj.add_description.call_args[0][0]
        assert "Very Critical" in add_description_call
        assert "Active Exploitation" in add_description_call

        # Check labels include the rule name
        add_labels_call = mock_stix_obj.add_labels.call_args[0][0]
        assert "Active Exploitation" in add_labels_call

    # Scenario: Vuln with all known criticality levels
    @pytest.mark.parametrize(
        "criticality,expected_severity",
        [
            (0, "No current evidence of risk"),
            (1, "Unusual"),
            (2, "Suspicious"),
            (3, "Malicious"),
            (4, "Very Malicious"),
            (5, "Very Critical"),
        ],
    )
    def test_vuln_all_known_criticality_levels(self, criticality, expected_severity):
        evidences = [
            {
                "rule": "Test Rule",
                "criticality": str(criticality),
                "evidenceString": "evidence",
                "mitigationString": "mitigation",
            }
        ]
        _, mock_stix_obj = self._run_vuln_with_evidences(evidences)

        add_description_call = mock_stix_obj.add_description.call_args[0][0]
        assert expected_severity in add_description_call

    # Scenario: Vuln with unknown criticality logs warning and still adds label
    def test_vuln_unknown_criticality_logs_warning_and_adds_label(self):
        helper = _mock_helper()
        evidences = [
            {
                "rule": "Unknown Rule",
                "criticality": "99",
                "evidenceString": "mystery",
                "mitigationString": "unknown",
            }
        ]
        helper, mock_stix_obj = self._run_vuln_with_evidences(evidences, helper=helper)

        # Warning was logged
        helper.connector_logger.warning.assert_called_once()
        warning_msg = helper.connector_logger.warning.call_args[0][0]
        assert "Unknown criticality level: 99" in warning_msg
        assert "Unknown Rule" in warning_msg

        # Label is still added as fallback
        add_labels_call = mock_stix_obj.add_labels.call_args[0][0]
        assert "Unknown Rule" in add_labels_call

    # Scenario: Vuln with mixed known and unknown criticalities
    def test_vuln_mixed_known_and_unknown(self):
        helper = _mock_helper()
        evidences = [
            {
                "rule": "Known Rule",
                "criticality": "3",
                "evidenceString": "known",
                "mitigationString": "fix",
            },
            {
                "rule": "Future Rule",
                "criticality": "10",
                "evidenceString": "future",
                "mitigationString": "tbd",
            },
        ]
        helper, mock_stix_obj = self._run_vuln_with_evidences(evidences, helper=helper)

        add_description_call = mock_stix_obj.add_description.call_args[0][0]
        assert "Malicious" in add_description_call
        assert "Known Rule" in add_description_call

        add_labels_call = mock_stix_obj.add_labels.call_args[0][0]
        assert "Known Rule" in add_labels_call
        assert "Future Rule" in add_labels_call

        helper.connector_logger.warning.assert_called_once()

    # Scenario: Vuln with empty EvidenceDetails
    def test_vuln_empty_evidence_details(self):
        helper = _mock_helper()
        risk_list = _build_risk_list(helper=helper)

        mock_stix_obj = MagicMock()
        mock_stix_obj.to_stix_bundle.return_value = MagicMock(
            objects=[1], serialize=MagicMock(return_value="{}")
        )

        csv_rows = [
            {
                "Name": "CVE-2025-00001",
                "Risk": "50",
                "FirstSeen": "2025-01-01T00:00:00.000Z",
                "LastSeen": "2025-04-01T00:00:00.000Z",
                "EvidenceDetails": "",
            }
        ]

        mock_class = MagicMock(return_value=mock_stix_obj)
        vuln_mapper = {
            "Vuln": {
                "class": mock_class,
                "path": "/public/opencti/opencti_default_vulnerability_v2.csv",
            }
        }

        with patch("rflib.risk_list.RISK_LIST_TYPE_MAPPER", vuln_mapper), patch(
            "csv.DictReader", return_value=iter(csv_rows)
        ):
            risk_list.run()

        add_labels_call = mock_stix_obj.add_labels.call_args[0][0]
        assert add_labels_call == []


# ── Tests for RiskList.run() non-Vuln processing ─────────────────────────────


class TestRiskListRunNonVuln:
    """Tests exercising real RiskList.run() code for the non-Vuln branch."""

    def _run_non_vuln_with_rules(self, rule_criticality, risk_rules, helper=None):
        """Run RiskList with a non-Vuln type CSV."""
        if helper is None:
            helper = _mock_helper()

        risk_list = _build_risk_list(helper=helper)

        mock_stix_obj = MagicMock()
        mock_stix_obj.to_stix_bundle.return_value = MagicMock(
            objects=[1], serialize=MagicMock(return_value="{}")
        )

        csv_rows = [
            {
                "Name": "1.2.3.4",
                "Risk": "80",
                "FirstSeen": "2025-01-01T00:00:00.000Z",
                "LastSeen": "2025-04-01T00:00:00.000Z",
                "RuleCriticality": rule_criticality,
                "RiskRules": risk_rules,
            }
        ]

        mock_class = MagicMock(return_value=mock_stix_obj)
        ip_mapper = {
            "IpAddress": {
                "class": mock_class,
                "path": "/public/opencti/default_ip.csv",
            }
        }

        with patch("rflib.risk_list.RISK_LIST_TYPE_MAPPER", ip_mapper), patch(
            "csv.DictReader", return_value=iter(csv_rows)
        ):
            risk_list.run()

        return helper, mock_stix_obj

    # Scenario: Non-Vuln with criticality 5 is properly matched
    def test_non_vuln_criticality_5_matched(self):
        _, mock_stix_obj = self._run_non_vuln_with_rules(
            "[5]", '["Critical Exploit Rule"]'
        )

        add_description_call = mock_stix_obj.add_description.call_args[0][0]
        assert "Very Critical" in add_description_call
        assert "100" in add_description_call
        assert "Critical Exploit Rule" in add_description_call

        add_labels_call = mock_stix_obj.add_labels.call_args[0][0]
        assert "Critical Exploit Rule" in add_labels_call

    # Scenario: Non-Vuln all known criticality levels
    @pytest.mark.parametrize(
        "criticality,expected_severity,expected_risk_score",
        [
            ("0", "No current evidence of risk", "0"),
            ("1", "Unusual", "5-24"),
            ("2", "Suspicious", "25-64"),
            ("3", "Malicious", "65-89"),
            ("4", "Very Malicious", "90-99"),
            ("5", "Very Critical", "100"),
        ],
    )
    def test_non_vuln_all_known_criticality_levels(
        self, criticality, expected_severity, expected_risk_score
    ):
        _, mock_stix_obj = self._run_non_vuln_with_rules(
            f"[{criticality}]", '["Test Rule"]'
        )

        add_description_call = mock_stix_obj.add_description.call_args[0][0]
        assert expected_severity in add_description_call
        assert expected_risk_score in add_description_call

    # Scenario: Non-Vuln unknown criticality logs warning and still adds label
    def test_non_vuln_unknown_criticality_logs_warning(self):
        helper = _mock_helper()
        helper, mock_stix_obj = self._run_non_vuln_with_rules(
            "[42]", '["Mystery Rule"]', helper=helper
        )

        helper.connector_logger.warning.assert_called_once()
        warning_msg = helper.connector_logger.warning.call_args[0][0]
        assert "Unknown criticality level: 42" in warning_msg
        assert "Mystery Rule" in warning_msg

        add_labels_call = mock_stix_obj.add_labels.call_args[0][0]
        assert "Mystery Rule" in add_labels_call

    # Scenario: Non-Vuln mixed known and unknown criticalities
    def test_non_vuln_mixed_known_and_unknown(self):
        helper = _mock_helper()
        helper, mock_stix_obj = self._run_non_vuln_with_rules(
            "[3,5,99]", '["Rule A","Rule B","Rule C"]', helper=helper
        )

        add_labels_call = mock_stix_obj.add_labels.call_args[0][0]
        assert "Rule A" in add_labels_call
        assert "Rule B" in add_labels_call
        assert "Rule C" in add_labels_call

        add_description_call = mock_stix_obj.add_description.call_args[0][0]
        assert "Malicious" in add_description_call
        assert "Very Critical" in add_description_call

        helper.connector_logger.warning.assert_called_once()

    # Scenario: Non-Vuln empty criticality defaults to 0
    def test_non_vuln_empty_criticality_defaults_to_zero(self):
        _, mock_stix_obj = self._run_non_vuln_with_rules("[]", '["No Score Rule"]')

        add_description_call = mock_stix_obj.add_description.call_args[0][0]
        assert "No current evidence of risk" in add_description_call

        add_labels_call = mock_stix_obj.add_labels.call_args[0][0]
        assert "No Score Rule" in add_labels_call
