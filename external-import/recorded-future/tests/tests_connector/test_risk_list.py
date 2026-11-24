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


# ── Tests for RiskList.run() state handling ───────────────────────────────────


# Scenario: keys saved by other modules while the risk lists run are kept
def test_run_keeps_state_keys_saved_by_other_modules_meanwhile():
    helper = _mock_helper()
    state_at_start = {
        "last_risk_lists_run": "2026-11-01 00:00:00",
        "last_analyst_notes_run": "2026-11-01 00:00:00",
    }
    # Analyst Notes and Threat Maps run in parallel threads and save the state
    # while the risk lists are being pulled.
    state_before_save = {
        "last_risk_lists_run": "2026-11-01 00:00:00",
        "last_analyst_notes_run": "2026-11-05 09:00:00",
        "last_threat_maps_run": "2026-11-05 09:00:00",
    }
    helper.get_state.side_effect = [state_at_start, state_before_save]
    risk_list = _build_risk_list(helper=helper)

    with patch("rflib.risk_list.RISK_LIST_TYPE_MAPPER", {}):
        risk_list.run()

    helper.connector_logger.error.assert_not_called()
    saved_state = helper.set_state.call_args.kwargs["state"]
    assert saved_state["last_analyst_notes_run"] == "2026-11-05 09:00:00"
    assert saved_state["last_threat_maps_run"] == "2026-11-05 09:00:00"
    assert saved_state["last_risk_lists_run"] != "2026-11-01 00:00:00"


# ── Tests for per-row error handling in RiskList.run() ───────────────────────


def _risk_list_row(name):
    return {
        "Name": name,
        "Risk": "80",
        "FirstSeen": "2025-01-01T00:00:00.000Z",
        "LastSeen": "2025-04-01T00:00:00.000Z",
        "RuleCriticality": "[3]",
        "RiskRules": '["Test Rule"]',
        "Links": "{}",
    }


def _mock_stix_obj():
    stix_obj = MagicMock()
    stix_obj.to_stix_bundle.return_value = MagicMock(
        objects=[1], serialize=MagicMock(return_value="{}")
    )
    return stix_obj


# Scenario: one row that fails to convert does not abort the rest of the risk list
def test_failing_row_is_skipped_and_remaining_rows_are_processed():
    helper = _mock_helper()
    risk_list = _build_risk_list(helper=helper)

    bad_obj = _mock_stix_obj()
    bad_obj.map_data.side_effect = KeyError("hits")
    good_obj = _mock_stix_obj()
    ip_mapper = {
        "IP": {
            "class": MagicMock(side_effect=[bad_obj, good_obj]),
            "path": "/public/opencti/default_ip.csv",
        }
    }
    rows = [_risk_list_row("1.1.1.1"), _risk_list_row("2.2.2.2")]

    with patch("rflib.risk_list.RISK_LIST_TYPE_MAPPER", ip_mapper), patch(
        "csv.DictReader", return_value=iter(rows)
    ):
        risk_list.run()

    # The good row is still sent and the run completes
    helper.send_stix2_bundle.assert_called_once()
    helper.api.work.to_processed.assert_called_once()
    helper.set_state.assert_called_once()
    assert "last_risk_lists_run" in helper.set_state.call_args.kwargs["state"]
    # The bad row is reported as a warning, not as a run-level error
    helper.connector_logger.warning.assert_called_once()
    assert "1.1.1.1" in str(helper.connector_logger.warning.call_args)
    helper.connector_logger.error.assert_not_called()


# Scenario: a row with malformed fields is skipped and the next row is still sent
@pytest.mark.parametrize(
    "bad_fields",
    [
        {"RuleCriticality": "[invalid]"},
        {"RuleCriticality": "[3,3]", "RiskRules": '["Only one rule"]'},
    ],
)
def test_row_with_malformed_fields_is_skipped_and_next_row_is_processed(bad_fields):
    helper = _mock_helper()
    risk_list = _build_risk_list(helper=helper)

    stix_class = MagicMock(return_value=_mock_stix_obj())
    ip_mapper = {"IP": {"class": stix_class, "path": "/public/opencti/default_ip.csv"}}
    rows = [
        {**_risk_list_row("1.1.1.1"), **bad_fields},
        _risk_list_row("2.2.2.2"),
    ]

    with patch("rflib.risk_list.RISK_LIST_TYPE_MAPPER", ip_mapper), patch(
        "csv.DictReader", return_value=iter(rows)
    ):
        risk_list.run()

    # Only the valid row is converted and sent, and the run completes
    stix_class.assert_called_once()
    assert stix_class.call_args.args[0] == "2.2.2.2"
    helper.send_stix2_bundle.assert_called_once()
    helper.set_state.assert_called_once()
    helper.connector_logger.warning.assert_called_once()
    assert "1.1.1.1" in str(helper.connector_logger.warning.call_args)
    helper.connector_logger.error.assert_not_called()


# ── Tests for the per risk list score thresholds ─────────────────────────────


def _vuln_row(name, risk):
    return {
        "Name": name,
        "Risk": risk,
        "FirstSeen": "2025-01-01T00:00:00.000Z",
        "LastSeen": "2025-04-01T00:00:00.000Z",
        "EvidenceDetails": "",
    }


def _run_ip_and_vuln_lists(
    risk_list_threshold, risk_list_thresholds, ip_rows, vuln_rows
):
    """Run the IP and the vulnerability risk lists, return the names converted per list."""
    helper = _mock_helper()
    rfapi = MagicMock()
    rfapi.check_vul_entitlement.return_value = True
    risk_list = RiskList(
        helper=helper,
        rfapi=rfapi,
        tlp="white",
        risk_list_threshold=risk_list_threshold,
        risklist_related_entities=[],
        riskrules_as_label=False,
        risk_list_thresholds=risk_list_thresholds,
    )
    ip_class = MagicMock(side_effect=lambda *args, **kwargs: _mock_stix_obj())
    vuln_class = MagicMock(side_effect=lambda *args, **kwargs: _mock_stix_obj())
    mapper = {
        "IpAddress": {"class": ip_class, "path": "/public/opencti/default_ip.csv"},
        "Vuln": {
            "class": vuln_class,
            "path": "/public/opencti/opencti_default_vulnerability_v2.csv",
        },
    }

    with patch("rflib.risk_list.RISK_LIST_TYPE_MAPPER", mapper), patch(
        "csv.DictReader", side_effect=[iter(ip_rows), iter(vuln_rows)]
    ):
        risk_list.run()

    helper.connector_logger.error.assert_not_called()
    ip_names = [call.args[0] for call in ip_class.call_args_list]
    vuln_names = [call.args[0] for call in vuln_class.call_args_list]
    return ip_names, vuln_names


def _ip_row(name, risk):
    return {**_risk_list_row(name), "Risk": risk}


# Scenario: a strict threshold for indicators and no filtering for vulnerabilities
def test_per_list_threshold_overrides_global_threshold_for_its_list_only():
    ip_names, vuln_names = _run_ip_and_vuln_lists(
        risk_list_threshold=70,
        risk_list_thresholds={"Vuln": 0},
        ip_rows=[_ip_row("1.1.1.1", "80"), _ip_row("2.2.2.2", "10")],
        vuln_rows=[_vuln_row("CVE-2025-0001", "80"), _vuln_row("CVE-2025-0002", "0")],
    )

    # The IP list keeps the global threshold of 70
    assert ip_names == ["1.1.1.1"]
    # The vulnerability list uses its own threshold of 0
    assert vuln_names == ["CVE-2025-0001", "CVE-2025-0002"]


# Scenario: a list without a threshold of its own uses the global threshold
@pytest.mark.parametrize("risk_list_thresholds", [None, {}, {"Vuln": None}])
def test_global_threshold_applies_when_list_has_no_threshold(risk_list_thresholds):
    _, vuln_names = _run_ip_and_vuln_lists(
        risk_list_threshold=70,
        risk_list_thresholds=risk_list_thresholds,
        ip_rows=[],
        vuln_rows=[_vuln_row("CVE-2025-0001", "70"), _vuln_row("CVE-2025-0002", "69")],
    )

    assert vuln_names == ["CVE-2025-0001"]


# Scenario: a list threshold stricter than the global one
def test_per_list_threshold_can_be_stricter_than_global_threshold():
    ip_names, vuln_names = _run_ip_and_vuln_lists(
        risk_list_threshold=None,
        risk_list_thresholds={"IpAddress": 90},
        ip_rows=[_ip_row("1.1.1.1", "95"), _ip_row("2.2.2.2", "89")],
        vuln_rows=[_vuln_row("CVE-2025-0001", "5")],
    )

    assert ip_names == ["1.1.1.1"]
    # No global threshold: the vulnerability list is not filtered
    assert vuln_names == ["CVE-2025-0001"]


# Scenario: a threshold of 0 also keeps rows with an empty or non-numeric risk
def test_zero_threshold_keeps_rows_without_numeric_risk():
    _, vuln_names = _run_ip_and_vuln_lists(
        risk_list_threshold=70,
        risk_list_thresholds={"Vuln": 0},
        ip_rows=[],
        vuln_rows=[_vuln_row("CVE-2025-0001", ""), _vuln_row("CVE-2025-0002", "n/a")],
    )

    assert vuln_names == ["CVE-2025-0001", "CVE-2025-0002"]


# Scenario: the filtered row is logged with its list, score and threshold
def test_row_below_threshold_is_logged_with_list_threshold():
    helper = _mock_helper()
    risk_list = RiskList(
        helper=helper,
        rfapi=MagicMock(),
        tlp="white",
        risk_list_threshold=70,
        risklist_related_entities=[],
        riskrules_as_label=False,
        risk_list_thresholds={"IpAddress": 90},
    )

    bundle = risk_list._row_to_bundle(
        _ip_row("1.1.1.1", "80"), "IpAddress", {"class": MagicMock()}, None
    )

    assert bundle is None
    helper.connector_logger.info.assert_called_once_with(
        "[RISK LIST] Ignoring object below the risk list threshold",
        meta={
            "name": "1.1.1.1",
            "risk_list": "IpAddress",
            "risk_score": 80,
            "risk_score_threshold": 90,
        },
    )
