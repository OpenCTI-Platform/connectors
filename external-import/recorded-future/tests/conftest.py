import os
import sys
from typing import Any

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(name="full_settings_dict")
def fixture_full_settings_dict() -> dict[str, dict[str, Any]]:
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "name": "Test Connector",
            "scope": "test, connector",
            "log_level": "error",
            "duration_period": "PT1D",
        },
        "rf": {
            "token": "test-token",
            "initial_lookback": 48,
            "pull_analyst_notes": True,
            "last_published_notes": 24,
            "tlp": "amber+strict",
            "topic": "test-topic",
            "insikt_only": True,
            "pull_signatures": False,
            "person_to_ta": False,
            "ta_to_intrusion_set": False,
            "risk_as_score": False,
            "risk_threshold": 60,
            "analyst_notes_guess_relationships": False,
            "pull_risk_list": False,
            "riskrules_as_label": False,
            "risk_list_threshold": 70,
            "risklist_related_entities": "Malware,Threat Actor,MitreAttackIdentifier",
            "pull_threat_maps": False,
            "interval": 1,
        },
        "alert": {
            "enable": False,
            "default_opencti_severity": "low",
            "priority_alerts_only": False,
        },
        "playbook_alert": {
            "enable": False,
            "severity_threshold_domain_abuse": "High",
            "severity_threshold_identity_novel_exposures": "Moderate",
            "severity_threshold_code_repo_leakage": "High",
            "debug": False,
        },
    }


@pytest.fixture(name="minimal_settings_dict")
def fixture_minimal_settings_dict() -> dict[str, dict[str, Any]]:
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
        },
        "rf": {
            "token": "test-token",
        },
    }
