from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector import MicrosoftDefenderIncidentsConnector

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

_BASE_ALERT = {
    "title": "Malware Detected",
    "createdDateTime": "2024-01-15T10:30:00Z",
    "lastUpdateDateTime": "2024-01-15T11:00:00Z",
    "category": "malware",
    "description": "Test description",
    "recommendedActions": "Isolate device",
    "alertWebUrl": "https://defender.microsoft.com/alert/123",
    "id": "alert-123",
    "severity": "high",
    "mitreTechniques": [],
    "evidence": [],
}

_BASE_INCIDENT = {
    "displayName": "Test Case Incident",
    "createdDateTime": "2024-01-15T10:00:00Z",
    "classification": "truePositive",
    "determination": "malware",
    "severity": "high",
    "id": "incident-123",
    "incidentWebUrl": "https://defender.microsoft.com/incident/123",
    "lastUpdateDateTime": "2024-01-15T12:00:00Z",
    "alerts": [_BASE_ALERT],
}


# ---------------------------------------------------------------------------
# Fixture: connector with real converter but mocked client
# ---------------------------------------------------------------------------


@pytest.fixture
def connector(mock_helper, mock_config):
    conn = MicrosoftDefenderIncidentsConnector(config=mock_config, helper=mock_helper)
    conn.client = MagicMock()
    return conn


# ---------------------------------------------------------------------------
# _get_last_incident_date
# ---------------------------------------------------------------------------


def test_get_last_incident_date_from_state(connector):
    connector.helper.get_state.return_value = {"last_incident_timestamp": 1704067200}
    result = connector._get_last_incident_date()
    assert result == 1704067200


def test_get_last_incident_date_from_import_start_date(connector, mock_config):
    connector.helper.get_state.return_value = None
    dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
    mock_config.microsoft_defender_incidents.import_start_date = dt
    result = connector._get_last_incident_date()
    assert result == int(dt.timestamp())


# ---------------------------------------------------------------------------
# _set_last_incident_date
# ---------------------------------------------------------------------------


def test_set_last_incident_date_merges_with_existing_state(connector):
    connector.helper.get_state.return_value = {"other_key": "value"}
    connector._set_last_incident_date(1704067200)
    connector.helper.set_state.assert_called_once_with(
        {"other_key": "value", "last_incident_timestamp": 1704067200}
    )


def test_set_last_incident_date_creates_new_state_when_none(connector):
    connector.helper.get_state.return_value = None
    connector._set_last_incident_date(1704067200)
    connector.helper.set_state.assert_called_once_with(
        {"last_incident_timestamp": 1704067200}
    )


# ---------------------------------------------------------------------------
# _extract_intelligence
# ---------------------------------------------------------------------------


def test_extract_intelligence_basic_incident(connector):
    stix_objects = connector._extract_intelligence(_BASE_INCIDENT)
    # At minimum: 1 stix_incident + 1 case
    assert len(stix_objects) >= 2


def test_extract_intelligence_with_mitre_technique(connector):
    incident = {
        **_BASE_INCIDENT,
        "alerts": [{**_BASE_ALERT, "mitreTechniques": ["T1059"]}],
    }
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "attack-pattern" in types
    assert "relationship" in types


def test_extract_intelligence_user_evidence(connector):
    evidence = {
        "@odata.type": "#microsoft.graph.security.userEvidence",
        "userAccount": {"accountName": "testuser", "displayName": "Test User"},
    }
    incident = {**_BASE_INCIDENT, "alerts": [{**_BASE_ALERT, "evidence": [evidence]}]}
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "user-account" in types


def test_extract_intelligence_ipv4_evidence(connector):
    evidence = {
        "@odata.type": "#microsoft.graph.security.ipEvidence",
        "ipAddress": "192.168.1.100",
    }
    incident = {**_BASE_INCIDENT, "alerts": [{**_BASE_ALERT, "evidence": [evidence]}]}
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "ipv4-addr" in types


def test_extract_intelligence_ipv6_evidence(connector):
    evidence = {
        "@odata.type": "#microsoft.graph.security.ipEvidence",
        "ipAddress": "2001:db8::1",
    }
    incident = {**_BASE_INCIDENT, "alerts": [{**_BASE_ALERT, "evidence": [evidence]}]}
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "ipv6-addr" in types


def test_extract_intelligence_ip_evidence_no_address_skipped(connector):
    evidence = {
        "@odata.type": "#microsoft.graph.security.ipEvidence",
        "ipAddress": None,
    }
    incident = {**_BASE_INCIDENT, "alerts": [{**_BASE_ALERT, "evidence": [evidence]}]}
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "ipv4-addr" not in types
    assert "ipv6-addr" not in types


def test_extract_intelligence_url_evidence(connector):
    evidence = {
        "@odata.type": "#microsoft.graph.security.urlEvidence",
        "url": "http://malicious.example.com",
    }
    incident = {**_BASE_INCIDENT, "alerts": [{**_BASE_ALERT, "evidence": [evidence]}]}
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "url" in types


def test_extract_intelligence_device_evidence(connector):
    evidence = {
        "@odata.type": "#microsoft.graph.security.deviceEvidence",
        "deviceDnsName": "workstation.example.com",
    }
    incident = {**_BASE_INCIDENT, "alerts": [{**_BASE_ALERT, "evidence": [evidence]}]}
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "identity" in types


def test_extract_intelligence_device_evidence_no_dns(connector):
    evidence = {
        "@odata.type": "#microsoft.graph.security.deviceEvidence",
        "deviceDnsName": None,
    }
    incident = {**_BASE_INCIDENT, "alerts": [{**_BASE_ALERT, "evidence": [evidence]}]}
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "identity" not in types


def test_extract_intelligence_file_evidence(connector):
    evidence = {
        "@odata.type": "#microsoft.graph.security.fileEvidence",
        "fileDetails": {
            "fileName": "malware.exe",
            "md5": "a" * 32,
            "sha256": "b" * 64,
            "filePath": "C:\\temp",
            "fileSize": 1024,
        },
    }
    incident = {**_BASE_INCIDENT, "alerts": [{**_BASE_ALERT, "evidence": [evidence]}]}
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "file" in types


def test_extract_intelligence_file_hash_evidence(connector):
    evidence = {
        "@odata.type": "#microsoft.graph.security.fileHashEvidence",
        "value": "c" * 64,
        "algorithm": "SHA-256",
    }
    incident = {**_BASE_INCIDENT, "alerts": [{**_BASE_ALERT, "evidence": [evidence]}]}
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "file" in types


def test_extract_intelligence_malware_evidence_no_files(connector):
    evidence = {
        "@odata.type": "#microsoft.graph.security.malwareEvidence",
        "name": "WannaCry",
        "createdDateTime": "2024-01-15T10:30:00Z",
        "category": ["ransomware"],
        "files": [],
    }
    incident = {**_BASE_INCIDENT, "alerts": [{**_BASE_ALERT, "evidence": [evidence]}]}
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "malware" in types


def test_extract_intelligence_malware_evidence_with_matching_file(connector):
    file_evidence = {
        "@odata.type": "#microsoft.graph.security.fileEvidence",
        "fileDetails": {
            "fileName": "wannacry.exe",
            "md5": "a" * 32,
            "filePath": "C:\\temp",
        },
    }
    malware_evidence = {
        "@odata.type": "#microsoft.graph.security.malwareEvidence",
        "name": "WannaCry",
        "createdDateTime": "2024-01-15T10:30:00Z",
        "category": ["ransomware"],
        "files": [{"fileDetails": {"fileName": "wannacry.exe"}}],
    }
    incident = {
        **_BASE_INCIDENT,
        "alerts": [{**_BASE_ALERT, "evidence": [file_evidence, malware_evidence]}],
    }
    stix_objects = connector._extract_intelligence(incident)
    types = [o.type for o in stix_objects if hasattr(o, "type")]
    assert "malware" in types
    assert "file" in types


# ---------------------------------------------------------------------------
# process_message
# ---------------------------------------------------------------------------


def test_process_message_no_incidents_skips_bundle(connector, mock_config):
    connector.helper.get_state.return_value = {"last_incident_timestamp": 1704067200}
    connector.client.get_incidents.return_value = []

    connector.process_message()

    connector.helper.connector_logger.info.assert_called()
    connector.helper.api.work.initiate_work.assert_not_called()


def test_process_message_no_last_timestamp(connector, mock_config):
    connector.helper.get_state.return_value = None
    mock_config.microsoft_defender_incidents.import_start_date = None
    connector.client.get_incidents.return_value = []

    connector.process_message()

    connector.helper.connector_logger.info.assert_called()


def test_process_message_with_incidents_sends_bundle(connector):
    connector.helper.get_state.return_value = {"last_incident_timestamp": 1704067200}
    connector.client.get_incidents.return_value = [_BASE_INCIDENT]
    connector.helper.api.work.initiate_work.return_value = "work-id-123"
    connector.helper.stix2_create_bundle.return_value = '{"type":"bundle"}'

    connector.process_message()

    connector.helper.api.work.initiate_work.assert_called_once()
    connector.helper.send_stix2_bundle.assert_called_once()
    connector.helper.api.work.to_processed.assert_called_once()


def test_process_message_exception_is_caught_and_logged(connector):
    connector.helper.get_state.return_value = None
    connector.client.set_oauth_token.side_effect = Exception("API failure")

    connector.process_message()

    connector.helper.connector_logger.error.assert_called()


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def test_run_calls_schedule_iso(connector, mock_config):
    connector.run()
    connector.helper.schedule_iso.assert_called_once_with(
        message_callback=connector.process_message,
        duration_period=mock_config.connector.duration_period,
    )
