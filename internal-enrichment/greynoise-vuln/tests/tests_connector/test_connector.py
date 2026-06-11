from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import stix2
from connector import ConnectorSettings, GreyNoiseVulnConnector
from pycti import OpenCTIConnectorHelper

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

CVE_DATA = {
    "id": "CVE-2021-44228",
    "details": {
        "vulnerability_description": "Apache Log4j RCE vulnerability",
        "product": "Log4j",
        "vendor": "Apache",
        "cve_cvss_score": 10.0,
    },
    "exploitation_details": {
        "attack_vector": "NETWORK",
        "epss_score": 0.97,
    },
    "exploitation_activity": {
        "activity_seen": True,
        "benign_ip_count_1d": 5,
        "benign_ip_count_10d": 50,
        "benign_ip_count_30d": 150,
        "threat_ip_count_1d": 100,
        "threat_ip_count_10d": 1000,
        "threat_ip_count_30d": 3000,
    },
    "exploitation_stats": {
        "number_of_available_exploits": 5,
        "number_of_threat_actors_exploiting_vulnerability": 3,
    },
    "timeline": {
        "cisa_kev_date_added": "2021-12-10",
    },
}

CVE_DATA_NO_KEV = {
    **CVE_DATA,
    "timeline": {"cisa_kev_date_added": None},
}

STIX_ENTITY = {
    "id": "vulnerability--a3f01b08-bf52-4b42-97e5-a1b2c3d4e5f6",
    "name": "CVE-2021-44228",
    "type": "vulnerability",
}

OPENCTI_ENTITY_WHITE = {
    "objectMarking": [{"definition_type": "TLP", "definition": "TLP:WHITE"}],
}

OPENCTI_ENTITY_RED = {
    "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
}

OPENCTI_ENTITY_NO_TLP = {
    "objectMarking": [],
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock heavy pycti dependencies to avoid external API calls."""
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "vulnerability",
                    "log_level": "error",
                    "auto": True,
                },
                "greynoise_vuln": {
                    "key": "test-api-key",
                    "max_tlp": "TLP:AMBER",
                    "name": "GreyNoise Internet Scanner",
                    "description": "GreyNoise test description",
                },
            }
        )


@pytest.fixture
def connector(mock_opencti_connector_helper):
    """Return a GreyNoiseVulnConnector with a mocked helper."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    helper.connector_logger = MagicMock()
    helper.api = MagicMock()
    helper.listen = MagicMock()
    helper.stix2_create_bundle = MagicMock(return_value="<bundle>")
    helper.send_stix2_bundle = MagicMock(return_value=["sent"])
    return GreyNoiseVulnConnector(config=settings, helper=helper)


@pytest.fixture
def connector_with_identity(connector):
    """Return a connector with greynoise_identity pre-generated."""
    connector.stix_objects = []
    connector._generate_greynoise_stix_identity()
    return connector


# ---------------------------------------------------------------------------
# _extract_and_check_markings
# ---------------------------------------------------------------------------


def test_extract_and_check_markings_valid_tlp(connector):
    """Valid TLP (WHITE <= AMBER) should not raise."""
    connector._extract_and_check_markings(OPENCTI_ENTITY_WHITE)  # no exception


def test_extract_and_check_markings_invalid_tlp_raises(connector):
    """TLP:RED exceeds max TLP:AMBER — must raise ValueError."""
    with pytest.raises(
        ValueError, match="TLP of the observable is greater than MAX TLP"
    ):
        connector._extract_and_check_markings(OPENCTI_ENTITY_RED)


def test_extract_and_check_markings_no_tlp_marking(connector):
    """Entity with no TLP marking falls back to default — should not raise."""
    connector._extract_and_check_markings(OPENCTI_ENTITY_NO_TLP)


# ---------------------------------------------------------------------------
# _generate_stix_relationship
# ---------------------------------------------------------------------------


def test_generate_stix_relationship(connector_with_identity):
    """Relationship is created with deterministic ID and no stop_time."""
    rel = connector_with_identity._generate_stix_relationship(
        source_ref="software--a3f01b08-bf52-4b42-97e5-a1b2c3d4e5f6",
        stix_core_relationship_type="related-to",
        target_ref="identity--b4e1c209-cf63-4c53-87f6-a1b2c3d4e5f6",
    )
    assert isinstance(rel, stix2.Relationship)
    assert rel.relationship_type == "related-to"
    assert not hasattr(rel, "stop_time") or rel.get("stop_time") is None


def test_generate_stix_relationship_with_start_time(connector_with_identity):
    rel = connector_with_identity._generate_stix_relationship(
        source_ref="software--a3f01b08-bf52-4b42-97e5-a1b2c3d4e5f6",
        stix_core_relationship_type="has",
        target_ref="identity--b4e1c209-cf63-4c53-87f6-a1b2c3d4e5f6",
        start_time="2021-01-01T00:00:00Z",
    )
    assert rel.start_time is not None


# ---------------------------------------------------------------------------
# _create_custom_label
# ---------------------------------------------------------------------------


def test_create_custom_label_success(connector):
    """Label is appended to all_labels when API returns it."""
    connector.all_labels = []
    connector.helper.api.label.read_or_create_unchecked.return_value = {
        "value": "gn-test-label"
    }
    connector._create_custom_label("gn-test-label", "#ff0000")
    assert "gn-test-label" in connector.all_labels


def test_create_custom_label_api_returns_none(connector):
    """When API returns None, an error is logged and label is not appended."""
    connector.all_labels = []
    connector.helper.api.label.read_or_create_unchecked.return_value = None
    connector._create_custom_label("gn-test-label", "#ff0000")
    assert connector.all_labels == []
    connector.helper.connector_logger.error.assert_called_once()


# ---------------------------------------------------------------------------
# _get_match
# ---------------------------------------------------------------------------


def test_get_match_found():
    result = GreyNoiseVulnConnector._get_match([{"key": "a"}, {"key": "b"}], "key", "b")
    assert result == {"key": "b"}


def test_get_match_not_found():
    result = GreyNoiseVulnConnector._get_match([{"key": "a"}], "key", "z")
    assert result is None


# ---------------------------------------------------------------------------
# _process_labels
# ---------------------------------------------------------------------------


def test_process_labels_all_active(connector):
    connector.helper.api.label.read_or_create_unchecked.return_value = MagicMock(
        __getitem__=lambda self, k: "label"
    )
    connector.helper.api.label.read_or_create_unchecked.side_effect = [
        {"value": "gn-activity-seen"},
        {"value": "gn-exploits-available"},
        {"value": "gn-threat-actors-exploiting"},
    ]
    labels = connector._process_labels(CVE_DATA)
    assert "gn-activity-seen" in labels
    assert "gn-exploits-available" in labels
    assert "gn-threat-actors-exploiting" in labels


def test_process_labels_no_exploitation_activity(connector):
    connector.helper.api.label.read_or_create_unchecked.return_value = None
    data = {
        "exploitation_activity": {"activity_seen": False},
        "exploitation_stats": {
            "number_of_available_exploits": 0,
            "number_of_threat_actors_exploiting_vulnerability": 0,
        },
    }
    labels = connector._process_labels(data)
    assert labels == []


def test_process_labels_missing_keys(connector):
    """Data missing optional keys should not raise."""
    labels = connector._process_labels({})
    assert labels == []


# ---------------------------------------------------------------------------
# _generate_stix_external_reference
# ---------------------------------------------------------------------------


def test_generate_stix_external_reference(connector_with_identity):
    refs = connector_with_identity._generate_stix_external_reference(CVE_DATA)
    assert len(refs) == 1
    assert refs[0].external_id == "CVE-2021-44228"
    assert "viz.greynoise.io" in refs[0].url


# ---------------------------------------------------------------------------
# _generate_stix_note
# ---------------------------------------------------------------------------


def test_generate_stix_note(connector_with_identity):
    initial_count = len(connector_with_identity.stix_objects)
    connector_with_identity._generate_stix_note(STIX_ENTITY, CVE_DATA)
    assert len(connector_with_identity.stix_objects) == initial_count + 1
    note = connector_with_identity.stix_objects[-1]
    assert note.type == "note"
    assert "GreyNoise Vulnerability" in note.content


# ---------------------------------------------------------------------------
# _generate_stix_software
# ---------------------------------------------------------------------------


def test_generate_stix_software(connector_with_identity):
    initial_count = len(connector_with_identity.stix_objects)
    connector_with_identity._generate_stix_software(STIX_ENTITY, CVE_DATA)
    # Adds: identity (vendor), software, 2 relationships
    assert len(connector_with_identity.stix_objects) == initial_count + 4


def test_generate_stix_software_empty_product_vendor(connector_with_identity):
    """Empty product/vendor strings should be replaced with 'Unknown'."""
    data = {
        **CVE_DATA,
        "details": {**CVE_DATA["details"], "product": "", "vendor": ""},
    }
    connector_with_identity._generate_stix_software(STIX_ENTITY, data)
    names = [
        obj.get("name", "")
        for obj in connector_with_identity.stix_objects
        if obj.get("type") == "software"
    ]
    assert any("Unknown" in n for n in names)


# ---------------------------------------------------------------------------
# _generate_greynoise_stix_identity
# ---------------------------------------------------------------------------


def test_generate_greynoise_stix_identity(connector):
    connector.stix_objects = []
    connector._generate_greynoise_stix_identity()
    assert hasattr(connector, "greynoise_identity")
    assert connector.greynoise_identity.name == "GreyNoise Internet Scanner"
    assert len(connector.stix_objects) == 1


# ---------------------------------------------------------------------------
# _generate_stix_vulnerability
# ---------------------------------------------------------------------------


def test_generate_stix_vulnerability(connector_with_identity):
    initial_count = len(connector_with_identity.stix_objects)
    connector_with_identity._generate_stix_vulnerability(CVE_DATA, [], [])
    assert len(connector_with_identity.stix_objects) == initial_count + 1
    vuln = connector_with_identity.stix_objects[-1]
    assert vuln.name == "CVE-2021-44228"


def test_generate_stix_vulnerability_kev_false(connector_with_identity):
    connector_with_identity._generate_stix_vulnerability(CVE_DATA_NO_KEV, [], [])
    vuln = connector_with_identity.stix_objects[-1]
    assert vuln.get("x_opencti_cisa_kev") is False


def test_generate_stix_vulnerability_kev_true(connector_with_identity):
    connector_with_identity._generate_stix_vulnerability(CVE_DATA, [], [])
    vuln = connector_with_identity.stix_objects[-1]
    assert vuln.get("x_opencti_cisa_kev") is True


# ---------------------------------------------------------------------------
# _generate_stix_bundle
# ---------------------------------------------------------------------------


def test_generate_stix_bundle(connector_with_identity):
    connector_with_identity.helper.api.label.read_or_create_unchecked.side_effect = [
        {"value": "gn-activity-seen"},
        {"value": "gn-exploits-available"},
        {"value": "gn-threat-actors-exploiting"},
    ]
    bundle = connector_with_identity._generate_stix_bundle(CVE_DATA, STIX_ENTITY)
    assert bundle == "<bundle>"
    connector_with_identity.helper.stix2_create_bundle.assert_called_once()


# ---------------------------------------------------------------------------
# _process_message — in scope
# ---------------------------------------------------------------------------


def _make_message_data(entity_type="vulnerability", event_type=None, stix_objects=None):
    data = {
        "entity_id": f"{entity_type}--00000000-0000-0000-0000-000000000001",
        "stix_entity": STIX_ENTITY,
        "enrichment_entity": OPENCTI_ENTITY_WHITE,
        "stix_objects": stix_objects or [],
    }
    if event_type is not None:
        data["event_type"] = event_type
    return data


def test_process_message_cve_found(connector):
    """In-scope entity with CVE data returns bundle sent message."""
    connector.helper.api.label.read_or_create_unchecked.return_value = None
    with patch("connector.connector.GreyNoise") as mock_gn_cls:
        mock_session = MagicMock()
        mock_session.cve.return_value = CVE_DATA
        mock_gn_cls.return_value = mock_session

        result = connector._process_message(_make_message_data())

    assert "stix bundle" in result.lower()
    connector.helper.send_stix2_bundle.assert_called_once()


def test_process_message_cve_not_found(connector):
    """'CVE not found' response sends original bundle back."""
    with patch("connector.connector.GreyNoise") as mock_gn_cls:
        mock_session = MagicMock()
        mock_session.cve.return_value = "CVE not found"
        mock_gn_cls.return_value = mock_session

        result = connector._process_message(_make_message_data())

    assert "No CVE found" in result
    connector.helper.send_stix2_bundle.assert_called_once()


def test_process_message_invalid_tlp_raises(connector):
    """Entity with TLP:RED exceeding max TLP:AMBER raises ValueError."""
    data = _make_message_data()
    data["enrichment_entity"] = OPENCTI_ENTITY_RED
    with pytest.raises(ValueError, match="TLP of the observable"):
        connector._process_message(data)


def test_process_message_api_exception_raises(connector):
    """GreyNoise API exception is re-raised as ValueError."""
    with patch("connector.connector.GreyNoise") as mock_gn_cls:
        mock_session = MagicMock()
        mock_session.cve.side_effect = RuntimeError("API down")
        mock_gn_cls.return_value = mock_session

        with pytest.raises(ValueError, match="Unexpected Error"):
            connector._process_message(_make_message_data())


# ---------------------------------------------------------------------------
# _process_message — out of scope
# ---------------------------------------------------------------------------


def test_process_message_out_of_scope_no_event_type_sends_bundle(connector):
    """Out-of-scope without event_type sends original bundle back."""
    data = _make_message_data(entity_type="indicator")
    result = connector._process_message(data)
    assert "Not in scope" in result
    connector.helper.send_stix2_bundle.assert_called_once()


def test_process_message_out_of_scope_with_event_type_skips_bundle(connector):
    """Out-of-scope with event_type set should NOT send a bundle."""
    data = _make_message_data(entity_type="indicator", event_type="create")
    connector._process_message(data)
    connector.helper.send_stix2_bundle.assert_not_called()


# ---------------------------------------------------------------------------
# process_message (public wrapper) — error handling
# ---------------------------------------------------------------------------


def test_process_message_public_logs_and_reraises_on_error(connector):
    """process_message catches exceptions, logs, sends original bundle, re-raises."""
    data = _make_message_data()
    data["enrichment_entity"] = OPENCTI_ENTITY_RED  # triggers ValueError inside

    with pytest.raises(Exception):
        connector.process_message(data)

    connector.helper.connector_logger.error.assert_called_once()
    connector.helper.send_stix2_bundle.assert_called_once()


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def test_run_calls_listen(connector):
    connector.run()
    connector.helper.listen.assert_called_once_with(
        message_callback=connector.process_message
    )
