"""Smoke tests for top-level instantiation: ConnectorSettings → helper → connector."""

from google_secops_siem_incidents import GoogleSecOpsConnector
from pycti import OpenCTIConnectorHelper
from test_helpers import make_stub_settings


# ---------------------------------------------------------------------------
# BDD helpers
# ---------------------------------------------------------------------------
def _given_stub_settings():
    """Return a ConnectorSettings instance backed by a valid full config."""
    return make_stub_settings()()


def _when_settings_instantiated(settings_cls):
    """Instantiate a settings class."""
    return settings_cls()


def _then_to_helper_config_is_dict_with_keys(settings):
    """Assert to_helper_config returns a dict with at least opencti and connector keys."""
    cfg = settings.to_helper_config()
    assert isinstance(cfg, dict)
    assert "opencti" in cfg
    assert "connector" in cfg


# ---------------------------------------------------------------------------
# Tests — Scenario: ConnectorSettings can be instantiated and returns a valid helper config dict
# ---------------------------------------------------------------------------
def test_connector_settings_is_instantiated():
    """ConnectorSettings can be instantiated and to_helper_config returns a dict with required keys."""
    settings = _given_stub_settings()
    _then_to_helper_config_is_dict_with_keys(settings)


# ---------------------------------------------------------------------------
# Tests — Scenario: OpenCTIConnectorHelper can be instantiated
# ---------------------------------------------------------------------------
def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """OpenCTIConnectorHelper can be built from ConnectorSettings.to_helper_config."""
    settings = _given_stub_settings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Google SecOps"
    assert helper.connect_scope == "google-secops-siem-incidents"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT1H"


# ---------------------------------------------------------------------------
# Tests — Scenario: GoogleSecOpsConnector can be instantiated
# ---------------------------------------------------------------------------
def test_connector_is_instantiated(mock_opencti_connector_helper):
    """GoogleSecOpsConnector can be instantiated with config and helper."""
    settings = _given_stub_settings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = GoogleSecOpsConnector(config=settings, helper=helper)

    assert connector.config is settings
    assert connector.helper is helper
