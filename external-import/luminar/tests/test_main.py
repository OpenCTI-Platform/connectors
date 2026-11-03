from unittest.mock import MagicMock

import pytest
from luminar_connector import ConnectorLuminar
from luminar_connector.config_loader import LUMINAR_BASE_URL, ConfigConnector
from luminar_connector.converter_to_stix import ConverterToStix
from luminar_connector.luminar_manager import LuminarManager
from pycti import OpenCTIConnectorHelper

CONFIG = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "connector-id",
        "type": "EXTERNAL_IMPORT",
        "name": "Test Connector",
        "scope": "test,connector",
        "log_level": "error",
        "duration_period": "PT5M",
    },
    "luminar": {
        "base_url": "https://luminar.test",
        "account_id": "account-id",
        "client_id": "client-id",
        "client_secret": "client-secret",
        "initial_fetch_date": "2026-01-01",
        "create_observable": True,
        "mask_credentials": True,
    },
}

ENV_VARS = [
    "OPENCTI_URL",
    "OPENCTI_TOKEN",
    "CONNECTOR_ID",
    "CONNECTOR_NAME",
    "CONNECTOR_SCOPE",
    "CONNECTOR_LOG_LEVEL",
    "CONNECTOR_DURATION_PERIOD",
    "LUMINAR_BASE_URL",
    "LUMINAR_ACCOUNT_ID",
    "LUMINAR_CLIENT_ID",
    "LUMINAR_CLIENT_SECRET",
    "LUMINAR_INITIAL_FETCH_DATE",
    "LUMINAR_CREATE_OBSERVABLE",
    "LUMINAR_MASK_CREDENTIALS",
]


@pytest.fixture
def config_dict(monkeypatch):
    """Serve CONFIG instead of src/config.yml and isolate from env vars."""
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    config = {section: dict(values) for section, values in CONFIG.items()}
    monkeypatch.setattr(ConfigConnector, "_load_config", staticmethod(lambda: config))
    return config


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def test_config_connector_reads_config(config_dict):
    config = ConfigConnector()

    assert config.load == config_dict
    assert config.duration_period == "PT5M"
    assert config.luminar_base_url == "https://luminar.test"
    assert config.luminar_account_id == "account-id"
    assert config.luminar_client_id == "client-id"
    assert config.luminar_client_secret == "client-secret"
    assert config.initial_fetch_date == "2026-01-01"
    assert config.create_observable is True
    assert config.mask_credentials is True


def test_config_connector_defaults(config_dict):
    del config_dict["connector"]["duration_period"]
    for key in ("base_url", "create_observable", "mask_credentials"):
        del config_dict["luminar"][key]

    config = ConfigConnector()

    assert config.duration_period == "P1D"
    assert config.luminar_base_url == LUMINAR_BASE_URL
    assert config.create_observable is True
    assert config.mask_credentials is False


def test_config_connector_env_vars_override_file(config_dict, monkeypatch):
    monkeypatch.setenv("LUMINAR_MASK_CREDENTIALS", "false")
    monkeypatch.setenv("LUMINAR_CLIENT_ID", "env-client")

    config = ConfigConnector()

    assert config.mask_credentials is False
    assert config.luminar_client_id == "env-client"


@pytest.mark.parametrize(
    "missing", ["account_id", "client_id", "client_secret", "initial_fetch_date"]
)
def test_config_connector_requires_luminar_settings(config_dict, missing):
    del config_dict["luminar"][missing]

    with pytest.raises(ValueError, match="Missing required configuration"):
        ConfigConnector()


def test_config_connector_rejects_blank_required_setting(config_dict, monkeypatch):
    monkeypatch.setenv("LUMINAR_CLIENT_ID", "   ")

    with pytest.raises(ValueError, match="LUMINAR_CLIENT_ID"):
        ConfigConnector()


def test_config_connector_load_config_from_file(monkeypatch, tmp_path):
    """_load_config returns {} when no config.yml exists next to the package."""
    import luminar_connector.config_loader as config_loader

    fake_module_file = tmp_path / "pkg" / "config_loader.py"
    fake_module_file.parent.mkdir()
    monkeypatch.setattr(config_loader, "__file__", str(fake_module_file))
    assert ConfigConnector._load_config() == {}

    (tmp_path / "config.yml").write_text("luminar:\n  account_id: from-file\n")
    assert ConfigConnector._load_config() == {"luminar": {"account_id": "from-file"}}


def test_opencti_connector_helper_is_instantiated(
    config_dict, mock_opencti_connector_helper
):
    helper = OpenCTIConnectorHelper(config=ConfigConnector().load)

    assert helper.opencti_url.rstrip("/") == "http://localhost:8080"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"


def test_connector_is_instantiated(config_dict, mock_opencti_connector_helper):
    connector = ConnectorLuminar()

    assert isinstance(connector.config, ConfigConnector)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.duration_period == "PT5M"
    assert connector.initial_fetch_date == "2026-01-01T00:00:00.000000Z"
    assert isinstance(connector.converter, ConverterToStix)
    assert connector.converter.create_observable is True
    assert connector.converter.mask_credentials is True
    assert isinstance(connector.client, LuminarManager)
    assert connector.client.base_url == "https://luminar.test"
    assert connector.client.added_after == "2026-01-01T00:00:00.000000Z"


def test_connector_rejects_invalid_initial_fetch_date(
    config_dict, mock_opencti_connector_helper
):
    config_dict["luminar"]["initial_fetch_date"] = "01/01/2026"

    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        ConnectorLuminar()
