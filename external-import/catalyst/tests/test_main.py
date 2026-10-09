"""Tests wiring the Pydantic settings into the existing CATALYST connector code."""

from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from catalyst import CatalystConnector, ConnectorSettings
from catalyst.config_loader import ConfigConnector
from pycti import OpenCTIConnectorHelper

from .test_settings import FULL_VALID_SETTINGS_DICT, build_settings_class

PYCTI_MODULE_IMPORT_PATH = "pycti.connector.opencti_connector_helper"


@pytest.fixture(name="stub_connector_settings")
def fixture_stub_connector_settings() -> type[ConnectorSettings]:
    """Return a `ConnectorSettings` subclass loading a static, valid configuration."""
    return build_settings_class(FULL_VALID_SETTINGS_DICT)


@pytest.fixture(name="mock_opencti_connector_helper")
def fixture_mock_opencti_connector_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralize every `OpenCTIConnectorHelper` side effect (network, threads, signals)."""
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated(
    stub_connector_settings: type[ConnectorSettings],
) -> None:
    """`ConfigConnector` must expose its historical attributes from the Pydantic settings."""
    config = ConfigConnector(settings=stub_connector_settings())

    assert isinstance(config.settings, ConnectorSettings)
    assert isinstance(config.to_helper_config(), dict)

    assert config.duration_period == timedelta(minutes=60)
    assert config.api_base_url == "https://prod.blindspot.prodaft.com/api"
    assert config.api_key == "test-api-key"
    assert config.tlp_level == "white"
    assert config.tlp_filter == "AMBER,RED"
    assert config.category_filter == "RESEARCH"
    assert config.sync_days_back == 730
    assert config.create_observables is True
    assert config.create_indicators is False


def test_config_connector_handles_missing_api_key(
    stub_connector_settings: type[ConnectorSettings],
) -> None:
    """An unset `CATALYST_API_KEY` must be exposed as `None`, not as a `SecretStr`."""
    settings_without_api_key = build_settings_class(
        {
            **FULL_VALID_SETTINGS_DICT,
            "catalyst": {
                k: v
                for k, v in FULL_VALID_SETTINGS_DICT["catalyst"].items()
                if k != "api_key"
            },
        }
    )

    config = ConfigConnector(settings=settings_without_api_key())

    assert config.api_key is None


@pytest.mark.usefixtures("mock_opencti_connector_helper")
def test_opencti_connector_helper_is_instantiated(
    stub_connector_settings: type[ConnectorSettings],
) -> None:
    """`OpenCTIConnectorHelper` must be configurable from `to_helper_config()`."""
    config = ConfigConnector(settings=stub_connector_settings())

    helper = OpenCTIConnectorHelper(config=config.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-opencti-token"
    assert helper.connect_id == "d2107025-9f07-40c0-ae3d-373e01643256"
    assert helper.connect_name == "CATALYST"
    assert helper.connect_scope == "catalyst"
    assert helper.connect_type == "EXTERNAL_IMPORT"


@pytest.mark.usefixtures("mock_opencti_connector_helper")
def test_connector_is_instantiated(
    monkeypatch: pytest.MonkeyPatch,
    stub_connector_settings: type[ConnectorSettings],
) -> None:
    """`CatalystConnector` must build its config, helper and client from the settings."""
    monkeypatch.setattr(
        "catalyst.config_loader.ConnectorSettings", stub_connector_settings
    )
    monkeypatch.setattr("catalyst.client_api.CatalystClient", MagicMock())

    connector = CatalystConnector()

    assert isinstance(connector.config, ConfigConnector)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_name == "CATALYST"
    assert connector.client.config is connector.config
    assert connector.client.helper is connector.helper
