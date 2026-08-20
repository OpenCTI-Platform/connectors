from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import shodan
from connector import ConnectorSettings, ShodanConnector
from pycti import OpenCTIConnectorHelper


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


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "shodan": {
                    "token": "SecretStr",
                    "max_tlp": "TLP:CLEAR",
                    "default_score": 42,
                    "import_search_results": True,
                    "create_note": True,
                    "use_isp_name_for_asn": True,
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "test,connector"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto == True


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = ShodanConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper


def _make_connector():
    """Helper to build a ShodanConnector with mocked dependencies."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    helper.connector_logger = MagicMock()
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])
    helper.stix2_create_bundle = MagicMock(return_value='{"type":"bundle"}')
    connector = ShodanConnector(config=settings, helper=helper)
    return connector


def _make_enrichment_data():
    """Minimal enrichment data payload for an IPv4 observable."""
    return {
        "stix_objects": [],
        "stix_entity": {
            "type": "ipv4-addr",
            "value": "1.2.3.4",
            "id": "ipv4-addr--test",
        },
        "enrichment_entity": {
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:CLEAR"}]
        },
    }


class TestProcessMessageErrorHandling:
    """Integration tests: process_message gracefully skips all Shodan API errors."""

    def test_unknown_ip_does_not_crash_consumer(self, mock_opencti_connector_helper):
        connector = _make_connector()
        data = _make_enrichment_data()

        with patch.object(
            connector.shodanAPI,
            "host",
            side_effect=shodan.APIError("No information available for that IP."),
        ):
            connector.process_message(data)

        connector.helper.connector_logger.error.assert_called_once()
        connector.helper.send_stix2_bundle.assert_not_called()

    def test_access_denied_does_not_crash_consumer(self, mock_opencti_connector_helper):
        connector = _make_connector()
        data = _make_enrichment_data()

        with patch.object(
            connector.shodanAPI,
            "host",
            side_effect=shodan.APIError("Access denied"),
        ):
            connector.process_message(data)

        connector.helper.connector_logger.error.assert_called_once()
        connector.helper.send_stix2_bundle.assert_not_called()

    def test_any_api_error_is_skipped_with_message(self, mock_opencti_connector_helper):
        connector = _make_connector()
        data = _make_enrichment_data()

        with patch.object(
            connector.shodanAPI,
            "host",
            side_effect=shodan.APIError("Rate limit reached"),
        ):
            connector.process_message(data)

        connector.helper.connector_logger.error.assert_called_once()


def _make_indicator_enrichment_data():
    """Minimal enrichment data payload for a Shodan indicator."""
    return {
        "stix_objects": [],
        "stix_entity": {
            "type": "indicator",
            "pattern_type": "shodan",
            "pattern": "apache port:443",
            "id": "indicator--test",
        },
        "enrichment_entity": {
            "id": "enrichment--test",
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:CLEAR"}],
        },
    }


class TestProcessMessageIndicatorErrorHandling:
    """Integration tests: process_message gracefully skips Shodan API errors on indicator/shodan path."""

    def test_count_api_error_does_not_crash_consumer(
        self, mock_opencti_connector_helper
    ):
        connector = _make_connector()
        connector.helper.api = MagicMock()
        data = _make_indicator_enrichment_data()

        with patch.object(
            connector.shodanAPI,
            "count",
            side_effect=shodan.APIError("Access denied"),
        ):
            connector.process_message(data)

        connector.helper.connector_logger.error.assert_called_once()
        connector.helper.send_stix2_bundle.assert_not_called()

    def test_rate_limit_on_indicator_does_not_crash_consumer(
        self, mock_opencti_connector_helper
    ):
        connector = _make_connector()
        connector.helper.api = MagicMock()
        data = _make_indicator_enrichment_data()

        with patch.object(
            connector.shodanAPI,
            "count",
            side_effect=shodan.APIError("Rate limit reached"),
        ):
            connector.process_message(data)

        connector.helper.connector_logger.error.assert_called_once()
        connector.helper.send_stix2_bundle.assert_not_called()
