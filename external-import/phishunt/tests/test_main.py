from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests
import stix2
from connector import ConnectorSettings, Phishunt
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
                    "duration_period": "PT5M",
                },
                "phishunt": {
                    "api_key": "SecretStr",
                    "create_indicators": True,
                    "default_x_opencti_score": 42,
                    "x_opencti_score_domain": 42,
                    "x_opencti_score_ip": 42,
                    "x_opencti_score_url": 42,
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
    assert helper.connect_duration_period == "PT5M"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = Phishunt(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper


# ──────────────────────────────────────────────────────────────
# Helpers for _process_feed tests
# ──────────────────────────────────────────────────────────────
def _make_connector(mock_helper_fixture) -> Phishunt:  # noqa: ARG001
    """Return a ready-to-use Phishunt connector with a fully mocked helper.

    ``send_stix2_bundle``, ``stix2_create_bundle``, and ``connector_logger`` are
    replaced with MagicMocks to avoid real network/RabbitMQ calls in tests.
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    connector = Phishunt(config=settings, helper=helper)
    connector.helper.send_stix2_bundle = MagicMock()
    connector.helper.stix2_create_bundle = MagicMock(return_value='{"type": "bundle"}')
    connector.helper.connector_logger = MagicMock()
    return connector


def _mock_response(data: list) -> MagicMock:
    """Build a mock requests.Response whose .json() returns *data*."""
    resp = MagicMock()
    resp.json.return_value = data
    resp.raise_for_status.return_value = None
    return resp


def _entry(
    url="http://evil.com/phish",
    domain="evil.com",
    company="evilcorp",
    ip="1.2.3.4",
    country="US",
) -> dict:
    return {"url": url, "domain": domain, "company": company, "ip": ip, "country": country}


# ──────────────────────────────────────────────────────────────
# Tests — _process_feed
# ──────────────────────────────────────────────────────────────
class TestProcessFeed:
    def test_full_entry_sends_one_bundle(self, mock_opencti_connector_helper):
        """A complete entry triggers exactly one bundle send."""
        connector = _make_connector(mock_opencti_connector_helper)
        with patch("connector.connector.requests.get", return_value=_mock_response([_entry()])):
            connector._process_feed("work-id")
        assert connector.helper.send_stix2_bundle.call_count == 1

    def test_full_entry_bundle_contains_all_stix_types(self, mock_opencti_connector_helper):
        """With create_indicators=True and a valid full entry, all expected STIX types are present."""
        connector = _make_connector(mock_opencti_connector_helper)
        with patch("connector.connector.requests.get", return_value=_mock_response([_entry()])):
            connector._process_feed("work-id")
        objects = connector.helper.stix2_create_bundle.call_args[0][0]
        stix_types = {type(o).__name__ for o in objects}
        assert "URL" in stix_types
        assert "Indicator" in stix_types
        assert "DomainName" in stix_types
        assert "IPv4Address" in stix_types
        assert "Location" in stix_types

    def test_entry_without_url_is_skipped(self, mock_opencti_connector_helper):
        """An entry with an empty url field is silently ignored, no bundle sent."""
        connector = _make_connector(mock_opencti_connector_helper)
        with patch("connector.connector.requests.get", return_value=_mock_response([_entry(url="")])):
            connector._process_feed("work-id")
        connector.helper.send_stix2_bundle.assert_not_called()

    def test_invalid_ip_logs_warning_and_skips_ipv4_observable(self, mock_opencti_connector_helper):
        """An invalid IP triggers a warning log and no IPv4Address is created."""
        connector = _make_connector(mock_opencti_connector_helper)
        with patch("connector.connector.requests.get", return_value=_mock_response([_entry(ip="not-an-ip")])):
            connector._process_feed("work-id")
        connector.helper.connector_logger.warning.assert_called_once()
        objects = connector.helper.stix2_create_bundle.call_args[0][0]
        assert not any(isinstance(o, stix2.IPv4Address) for o in objects)

    def test_country_dash_skips_location(self, mock_opencti_connector_helper):
        """An entry with country='-' produces no Location object."""
        connector = _make_connector(mock_opencti_connector_helper)
        with patch("connector.connector.requests.get", return_value=_mock_response([_entry(country="-")])):
            connector._process_feed("work-id")
        objects = connector.helper.stix2_create_bundle.call_args[0][0]
        assert not any(isinstance(o, stix2.Location) for o in objects)

    def test_http_error_is_caught_and_logged(self, mock_opencti_connector_helper):
        """An HTTP error is caught, logged as error, and no bundle is sent."""
        connector = _make_connector(mock_opencti_connector_helper)
        resp = MagicMock()
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError("403 Forbidden")
        with patch("connector.connector.requests.get", return_value=resp):
            connector._process_feed("work-id")
        connector.helper.send_stix2_bundle.assert_not_called()
        connector.helper.connector_logger.error.assert_called_once()

    def test_create_indicators_false_only_url_in_bundle(self, mock_opencti_connector_helper):
        """With create_indicators=False, only the URL observable is added, no Indicator or IP."""
        connector = _make_connector(mock_opencti_connector_helper)
        connector.create_indicators = False
        with patch("connector.connector.requests.get", return_value=_mock_response([_entry()])):
            connector._process_feed("work-id")
        objects = connector.helper.stix2_create_bundle.call_args[0][0]
        assert any(isinstance(o, stix2.URL) for o in objects)
        assert not any(isinstance(o, stix2.Indicator) for o in objects)
        assert not any(isinstance(o, stix2.IPv4Address) for o in objects)
