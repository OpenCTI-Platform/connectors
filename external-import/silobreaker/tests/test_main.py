from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, Silobreaker
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
                "silobreaker": {
                    "api_url": "https://api.silobreaker.com",
                    "api_key": "test-api-key",
                    "api_shared": "test-api-shared",
                    "lists": "138809,96910,36592,55112,50774",
                    "import_start_date": "2024-09-01",
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

    connector = Silobreaker(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper


def test_convert_to_markdown(mock_opencti_connector_helper):
    """
    Test that `Silobreaker._convert_to_markdown` converts HTML to Markdown and applies
    the Silobreaker-specific post-processing:
        - headings MUST use the ATX style (`#`), as html2text produced before the migration
        - a headerless table MUST keep its first row as the header
        - defanged `hxxps` links MUST be restored to `https`
        - protocol-relative links MUST be made absolute with `https://`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    connector = Silobreaker(config=settings, helper=helper)

    html = (
        "<h1>Title</h1>"
        "<p>Some <strong>bold</strong> text.</p>"
        "<table><tr><td>IOC</td><td>Type</td></tr>"
        "<tr><td>1.2.3.4</td><td>ip</td></tr></table>"
        '<p><a href="hxxps://evil.example/payload">defanged</a> '
        '<a href="//cdn.example/asset">relative</a></p>'
    )

    markdown = connector._convert_to_markdown(html)

    assert "# Title" in markdown
    assert "**bold**" in markdown
    assert "| IOC | Type |" in markdown
    assert "| --- | --- |" in markdown
    assert "| 1.2.3.4 | ip |" in markdown
    assert "[defanged](https://evil.example/payload)" in markdown
    assert "[relative](https://cdn.example/asset)" in markdown
    assert "hxxps" not in markdown
    assert "](//" not in markdown
