from connector import ConnectorSettings, SpurIPProcessor
from connectors_sdk import InternalEnrichmentConnector
from pycti import OpenCTIConnectorHelper


def test_connector_settings_is_instantiated(settings):
    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(
    mock_opencti_connector_helper, settings
):
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "IPv4-Addr,IPv6-Addr"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto is True


def test_connector_is_instantiated(mock_opencti_connector_helper, settings):
    processor = SpurIPProcessor()

    connector = InternalEnrichmentConnector(
        settings=settings, enrichment_processors=[processor]
    )
    connector._init_dependencies()

    assert connector.settings == settings
    assert processor.client._base_url == "http://test.com"
    assert processor.default_score == 70
