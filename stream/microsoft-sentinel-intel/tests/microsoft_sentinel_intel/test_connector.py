import json
from unittest.mock import MagicMock, Mock

import pytest
from filigran_sseclient.sseclient import Event
from microsoft_sentinel_intel import ConnectorClient
from microsoft_sentinel_intel.config import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from pytest_mock import MockerFixture
from src.microsoft_sentinel_intel import Connector


@pytest.fixture(name="connector")
def fixture_connector(mocked_api_client: MagicMock) -> Connector:
    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config.model_dump_pycti())
    client = ConnectorClient(helper=helper, config=config)
    return Connector(helper=helper, config=config, client=client)


@pytest.fixture(name="event_data_indicator")
def fixture_event_data_indicator() -> dict:
    return {
        "id": "indicator--uuid",
        "spec_version": "2.1",
        "type": "indicator",
        "extensions": {},
        "created": "2025-06-06T09:37:59.399Z",
        "modified": "2025-06-06T09:37:59.399Z",
        "revoked": False,
        "confidence": 100,
        "lang": "en",
        "name": "1.1.1.1",
        "description": "1.1.1.1",
        "pattern": "[ipv4-addr:value = '1.1.1.1']",
        "pattern_type": "stix",
        "valid_from": "2025-06-06T09:37:59.368Z",
        "valid_until": "2025-06-26T15:12:38.802Z",
    }


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_process_message(connector: Connector) -> None:
    # Ensure there s no error running process_message
    connector.process_message(Event())


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_handle_event_create(
    mocker: MockerFixture, connector: Connector, event_data_indicator: dict
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )
    connector._handle_event(
        Event(event="create", data=json.dumps({"data": event_data_indicator}))
    )

    event_data_indicator.pop("extensions")  # as delete_extensions is True
    event_data_indicator["labels"] = ["label"]  # labels in config

    request = mocked_send_request.call_args.kwargs["request"]
    assert request.method == "POST"
    assert (
        request.url == "https://api.ti.sentinel.azure.com"
        "/workspaces/ChangeMe/"
        "threat-intelligence-stix-objects:upload"
        "?api-version=2024-02-01-preview"
    )
    assert json.loads(request.body) == {
        "sourcesystem": "Opencti Stream Connector",
        "stixobjects": [event_data_indicator],
    }


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_handle_event_delete(
    mocker: MockerFixture, connector: Connector, event_data_indicator: dict
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request"
    )
    mocked_send_request.side_effect = [
        Mock(
            status_code=200,
            body=lambda: json.dumps({"value": [{"name": "SentinelId"}]}),
        ),
        Mock(status_code=200),
    ]
    connector._handle_event(
        Event(event="delete", data=json.dumps({"data": event_data_indicator}))
    )

    assert mocked_send_request.call_count == 2
    # First call to query the indicator
    request = mocked_send_request.call_args_list[0].kwargs["request"]
    assert request.method == "POST"
    assert (
        request.url == "https://management.azure.com"
        "/subscriptions/ChangeMe/resourceGroups/default/providers/Microsoft.OperationalInsights/workspaces/ChangeMe"
        "/providers/Microsoft.SecurityInsights/threatIntelligence/main"
        "/queryIndicators?api-version=2025-03-01"
    )
    assert json.loads(request.body) == {"keywords": event_data_indicator["id"]}
    # Second call to delete the indicator
    request = mocked_send_request.call_args_list[1].kwargs["request"]
    assert request.method == "DELETE"
    assert (
        request.url == "https://management.azure.com"
        "/subscriptions/ChangeMe/resourceGroups/default/providers/Microsoft.OperationalInsights/workspaces/ChangeMe"
        "/providers/Microsoft.SecurityInsights/threatIntelligence/main"
        "/indicators/SentinelId?api-version=2025-03-01"
    )
