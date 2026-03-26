import json
from unittest.mock import MagicMock, Mock

import pytest
from filigran_sseclient.sseclient import Event
from microsoft_sentinel_intel import ConnectorClient
from microsoft_sentinel_intel.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from pytest_mock import MockerFixture
from src.microsoft_sentinel_intel import Connector


@pytest.fixture(name="connector")
def fixture_connector(
    mocked_api_client: MagicMock, mock_microsoft_sentinel_intel_config
) -> Connector:
    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config.to_helper_config())
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


@pytest.fixture(name="event_data_indicator_2")
def fixture_event_data_indicator_2() -> dict:
    return {
        "id": "indicator--uuid-2",
        "spec_version": "2.1",
        "type": "indicator",
        "extensions": {},
        "created": "2025-06-07T09:37:59.399Z",
        "modified": "2025-06-07T09:37:59.399Z",
        "revoked": False,
        "confidence": 100,
        "lang": "en",
        "name": "2.2.2.2",
        "description": "2.2.2.2",
        "pattern": "[ipv4-addr:value = '2.2.2.2']",
        "pattern_type": "stix",
        "valid_from": "2025-06-07T09:37:59.368Z",
        "valid_until": "2025-06-27T15:12:38.802Z",
    }


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_process_message_batch_create(
    mocker: MockerFixture,
    connector: Connector,
    event_data_indicator: dict,
    event_data_indicator_2: dict,
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    batch_data = {
        "events": [
            Event(
                event="create",
                data=json.dumps({"data": event_data_indicator}),
            ),
            Event(
                event="create",
                data=json.dumps({"data": event_data_indicator_2}),
            ),
        ],
        "batch_metadata": {
            "batch_size": 2,
            "trigger_reason": "size_limit",
            "elapsed_time": 1.0,
            "timestamp": 1000.0,
        },
    }
    connector.process_message_batch(batch_data)

    # Both indicators should be uploaded in a single API call
    assert mocked_send_request.call_count == 1
    request = mocked_send_request.call_args.kwargs["request"]
    assert request.method == "POST"
    body = json.loads(request.body)
    assert len(body["stixobjects"]) == 2
    assert body["sourcesystem"] == "Opencti Stream Connector"


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_process_message_batch_delete(
    mocker: MockerFixture,
    connector: Connector,
    event_data_indicator: dict,
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
    )
    mocked_send_request.side_effect = [
        Mock(
            status_code=200,
            body=lambda: json.dumps({"value": [{"name": "SentinelId"}]}),
        ),
        Mock(status_code=200),
    ]

    batch_data = {
        "events": [
            Event(
                event="delete",
                data=json.dumps({"data": event_data_indicator}),
            ),
        ],
        "batch_metadata": {
            "batch_size": 1,
            "trigger_reason": "timeout",
            "elapsed_time": 30.0,
            "timestamp": 1000.0,
        },
    }
    connector.process_message_batch(batch_data)

    # Delete requires 2 API calls (query + delete)
    assert mocked_send_request.call_count == 2


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_process_message_batch_mixed(
    mocker: MockerFixture,
    connector: Connector,
    event_data_indicator: dict,
    event_data_indicator_2: dict,
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
    )
    mocked_send_request.side_effect = [
        # First call: bulk upload for creates
        Mock(status_code=200),
        # Second call: query for delete
        Mock(
            status_code=200,
            body=lambda: json.dumps({"value": [{"name": "SentinelId"}]}),
        ),
        # Third call: actual delete
        Mock(status_code=200),
    ]

    batch_data = {
        "events": [
            Event(
                event="create",
                data=json.dumps({"data": event_data_indicator}),
            ),
            Event(
                event="delete",
                data=json.dumps({"data": event_data_indicator_2}),
            ),
        ],
        "batch_metadata": {
            "batch_size": 2,
            "trigger_reason": "size_limit",
            "elapsed_time": 1.0,
            "timestamp": 1000.0,
        },
    }
    connector.process_message_batch(batch_data)

    # 1 upload call + 2 delete calls (query + delete)
    assert mocked_send_request.call_count == 3


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_process_message_batch_skips_non_indicator(
    mocker: MockerFixture,
    connector: Connector,
    event_data_indicator: dict,
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    non_indicator = {
        "id": "malware--uuid",
        "type": "malware",
        "name": "BadMalware",
        "pattern_type": "stix",
    }

    batch_data = {
        "events": [
            Event(
                event="create",
                data=json.dumps({"data": non_indicator}),
            ),
            Event(
                event="create",
                data=json.dumps({"data": event_data_indicator}),
            ),
        ],
        "batch_metadata": {
            "batch_size": 2,
            "trigger_reason": "size_limit",
            "elapsed_time": 1.0,
            "timestamp": 1000.0,
        },
    }
    connector.process_message_batch(batch_data)

    # Only one indicator should be uploaded (the non-indicator is skipped)
    assert mocked_send_request.call_count == 1
    body = json.loads(mocked_send_request.call_args.kwargs["request"].body)
    assert len(body["stixobjects"]) == 1
