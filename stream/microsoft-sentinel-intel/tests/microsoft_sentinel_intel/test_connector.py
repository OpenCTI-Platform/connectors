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


@pytest.fixture(name="batch_connector")
def fixture_batch_connector(
    mocked_api_client: MagicMock, mock_microsoft_sentinel_intel_batch_config
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


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_handle_event_no_data(mocker: MockerFixture, connector: Connector) -> None:
    """Connector should gracefully ignore events with no 'data' in its JSON payload."""
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request"
    )
    connector._handle_event(
        Event(event="consumer_metrics", data=json.dumps({"metric": "value"}))
    )
    assert mocked_send_request.call_count == 0


# --- Batch mode tests ---


def _make_indicator_data(indicator_id: str, name: str = "1.1.1.1") -> dict:
    return {
        "id": indicator_id,
        "spec_version": "2.1",
        "type": "indicator",
        "extensions": {},
        "created": "2025-06-06T09:37:59.399Z",
        "modified": "2025-06-06T09:37:59.399Z",
        "revoked": False,
        "confidence": 100,
        "lang": "en",
        "name": name,
        "description": name,
        "pattern": f"[ipv4-addr:value = '{name}']",
        "pattern_type": "stix",
        "valid_from": "2025-06-06T09:37:59.368Z",
        "valid_until": "2025-06-26T15:12:38.802Z",
    }


def _make_batch_event(
    event_type: str, indicator_id: str, name: str = "1.1.1.1"
) -> Event:
    data = _make_indicator_data(indicator_id, name)
    return Event(event=event_type, data=json.dumps({"data": data}))


def _make_batch_data(events: list[Event]) -> dict:
    return {"events": events}


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_batch_config")
def test_process_batch_uploads_all(
    mocker: MockerFixture, batch_connector: Connector
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    batch_data = _make_batch_data(
        [
            _make_batch_event("create", "indicator--1", "1.1.1.1"),
            _make_batch_event("create", "indicator--2", "2.2.2.2"),
            _make_batch_event("create", "indicator--3", "3.3.3.3"),
        ]
    )
    batch_connector.process_batch(batch_data)

    assert mocked_send_request.call_count == 1
    request = mocked_send_request.call_args.kwargs["request"]
    body = json.loads(request.body)
    assert len(body["stixobjects"]) == 3


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_batch_config")
def test_process_batch_deduplicates(
    mocker: MockerFixture, batch_connector: Connector
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    batch_data = _make_batch_data(
        [
            _make_batch_event("create", "indicator--1", "1.1.1.1"),
            _make_batch_event("update", "indicator--1", "updated-name"),
            _make_batch_event("create", "indicator--2", "2.2.2.2"),
        ]
    )
    batch_connector.process_batch(batch_data)

    assert mocked_send_request.call_count == 1
    request = mocked_send_request.call_args.kwargs["request"]
    body = json.loads(request.body)
    # Only 2 unique objects despite 3 events
    assert len(body["stixobjects"]) == 2
    names = {obj["name"] for obj in body["stixobjects"]}
    assert "updated-name" in names
    assert "1.1.1.1" not in names


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_batch_config")
def test_process_batch_skips_delete(
    mocker: MockerFixture, batch_connector: Connector
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    batch_data = _make_batch_data(
        [
            _make_batch_event("delete", "indicator--1", "1.1.1.1"),
        ]
    )
    batch_connector.process_batch(batch_data)

    assert mocked_send_request.call_count == 0


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_batch_config")
def test_process_batch_prepare_applied(
    mocker: MockerFixture, batch_connector: Connector
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    batch_data = _make_batch_data(
        [
            _make_batch_event("create", "indicator--1", "1.1.1.1"),
            _make_batch_event("create", "indicator--2", "2.2.2.2"),
            _make_batch_event("create", "indicator--3", "3.3.3.3"),
        ]
    )
    batch_connector.process_batch(batch_data)

    request = mocked_send_request.call_args.kwargs["request"]
    body = json.loads(request.body)
    for obj in body["stixobjects"]:
        assert "extensions" not in obj  # delete_extensions is True
        assert "label" in obj["labels"]  # extra_labels applied


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_batch_config")
def test_process_batch_empty_events(
    mocker: MockerFixture, batch_connector: Connector
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    batch_connector.process_batch({"events": []})

    assert mocked_send_request.call_count == 0


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_batch_config")
def test_process_batch_skips_no_data_events(
    mocker: MockerFixture, batch_connector: Connector
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    batch_data = _make_batch_data(
        [
            Event(event="consumer_metrics", data=json.dumps({"metric": "value"})),
        ]
    )
    batch_connector.process_batch(batch_data)

    assert mocked_send_request.call_count == 0


@pytest.fixture(name="create_update_only_connector")
def fixture_create_update_only_connector(
    mocked_api_client: MagicMock,
    mock_microsoft_sentinel_intel_create_update_only_config,
) -> Connector:
    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config.to_helper_config())
    client = ConnectorClient(helper=helper, config=config)
    return Connector(helper=helper, config=config, client=client)


@pytest.fixture(name="delete_only_connector")
def fixture_delete_only_connector(
    mocked_api_client: MagicMock, mock_microsoft_sentinel_intel_delete_only_config
) -> Connector:
    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config.to_helper_config())
    client = ConnectorClient(helper=helper, config=config)
    return Connector(helper=helper, config=config, client=client)


@pytest.fixture(name="batch_create_only_connector")
def fixture_batch_create_only_connector(
    mocked_api_client: MagicMock, mock_microsoft_sentinel_intel_batch_create_only_config
) -> Connector:
    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config.to_helper_config())
    client = ConnectorClient(helper=helper, config=config)
    return Connector(helper=helper, config=config, client=client)


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_realtime_mode_unchanged(
    mocker: MockerFixture, connector: Connector, event_data_indicator: dict
) -> None:
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )
    connector._handle_event(
        Event(event="create", data=json.dumps({"data": event_data_indicator}))
    )
    # In real-time mode, upload is called immediately for each event
    assert mocked_send_request.call_count == 1


# --- Event type filtering tests ---


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_create_update_only_config")
def test_event_types_filters_delete(
    mocker: MockerFixture,
    create_update_only_connector: Connector,
    event_data_indicator: dict,
) -> None:
    """Connector with event_types=create,update should ignore delete events."""
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )
    create_update_only_connector._handle_event(
        Event(event="delete", data=json.dumps({"data": event_data_indicator}))
    )
    assert mocked_send_request.call_count == 0


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_delete_only_config")
def test_event_types_filters_create_update(
    mocker: MockerFixture, delete_only_connector: Connector, event_data_indicator: dict
) -> None:
    """Connector with event_types=delete should ignore create/update events."""
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )
    delete_only_connector._handle_event(
        Event(event="create", data=json.dumps({"data": event_data_indicator}))
    )
    delete_only_connector._handle_event(
        Event(event="update", data=json.dumps({"data": event_data_indicator}))
    )
    assert mocked_send_request.call_count == 0


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_batch_create_only_config")
def test_process_batch_event_types_filter(
    mocker: MockerFixture, batch_create_only_connector: Connector
) -> None:
    """Batch connector with event_types=create should skip update events."""
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    batch_data = _make_batch_data(
        [
            _make_batch_event("create", "indicator--1", "1.1.1.1"),
            _make_batch_event("update", "indicator--2", "2.2.2.2"),
            _make_batch_event("create", "indicator--3", "3.3.3.3"),
        ]
    )
    batch_create_only_connector.process_batch(batch_data)

    assert mocked_send_request.call_count == 1
    request = mocked_send_request.call_args.kwargs["request"]
    body = json.loads(request.body)
    assert len(body["stixobjects"]) == 2


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_batch_config")
def test_process_batch_malformed_json(
    mocker: MockerFixture, batch_connector: Connector
) -> None:
    """Batch should skip malformed JSON events and process remaining valid ones."""
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    batch_data = _make_batch_data(
        [
            Event(event="create", data="not valid json"),
            _make_batch_event("create", "indicator--1", "1.1.1.1"),
        ]
    )
    batch_connector.process_batch(batch_data)

    assert mocked_send_request.call_count == 1
    request = mocked_send_request.call_args.kwargs["request"]
    body = json.loads(request.body)
    assert len(body["stixobjects"]) == 1


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_batch_config")
def test_process_batch_non_indicator_stix_types(
    mocker: MockerFixture, batch_connector: Connector
) -> None:
    """Batch should skip non-indicator STIX objects."""
    mocked_send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    non_indicator = {
        "id": "malware--uuid",
        "type": "malware",
        "name": "some-malware",
    }
    batch_data = _make_batch_data(
        [
            Event(event="create", data=json.dumps({"data": non_indicator})),
            _make_batch_event("create", "indicator--1", "1.1.1.1"),
        ]
    )
    batch_connector.process_batch(batch_data)

    assert mocked_send_request.call_count == 1
    request = mocked_send_request.call_args.kwargs["request"]
    body = json.loads(request.body)
    assert len(body["stixobjects"]) == 1


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_prepare_stix_object_missing_extensions(
    connector: Connector, event_data_indicator: dict
) -> None:
    """_prepare_stix_object should not raise if 'extensions' key is absent."""
    indicator_no_ext = {
        k: v for k, v in event_data_indicator.items() if k != "extensions"
    }
    result = connector._prepare_stix_object(indicator_no_ext)
    assert "extensions" not in result


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_prepare_stix_object_does_not_mutate_input(
    connector: Connector, event_data_indicator: dict
) -> None:
    """_prepare_stix_object should not modify the original dict."""
    original_keys = set(event_data_indicator.keys())
    connector._prepare_stix_object(event_data_indicator)
    assert set(event_data_indicator.keys()) == original_keys
    assert "extensions" in event_data_indicator
