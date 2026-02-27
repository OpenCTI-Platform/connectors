import json
from unittest.mock import MagicMock, call

import freezegun
import pytest
from connector import CTXException, CyberThreatExchangeConnector
from pytest_mock import MockerFixture


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_init(
    mocked_helper: MagicMock, mock_session: MagicMock, mock_config
) -> None:
    """Test connector initialization"""
    connector = CyberThreatExchangeConnector()

    assert connector.base_url == "https://test-ctx-url/"
    assert connector.api_key == "test-api-key"
    assert connector.feed_ids == ["feed-1", "feed-2"]
    assert connector.interval_hours == 1
    assert connector.session.headers == {"API-KEY": "test-api-key"}


@pytest.fixture
def connector(
    mocked_helper, mock_session: MagicMock, mock_config
) -> CyberThreatExchangeConnector:
    """Fixture for CyberThreatExchangeConnector instance"""
    return CyberThreatExchangeConnector()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_run(connector: CyberThreatExchangeConnector) -> None:
    """Test connector run method"""
    connector.run()

    assert connector.helper.log_info.call_count == 1
    connector.helper.log_info.assert_has_calls([call("Starting CyberThreatExchange")])

    assert connector.helper.schedule_process.call_count == 1
    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.run_once, duration_period=3600
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_empty(connector: CyberThreatExchangeConnector) -> None:
    """Test _get_state with empty state"""
    connector.helper.get_state.return_value = None

    state = connector._get_state()

    assert state == {"feeds": {}}
    connector.helper.get_state.assert_called_once()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_existing(connector: CyberThreatExchangeConnector) -> None:
    """Test _get_state with existing state"""
    existing_state = {
        "feeds": {"feed-1": {"last_run_at": "2026-02-17T15:24:00Z"}},
    }
    connector.helper.get_state.return_value = existing_state

    state = connector._get_state()

    assert state == existing_state
    connector.helper.get_state.assert_called_once()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_set_feed_state(connector: CyberThreatExchangeConnector) -> None:
    """Test set_feed_state method"""
    connector.helper.get_state.return_value = {"feeds": {}}

    connector.set_feed_state("feed-1", last_updated="2026-02-18T15:24:00Z")

    expected_state = {
        "feeds": {"feed-1": {"last_run_at": "2026-02-18T15:24:00Z"}},
    }
    connector.helper.set_state.assert_called_once_with(expected_state)


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_set_feed_state_updates_max(connector: CyberThreatExchangeConnector) -> None:
    """Test set_feed_state updates to max of existing and new timestamp"""
    connector.helper.get_state.return_value = {
        "feeds": {"feed-1": {"last_run_at": "2026-02-19T15:24:00Z"}}
    }

    connector.set_feed_state("feed-1", last_updated="2026-02-18T15:24:00Z")

    # Should keep the later timestamp
    expected_state = {
        "feeds": {"feed-1": {"last_run_at": "2026-02-19T15:24:00Z"}},
    }
    connector.helper.set_state.assert_called_once_with(expected_state)


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_set_feed_state_without_feed_id(
    connector: CyberThreatExchangeConnector,
) -> None:
    """Test set_feed_state with None feed_id"""
    connector.helper.get_state.return_value = {"feeds": {}}

    connector.set_feed_state(None, None)

    expected_state = {"feeds": {}}
    connector.helper.set_state.assert_called_once_with(expected_state)


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_list_subbed_feeds_success(
    mock_session: MagicMock, connector: CyberThreatExchangeConnector
) -> None:
    """Test list_subbed_feeds success"""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 2,
        "results": [
            {
                "feed": {"id": "feed-1", "name": "Feed One"},
                "subscription": {"status": "active"},
            },
            {
                "feed": {"id": "feed-2", "name": "Feed Two"},
                "subscription": {"status": "active"},
            },
        ],
    }
    mock_session.get.return_value = mock_response

    feeds = connector.list_subbed_feeds()

    assert len(feeds) == 2
    assert feeds[0]["feed"]["id"] == "feed-1"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_list_subbed_feeds_failure(
    mock_session: MagicMock, connector: CyberThreatExchangeConnector
) -> None:
    """Test list_subbed_feeds failure"""
    mock_session.get.side_effect = Exception("API Error")

    with pytest.raises(CTXException, match="failed to fetch feeds"):
        connector.list_subbed_feeds()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_retrieve(
    mock_session: MagicMock, connector: CyberThreatExchangeConnector
) -> None:
    """Test retrieve method with pagination"""
    # Mock two pages of results
    mock_response_1 = MagicMock()
    mock_response_1.json.return_value = {
        "total_results_count": 3,
        "results": [{"id": "obj-1"}, {"id": "obj-2"}],
    }

    mock_response_2 = MagicMock()
    mock_response_2.json.return_value = {
        "total_results_count": 3,
        "results": [{"id": "obj-3"}],
    }

    mock_session.get.side_effect = [mock_response_1, mock_response_2]

    objects = connector.retrieve("v1/test/", list_key="results")

    assert len(objects) == 3
    assert objects[0]["id"] == "obj-1"
    assert objects[2]["id"] == "obj-3"
    assert mock_session.get.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_retrieve_with_params(
    mock_session: MagicMock, connector: CyberThreatExchangeConnector
) -> None:
    """Test retrieve method with custom params"""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 1,
        "objects": [{"id": "obj-1"}],
    }
    mock_session.get.return_value = mock_response

    objects = connector.retrieve(
        "v1/test/", list_key="objects", params={"added_after": "2026-02-17T00:00:00Z"}
    )

    assert len(objects) == 1
    # Verify params were passed
    call_params = mock_session.get.call_args[1]["params"]
    assert "added_after" in call_params
    assert call_params["added_after"] == "2026-02-17T00:00:00Z"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_retrieve_generator(
    mock_session: MagicMock, connector: CyberThreatExchangeConnector
) -> None:
    """Test _retrieve generator method"""
    # Mock two batches
    mock_response_1 = MagicMock()
    mock_response_1.json.return_value = {
        "total_results_count": 3,
        "objects": [{"id": "obj-1"}, {"id": "obj-2"}],
    }

    mock_response_2 = MagicMock()
    mock_response_2.json.return_value = {
        "total_results_count": 3,
        "objects": [{"id": "obj-3"}],
    }

    mock_session.get.side_effect = [mock_response_1, mock_response_2]

    batches = list(connector._retrieve("v1/test/", list_key="objects"))

    assert len(batches) == 2
    assert len(batches[0]) == 2
    assert len(batches[1]) == 1


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_retrieve_with_next_url(
    mock_session: MagicMock, connector: CyberThreatExchangeConnector
) -> None:
    """Test _retrieve with next URL pagination"""
    # Mock responses with next URL
    mock_response_1 = MagicMock()
    mock_response_1.json.return_value = {
        "next": "https://test-ctx-url/v1/test/?page=2",
        "objects": [{"id": "obj-1"}],
    }

    mock_response_2 = MagicMock()
    mock_response_2.json.return_value = {
        "next": None,
        "objects": [{"id": "obj-2"}],
    }

    mock_session.get.side_effect = [mock_response_1, mock_response_2]

    batches = list(connector._retrieve("v1/test/", list_key="objects"))

    assert len(batches) == 2
    # Verify second call used the next URL
    assert mock_session.get.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_and_process_objects_no_filter(
    mocker: MockerFixture,
    mock_session: MagicMock,
    connector: CyberThreatExchangeConnector,
) -> None:
    """Test get_and_process_objects without last_run_at"""
    connector.helper.get_state.return_value = {"feeds": {}}

    feed = {"id": "feed-1", "name": "Test Feed"}

    # Mock _retrieve to return batches
    mock_objects = [
        [{"type": "indicator", "id": "indicator--1"}],
        [{"type": "indicator", "id": "indicator--2"}],
    ]
    mocker.patch.object(connector, "_retrieve", return_value=iter(mock_objects))

    connector.get_and_process_objects(feed, "work-id")

    # Verify bundles were sent
    assert connector.helper.send_stix2_bundle.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_and_process_objects_with_filter(
    mocker: MockerFixture,
    mock_session: MagicMock,
    connector: CyberThreatExchangeConnector,
) -> None:
    """Test get_and_process_objects with last_run_at filter"""
    connector.helper.get_state.return_value = {
        "feeds": {"feed-1": {"last_run_at": "2026-02-17T15:24:00Z"}}
    }

    feed = {"id": "feed-1", "name": "Test Feed"}

    mock_objects = [[{"type": "indicator", "id": "indicator--1"}]]
    retrieve_mock = mocker.patch.object(
        connector, "_retrieve", return_value=iter(mock_objects)
    )

    connector.get_and_process_objects(feed, "work-id")

    # Verify _retrieve was called with added_after filter
    call_args = retrieve_mock.call_args
    assert "params" in call_args[1]
    assert "added_after" in call_args[1]["params"]
    assert call_args[1]["params"]["added_after"] == "2026-02-17T15:24:00Z"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_and_process_objects_creates_bundle(
    mocker: MockerFixture,
    mock_session: MagicMock,
    connector: CyberThreatExchangeConnector,
) -> None:
    """Test get_and_process_objects creates proper STIX bundle"""
    connector.helper.get_state.return_value = {"feeds": {}}

    feed = {"id": "feed-1", "name": "Test Feed"}

    mock_objects = [
        [
            {"type": "indicator", "id": "indicator--1"},
            {"type": "indicator", "id": "indicator--2"},
        ]
    ]
    mocker.patch.object(connector, "_retrieve", return_value=iter(mock_objects))

    connector.get_and_process_objects(feed, "work-id")

    connector.helper.send_stix2_bundle.assert_called_once()
    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = json.loads(bundle_arg)

    assert bundle["type"] == "bundle"
    assert bundle["id"] == "bundle--feed-1"
    assert len(bundle["objects"]) == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once_processes_all_feeds(
    mocker: MockerFixture, connector: CyberThreatExchangeConnector
) -> None:
    """Test _run_once processes all subscribed feeds"""
    mock_feeds = [
        {
            "feed": {"id": "feed-1", "name": "Feed One"},
            "subscription": {"status": "active"},
        },
        {
            "feed": {"id": "feed-2", "name": "Feed Two"},
            "subscription": {"status": "active"},
        },
    ]
    mocker.patch.object(connector, "list_subbed_feeds", return_value=mock_feeds)
    get_and_process_mock = mocker.patch.object(connector, "get_and_process_objects")
    mocker.patch.object(connector, "set_feed_state")

    connector._run_once()

    assert get_and_process_mock.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once_filters_by_config_feed_ids(
    mocker: MockerFixture, connector: CyberThreatExchangeConnector
) -> None:
    """Test _run_once filters feeds based on config"""
    mock_feeds = [
        {
            "feed": {"id": "feed-1", "name": "Feed One"},
            "subscription": {"status": "active"},
        },
        {
            "feed": {"id": "feed-3", "name": "Feed Three"},
            "subscription": {"status": "active"},
        },
    ]
    mocker.patch.object(connector, "list_subbed_feeds", return_value=mock_feeds)
    get_and_process_mock = mocker.patch.object(connector, "get_and_process_objects")
    mocker.patch.object(connector, "set_feed_state")

    connector._run_once()

    # Only feed-1 should be processed (feed-3 not in config)
    assert get_and_process_mock.call_count == 1
    assert get_and_process_mock.call_args[0][0]["id"] == "feed-1"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once_skips_inactive_subscriptions(
    mocker: MockerFixture, connector: CyberThreatExchangeConnector
) -> None:
    """Test _run_once skips feeds with inactive subscriptions"""
    mock_feeds = [
        {
            "feed": {"id": "feed-1", "name": "Feed One"},
            "subscription": {"status": "inactive"},
        },
    ]
    mocker.patch.object(connector, "list_subbed_feeds", return_value=mock_feeds)
    get_and_process_mock = mocker.patch.object(connector, "get_and_process_objects")

    connector._run_once()

    # Should not process inactive subscription
    get_and_process_mock.assert_not_called()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once_creates_work_per_feed(
    mocker: MockerFixture, connector: CyberThreatExchangeConnector
) -> None:
    """Test _run_once creates separate work items for each feed"""
    mock_feeds = [
        {
            "feed": {"id": "feed-1", "name": "Feed One"},
            "subscription": {"status": "active"},
        },
        {
            "feed": {"id": "feed-2", "name": "Feed Two"},
            "subscription": {"status": "active"},
        },
    ]
    mocker.patch.object(connector, "list_subbed_feeds", return_value=mock_feeds)
    mocker.patch.object(connector, "get_and_process_objects")
    mocker.patch.object(connector, "set_feed_state")

    connector._run_once()

    # Should create work item for each feed
    assert connector.helper.api.work.initiate_work.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once_updates_feed_state(
    mocker: MockerFixture, connector: CyberThreatExchangeConnector
) -> None:
    """Test _run_once updates feed state after processing"""
    mock_feeds = [
        {
            "feed": {"id": "feed-1", "name": "Feed One"},
            "subscription": {"status": "active"},
        },
        {
            "feed": {"id": "feed-2", "name": "Feed Two"},
            "subscription": {"status": "active"},
        },
    ]
    connector.feed_ids = ["feed-1"]
    connector.current_run_time = "2026-02-18T15:24:00Z"
    mocker.patch.object(connector, "list_subbed_feeds", return_value=mock_feeds)
    mocker.patch.object(connector, "get_and_process_objects")
    set_feed_state_mock = mocker.patch.object(connector, "set_feed_state")

    connector._run_once()

    set_feed_state_mock.assert_has_calls(
        [call("feed-1", last_updated="2026-02-18T15:24:00Z"), call(None, None)]
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once_wrapper(
    mocker: MockerFixture, connector: CyberThreatExchangeConnector
) -> None:
    """Test run_once method wraps _run_once in work context"""
    run_once_mock = mocker.patch.object(connector, "_run_once")

    connector.run_once()

    run_once_mock.assert_called_once()
    connector.helper.api.work.initiate_work.assert_called_once()
    connector.helper.api.work.to_processed.assert_called_once()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_success(connector: CyberThreatExchangeConnector) -> None:
    """Test _run_in_work context manager success"""
    with connector._run_in_work("Test Work") as work_id:
        assert work_id == "work-id"

    connector.helper.api.work.to_processed.assert_called_once_with(
        work_id="work-id", message="[CyberThreatExchange] Work done", in_error=False
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_failure(connector: CyberThreatExchangeConnector) -> None:
    """Test _run_in_work context manager failure"""
    with connector._run_in_work("Test Work"):
        raise ValueError("Test error")

    call_kwargs = connector.helper.api.work.to_processed.call_args[1]
    assert call_kwargs["in_error"] is True
    assert "[CyberThreatExchange] Work failed" in call_kwargs["message"]
    assert "ValueError: Test error" in call_kwargs["message"]


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_param(connector: CyberThreatExchangeConnector) -> None:
    """Test _get_param method"""
    result = connector._get_param("base_url")
    assert result == "https://test-ctx-url/"

    result = connector._get_param("interval_hours", is_number=True)
    assert result == 1
    assert isinstance(result, int)
