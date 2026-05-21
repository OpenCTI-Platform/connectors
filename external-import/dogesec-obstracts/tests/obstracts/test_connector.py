import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, call

import freezegun
import pytest
from obstracts import ObstractsConnector, ObstractsException
from pytest_mock import MockerFixture


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_init(mocked_helper, mock_session: MagicMock, mock_config) -> None:
    """Test connector initialization"""
    connector = ObstractsConnector()
    assert connector.base_url == "https://test-obstracts-url/"
    assert connector.api_key == "test-api-key"
    assert connector.feed_ids == ["feed-1", "feed-2"]
    assert connector.interval_hours == 1
    assert connector.days_to_backfill == 7
    assert connector.session.headers == {"API-KEY": "test-api-key"}


@pytest.fixture
def connector(
    mocked_helper, mock_session: MagicMock, mock_config
) -> ObstractsConnector:
    """Fixture for ObstractsConnector instance"""
    return ObstractsConnector()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_run(connector: ObstractsConnector) -> None:
    """Test connector run method"""
    connector.run()

    assert connector.helper.log_info.call_count == 1
    connector.helper.log_info.assert_has_calls([call("Starting Obstracts")])

    assert connector.helper.schedule_process.call_count == 1
    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.run_once, duration_period=3600
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_empty(connector: ObstractsConnector) -> None:
    """Test _get_state with empty state"""
    connector.helper.get_state.return_value = None

    state = connector._get_state()

    assert state == {"feeds": {}}
    connector.helper.get_state.assert_called_once()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_existing(connector: ObstractsConnector) -> None:
    """Test _get_state with existing state"""
    existing_state = {
        "feeds": {"feed-1": {"latest_post_update_time": "2026-02-17T15:24:00Z"}},
        "last_run": "2026-02-17T15:24:00Z",
    }
    connector.helper.get_state.return_value = existing_state
    state = connector._get_state()

    assert state == existing_state
    connector.helper.get_state.assert_called_once()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_set_feed_state(connector: ObstractsConnector) -> None:
    """Test set_feed_state method"""
    connector.helper.get_state.return_value = {"feeds": {}}

    connector.set_feed_state("feed-1", "2026-02-18T15:24:00Z")

    expected_state = {
        "feeds": {"feed-1": {"latest_post_update_time": "2026-02-18T15:24:00Z"}},
        "last_run": "2026-02-18T15:24:00+00:00",
    }
    connector.helper.set_state.assert_called_once_with(expected_state)
    connector.helper.last_run_datetime.assert_called_once()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_set_feed_state_no_feed_id(connector: ObstractsConnector) -> None:
    """Test set_feed_state with no feed_id (final state save)"""
    existing_state = {
        "feeds": {"feed-1": {"latest_post_update_time": "2026-02-17T15:24:00Z"}},
        "last_run": "2025-02-17T15:24:00Z",
    }
    connector.helper.get_state.return_value = existing_state

    connector.set_feed_state(None, None)

    expected_state = existing_state.copy()
    expected_state["last_run"] = "2026-02-18T15:24:00+00:00"
    connector.helper.set_state.assert_called_once_with(expected_state)


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_list_feeds_success(
    mock_session: MagicMock, connector: ObstractsConnector
) -> None:
    """Test list_feeds success"""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 2,
        "feeds": [
            {"id": "feed-1", "title": "Feed One"},
            {"id": "feed-2", "title": "Feed Two"},
        ],
    }
    mock_session.get.return_value = mock_response

    feeds = connector.list_feeds()

    assert len(feeds) == 2
    assert feeds[0]["id"] == "feed-1"
    assert feeds[1]["id"] == "feed-2"
    mock_session.get.assert_called()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_list_feeds_failure(
    mock_session: MagicMock, connector: ObstractsConnector
) -> None:
    """Test list_feeds failure"""
    mock_session.get.side_effect = Exception("API Error")

    with pytest.raises(ObstractsException, match="failed to fetch feeds"):
        connector.list_feeds()

    connector.helper.log_error.assert_called_once_with("failed to fetch feeds")


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_retrieve(mock_session: MagicMock, connector: ObstractsConnector) -> None:
    """Test retrieve method with pagination"""
    # Mock two pages of results
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

    objects = connector.retrieve("v1/test/", list_key="objects")

    assert len(objects) == 3
    assert objects[0]["id"] == "obj-1"
    assert objects[2]["id"] == "obj-3"
    assert mock_session.get.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_process_post_success(
    mock_session: MagicMock, connector: ObstractsConnector
) -> None:
    """Test process_post success"""

    post = {
        "id": "post-1",
        "title": "Test Post",
        "datetime_updated": "2026-02-18T15:24:00Z",
    }

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 2,
        "objects": [
            {"type": "indicator", "id": "indicator--1"},
            {"type": "indicator", "id": "indicator--2"},
        ],
    }
    mock_session.get.return_value = mock_response

    connector.process_post("feed-1", post, "work-id")

    # Verify bundle was sent
    connector.helper.send_stix2_bundle.assert_called_once()
    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = json.loads(bundle_arg)

    assert bundle["type"] == "bundle"
    assert bundle["id"] == "bundle--post-1"
    assert len(bundle["objects"]) == 2

    # Verify work_id was passed
    assert connector.helper.send_stix2_bundle.call_args[1]["work_id"] == "work-id"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_process_post_failure(
    mock_session: MagicMock, connector: ObstractsConnector
) -> None:
    """Test process_post failure"""

    post = {
        "id": "post-1",
        "title": "Test Post",
        "datetime_updated": "2026-02-18T15:24:00Z",
    }

    mock_session.get.side_effect = Exception("API Error")

    # Should not raise, but log error
    connector.process_post("feed-1", post, "work-id")

    connector.helper.log_error.assert_called_once_with(
        "could not process post Post(title='Test Post', id=post-1)"
    )
    connector.helper.send_stix2_bundle.assert_not_called()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_posts_after_last_with_state(
    mocker: MockerFixture, mock_session: MagicMock, connector: ObstractsConnector
) -> None:
    """Test get_posts_after_last with existing state"""
    existing_state = {
        "feeds": {"feed-1": {"latest_post_update_time": "2026-02-17T15:24:00Z"}}
    }
    connector.helper.get_state.return_value = existing_state

    feed = {"id": "feed-1", "title": "Test Feed"}

    # Mock retrieve to return posts
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 1,
        "posts": [
            {
                "id": "post-1",
                "title": "Post 1",
                "datetime_updated": "2026-02-18T15:24:00Z",
            }
        ],
    }
    mock_session.get.return_value = mock_response

    # Mock process_post
    process_post_mock = mocker.patch.object(connector, "process_post")

    connector.get_posts_after_last(feed, "work-id")

    # Verify retrieve was called with correct params
    assert "updated_after" in mock_session.get.call_args[1]["params"]
    assert (
        mock_session.get.call_args[1]["params"]["updated_after"]
        == "2026-02-17T15:24:00Z"
    )

    # Verify process_post was called
    process_post_mock.assert_called_once()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_posts_after_last_no_state(
    mocker: MockerFixture, mock_session: MagicMock, connector: ObstractsConnector
) -> None:
    """Test get_posts_after_last with no state (uses backfill)"""
    connector.helper.get_state.return_value = {"feeds": {}}

    feed = {"id": "feed-1", "title": "Test Feed"}

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 0,
        "posts": [],
    }
    mock_session.get.return_value = mock_response

    mocker.patch.object(connector, "process_post")

    connector.get_posts_after_last(feed, "work-id")

    # Verify backfill date was used (7 days ago)
    expected_date = (datetime.now(UTC) - timedelta(days=7)).isoformat()
    assert "updated_after" in mock_session.get.call_args[1]["params"]
    assert isinstance(mock_session.get.call_args[1]["params"]["updated_after"], str)
    assert expected_date == mock_session.get.call_args[1]["params"]["updated_after"]


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once(mocker: MockerFixture, connector: ObstractsConnector) -> None:
    """Test run_once method"""

    # Mock list_feeds
    mock_feeds = [
        {"id": "feed-1", "title": "Feed One"},
        {"id": "feed-2", "title": "Feed Two"},
    ]
    mocker.patch.object(connector, "list_feeds", return_value=mock_feeds)

    # Mock get_posts_after_last
    get_posts_mock = mocker.patch.object(connector, "get_posts_after_last")

    # Mock set_feed_state
    mocker.patch.object(connector, "set_feed_state")

    connector.run_once()

    # Verify work was initiated
    connector.helper.api.work.initiate_work.assert_called()

    # Verify feeds were processed
    assert get_posts_mock.call_count == 2

    # Verify work was closed
    connector.helper.api.work.to_processed.assert_called()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once_filters_feeds(
    mocker: MockerFixture, connector: ObstractsConnector
) -> None:
    """Test run_once filters feeds based on config"""

    # Mock list_feeds to return 3 feeds, but only 2 are in config
    mock_feeds = [
        {"id": "feed-1", "title": "Feed One"},
        {"id": "feed-2", "title": "Feed Two"},
        {"id": "feed-3", "title": "Feed Three"},  # Not in config
    ]
    mocker.patch.object(connector, "list_feeds", return_value=mock_feeds)

    get_posts_mock = mocker.patch.object(connector, "get_posts_after_last")
    mocker.patch.object(connector, "set_feed_state")

    connector.run_once()

    # Should only process 2 feeds (feed-1 and feed-2 from config)
    assert get_posts_mock.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_success(connector: ObstractsConnector) -> None:
    """Test _run_in_work context manager success"""

    with connector._run_in_work("Test Work") as work_id:
        assert work_id == "work-id"

    connector.helper.api.work.initiate_work.assert_called_once_with(
        "connector-id", "Test Work"
    )
    connector.helper.api.work.to_processed.assert_called_once_with(
        work_id="work-id", message="[OBSTRACTS] Work done", in_error=False
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_failure(connector: ObstractsConnector) -> None:
    """Test _run_in_work context manager failure"""

    with connector._run_in_work("Test Work"):
        raise ValueError("Test error")

    connector.helper.api.work.to_processed.assert_called_once()
    call_kwargs = connector.helper.api.work.to_processed.call_args[1]
    assert call_kwargs["in_error"] is True
    assert "[OBSTRACTS] Work failed" in call_kwargs["message"]
    assert "ValueError: Test error" in call_kwargs["message"]


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_param(connector: ObstractsConnector) -> None:
    """Test _get_param method"""

    # String param
    result = connector._get_param("base_url")
    assert result == "https://test-obstracts-url/"

    # Number param
    result = connector._get_param("interval_hours", is_number=True)
    assert result == 1
    assert isinstance(result, int)


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_retrieve_with_params(
    mock_session: MagicMock, connector: ObstractsConnector
) -> None:
    """Test retrieve with custom params"""

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 1,
        "objects": [{"id": "obj-1"}],
    }
    mock_session.get.return_value = mock_response

    objects = connector.retrieve(
        "v1/test/", list_key="objects", params={"custom_param": "value"}
    )

    assert len(objects) == 1
    # Verify custom param was passed
    call_params = mock_session.get.call_args[1]["params"]
    assert call_params["custom_param"] == "value"
    assert call_params["page"] == 2
    assert call_params["page_size"] == 200
