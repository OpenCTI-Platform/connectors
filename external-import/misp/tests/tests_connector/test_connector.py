import time
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

from api_client.models import EventRestSearchListItem
from connector import ConnectorSettings, Misp
from freezegun import freeze_time
from pycti import OpenCTIConnectorHelper

minimal_config_dict = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "misp": {
        "url": "http://test.com",
        "key": "test-api-key",
    },
}


def fake_misp_connector(config_dict: dict) -> Misp:
    class StubConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config_dict)

    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    return Misp(config=settings, helper=helper)


def test_get_event_datetime_with_timestamp(mock_opencti_connector_helper, mock_py_misp):
    """
    Test that _get_event_datetime correctly parses a UNIX timestamp when datetime_attribute is 'timestamp'.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "timestamp"

    connector = fake_misp_connector(config_dict)

    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "timestamp": str(
                    int(datetime(2026, 1, 30, tzinfo=timezone.utc).timestamp())
                )
            }
        }
    )
    event_datetime = connector._get_event_datetime(event)
    assert (
        event_datetime.year == 2026
        and event_datetime.month == 1
        and event_datetime.day == 30
        and event_datetime.tzinfo == timezone.utc
    )


def test_get_event_datetime_with_publish_timestamp(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that _get_event_datetime correctly parses a UNIX timestamp when datetime_attribute is 'publish_timestamp'.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "publish_timestamp"

    connector = fake_misp_connector(config_dict)

    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "publish_timestamp": str(
                    int(datetime(2026, 1, 30, tzinfo=timezone.utc).timestamp())
                )
            }
        }
    )
    event_datetime = connector._get_event_datetime(event)
    assert (
        event_datetime.year == 2026
        and event_datetime.month == 1
        and event_datetime.day == 30
        and event_datetime.tzinfo == timezone.utc
    )


def test_get_event_datetime_with_sighting_timestamp(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that _get_event_datetime correctly parses a UNIX timestamp when datetime_attribute is 'sighting_timestamp'.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "sighting_timestamp"

    connector = fake_misp_connector(config_dict)

    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "sighting_timestamp": str(
                    int(datetime(2026, 1, 30, tzinfo=timezone.utc).timestamp())
                )
            }
        }
    )
    event_datetime = connector._get_event_datetime(event)
    assert (
        event_datetime.year == 2026
        and event_datetime.month == 1
        and event_datetime.day == 30
        and event_datetime.tzinfo == timezone.utc
    )


def test_get_event_datetime_with_date(mock_opencti_connector_helper, mock_py_misp):
    """
    Test that _get_event_datetime correctly parses an ISO date string when datetime_attribute is 'date'.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "date"

    connector = fake_misp_connector(config_dict)

    event = EventRestSearchListItem.model_validate(
        {"Event": {"date": date(2026, 1, 30).isoformat()}}
    )
    event_datetime = connector._get_event_datetime(event)
    assert (
        event_datetime.year == 2026
        and event_datetime.month == 1
        and event_datetime.day == 30
    )


def test_get_event_datetime_with_invalid_attribute(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that _get_event_datetime raises ValueError when datetime_attribute is not supported.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)

    connector = fake_misp_connector(config_dict)

    with patch.object(connector, "config") as mock_invalid_config:
        mock_invalid_config.misp.datetime_attribute = "invalid"

        event = EventRestSearchListItem.model_validate({"Event": {"invalid": "foo"}})
        try:
            connector._get_event_datetime(event)
        except ValueError as error:
            assert "MISP_DATETIME_ATTRIBUTE" in str(error) or "must be either" in str(
                error
            )
        else:
            assert False, "Expected ValueError for invalid datetime_attribute"


def test_connector_validate_event_with_owner_org_in_import_owner_orgs_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when its owner org is in the list of allowed orgs.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_owner_orgs"] = ["Test Org"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Test Org"}}}
    )

    assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_with_owner_org_not_in_import_owner_orgs_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector doesn't validate an event when its owner org is not in the list of allowed orgs.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_owner_orgs"] = ["Test Org"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Another Org"}}}
    )

    assert connector._validate_event(event) is False


def test_connector_validates_event_when_no_import_owner_orgs_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when no allowed owner orgs are configured.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Any Org"}}}
    )

    assert connector._validate_event(event) is True


def test_connector_validates_event_with_owner_org_not_in_import_owner_orgs_not_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when its owner org is not in the list of excluded orgs.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_owner_orgs_not"] = ["Excluded Org"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Allowed Org"}}}
    )

    assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_with_owner_org_in_import_owner_orgs_not_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector doesn't validate an event when its owner org is in the list of excluded orgs.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_owner_orgs_not"] = ["Excluded Org"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Excluded Org"}}}
    )

    assert connector._validate_event(event) is False


def test_connector_validates_event_when_no_import_owner_orgs_not_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when no excluded owner orgs are configured.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Any Org"}}}
    )

    assert connector._validate_event(event) is True


def test_connector_validates_event_with_distribution_in_import_distribution_levels(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when its distribution level is in the list of allowed levels.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """

    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_distribution_levels"] = ["2"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "distribution": 2}}
    )

    assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_with_distribution_not_in_import_distribution_levels(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector doesn't validate an event when its distribution level is not in the list of allowed levels.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_distribution_levels"] = ["0", "1"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "distribution": 2}}
    )

    assert connector._validate_event(event) is False


def test_connector_validates_event_with_threat_level_in_import_threat_levels(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when its threat level is in the list of allowed levels.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_threat_levels"] = ["3"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "threat_level_id": 3}}
    )

    assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_with_threat_level_not_in_import_threat_levels(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector doesn't validate an event when its threat level is not in the list of allowed levels.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_threat_levels"] = ["1", "2"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "threat_level_id": 3}}
    )

    assert connector._validate_event(event) is False


def test_connector_validates_event_when_import_only_published_and_event_published(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when "import_only_published" is True and the event is published.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_only_published"] = True

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "published": True}}
    )

    assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_when_import_only_published_and_event_not_published(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector doesn't validate an event when "import_only_published" is True and the event is not published.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_only_published"] = True

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "published": False}}
    )

    assert connector._validate_event(event) is False


def test_connector_validates_event_not_yet_processed_by_creation_date(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "date"

    connector = fake_misp_connector(config_dict)

    with patch.object(connector, "work_manager") as mock_work_manager:
        mock_work_manager.get_state.return_value = {
            "current_event_id": "1",
            "remaining_objects_count": 0,
        }
        event = EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": "42",
                    "date": "2026-01-01",
                }
            }
        )
        assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_already_processed_by_creation_date(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "date"

    connector = fake_misp_connector(config_dict)

    with patch.object(connector, "work_manager") as mock_work_manager:
        mock_work_manager.get_state.return_value = {
            "current_event_id": "100",
            "remaining_objects_count": 0,
        }
        event = EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": "42",
                    "date": "2026-01-01",
                }
            }
        )
        assert connector._validate_event(event) is False


def test_connector_validates_event_not_yet_processed_by_update_datetime(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "timestamp"

    connector = fake_misp_connector(config_dict)

    with patch.object(connector, "work_manager") as mock_work_manager:
        mock_work_manager.get_state.return_value = {
            "last_event_date": "2026-01-01T00:00:00+00:00",
            "remaining_objects_count": 0,
        }
        event = EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": "42",
                    "timestamp": str(
                        int(datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp())
                    ),
                }
            }
        )
        assert connector._validate_event(event) is True


def test_connector_creates_misp_client_with_request_timeout_from_config(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that MISPClient is instantiated with timeout from config.misp.request_timeout.
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["request_timeout"] = 90.0

    with patch("connector.connector.MISPClient") as mock_misp_client_class:
        fake_misp_connector(config_dict)
        mock_misp_client_class.assert_called_once()
        call_kwargs = mock_misp_client_class.call_args.kwargs
        assert call_kwargs["timeout"] == 90.0


def test_connector_creates_misp_client_with_request_timeout_none(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that MISPClient is instantiated with timeout=None when request_timeout is None.
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["request_timeout"] = None

    with patch("connector.connector.MISPClient") as mock_misp_client_class:
        fake_misp_connector(config_dict)
        mock_misp_client_class.assert_called_once()
        call_kwargs = mock_misp_client_class.call_args.kwargs
        assert call_kwargs["timeout"] is None


def test_connector_does_not_validate_event_already_processed_by_update_datetime(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "timestamp"

    connector = fake_misp_connector(config_dict)

    with patch.object(connector, "work_manager") as mock_work_manager:
        mock_work_manager.get_state.return_value = {
            "last_event_date": "2026-01-02T00:00:00+00:00",
            "remaining_objects_count": 0,
        }
        event = EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": "42",
                    "timestamp": str(
                        int(datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp())
                    ),
                }
            }
        )
        # Timestamp is the same as the last event date, so the event should be validated
        assert connector._validate_event(event) is True

        event = EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": "42",
                    "timestamp": str(
                        int(
                            datetime.fromisoformat(
                                "2026-01-01T23:59:59+00:00"
                            ).timestamp()
                        )
                    ),
                }
            }
        )
        # Timestamp is before the last event date, so the event should not be validated
        assert connector._validate_event(event) is False


def _make_publish_timestamp_event(event_id: str, ts: int) -> EventRestSearchListItem:
    return EventRestSearchListItem.model_validate(
        {"Event": {"id": event_id, "publish_timestamp": str(ts)}}
    )


def _run_process_events(connector, events, buffering_sequence, initial_state=None):
    """
    Run `process_events` with all external dependencies mocked.

    Returns:
        (state dict, mock for _process_bundle_in_batch, process_events return value)
    """
    state = dict(initial_state or {})

    def track_update_state(state_update=None, **kwargs):
        if state_update:
            state.update(state_update)

    with (
        patch.object(connector, "helper") as mock_helper,
        patch.object(connector, "work_manager") as mock_wm,
        patch.object(connector, "client_api") as mock_api,
        patch.object(connector, "converter") as mock_converter,
        patch.object(connector, "batch_processor"),
        patch.object(connector, "_process_bundle_in_batch") as mock_process,
    ):
        mock_helper.get_state.return_value = initial_state or {}
        mock_helper.metric = MagicMock()

        mock_wm.get_state.side_effect = lambda: dict(state)
        mock_wm.update_state.side_effect = track_update_state
        if isinstance(buffering_sequence, list):
            mock_wm.check_connector_buffering.side_effect = buffering_sequence
        else:
            mock_wm.check_connector_buffering.return_value = buffering_sequence

        mock_api.search_events.return_value = iter(events)
        mock_converter.process.return_value = (MagicMock(), [], [MagicMock()])

        result = connector.process_events()

    return state, mock_process, result


@freeze_time("2026-01-01 00:00:00")
def test_process_events_state_updated_before_buffering_check(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that `last_event_date` is set to the current event's timestamp BEFORE
    the buffering check is performed.

    Scenario:
    - Event A (earlier timestamp): processed normally.
    - Event B (later timestamp): buffering detected → loop breaks.

    Expected: after the run, `last_event_date` equals event B's timestamp (not
    A's), so that MISP's date filter excludes event A on the next run.
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
    connector = fake_misp_connector(config_dict)

    ts_a = int(time.time())
    ts_b = int(time.time() + 1)

    event_a = _make_publish_timestamp_event("1", ts_a)
    event_b = _make_publish_timestamp_event("2", ts_b)

    # No buffering for A, buffering triggers on B
    state, _, result = _run_process_events(
        connector, [event_a, event_b], buffering_sequence=[False, True]
    )

    expected = datetime.fromtimestamp(ts_b, tz=timezone.utc).isoformat()
    assert state.get("last_event_date") == expected


@freeze_time("2026-01-01 00:00:00")
def test_process_events_buffered_event_not_processed(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that when buffering is detected for event B, `_process_bundle_in_batch`
    is NOT called for it — even though the state has already been advanced to
    its timestamp.
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
    connector = fake_misp_connector(config_dict)

    ts_a = int(time.time())
    ts_b = int(time.time() + 1)

    event_a = _make_publish_timestamp_event("1", ts_a)
    event_b = _make_publish_timestamp_event("2", ts_b)

    state, mock_process, _ = _run_process_events(
        connector, [event_a, event_b], buffering_sequence=[False, True]
    )

    # Only event A should have been processed
    assert mock_process.call_count == 1
    assert mock_process.call_args[1]["event"] == event_a


def test_process_events_adds_one_second_after_loop_completion(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that after the event loop completes without interruption, `last_event_date`
    is advanced by 1 second. This prevents events at the exact boundary timestamp
    from being re-queried (and reprocessed) on the next run.
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
    connector = fake_misp_connector(config_dict)

    with freeze_time("2026-01-01 00:00:00") as frozen_time:
        ts = int(time.time())
        event = _make_publish_timestamp_event("1", ts)

        # No buffering — loop completes normally
        state, _, result = _run_process_events(
            connector, [event], buffering_sequence=False
        )

        # ts == Now, so no 1 second added
        expected = (datetime.fromtimestamp(ts, tz=timezone.utc)).isoformat()
        assert state.get("last_event_date") == expected
        assert result is None

        frozen_time.move_to("2026-01-01 00:00:01")
        state, _, result = _run_process_events(
            connector, [event], buffering_sequence=False
        )
        expected = (
            datetime.fromtimestamp(ts, tz=timezone.utc) + timedelta(seconds=1)
        ).isoformat()
        assert state.get("last_event_date") == expected
        assert result is None
