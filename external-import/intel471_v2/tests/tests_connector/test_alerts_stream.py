import datetime
from queue import Queue
from types import SimpleNamespace
from unittest.mock import MagicMock

from intel471.streams.verity471.alerts import (
    ALERTS_MIGRATION_MARGIN_MS,
    Verity471AlertsStream,
)


def _config(**overrides):
    values = {
        "watcher_group_ids": [],
        "watcher_ids": [],
        "statuses": [],
        "is_trashed_included": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _build_alerts_stream(state=None, connector_config=None):
    """
    Build an alerts stream whose helper-state access is served from an in-memory dict,
    so the cursor/fingerprint/last-seen logic can be exercised without the queue-based
    state handler that runs in the connector.
    """
    state = {} if state is None else state
    stream = Verity471AlertsStream(
        MagicMock(),
        MagicMock(),
        Queue(),
        Queue(),
        connector_config=connector_config,
    )
    stream._get_state = lambda key: state.get(key)
    stream._set_state = lambda key, value: state.__setitem__(key, value)
    return stream, state


def test_get_api_kwargs_includes_filters_when_set():
    config = _config(
        watcher_group_ids=["1", "2"],
        watcher_ids=["9"],
        statuses=["generated", "completed"],
        is_trashed_included=True,
    )
    stream, _ = _build_alerts_stream(connector_config=config)

    kwargs = stream._get_api_kwargs(cursor="abc")

    assert kwargs["watcher_group_ids"] == "1,2"
    assert kwargs["watcher_ids"] == "9"
    assert kwargs["statuses"] == "generated,completed"
    assert kwargs["is_trashed_included"] is True
    assert kwargs["cursor"] == "abc"
    assert "var_from" in kwargs and "size" in kwargs


def test_get_api_kwargs_omits_filters_when_empty():
    stream, _ = _build_alerts_stream(connector_config=_config())

    kwargs = stream._get_api_kwargs(cursor=None)

    for key in ("watcher_group_ids", "watcher_ids", "statuses", "is_trashed_included"):
        assert key not in kwargs
    assert "cursor" not in kwargs
    assert "var_from" in kwargs and "size" in kwargs


def test_get_api_kwargs_tolerates_missing_config():
    stream, _ = _build_alerts_stream(connector_config=None)

    kwargs = stream._get_api_kwargs(cursor=None)

    assert "watcher_group_ids" not in kwargs
    assert "var_from" in kwargs and "size" in kwargs


def test_first_run_records_fingerprint_and_keeps_cursor():
    state = {"alerts_cursor_v471": "cur1"}
    stream, state = _build_alerts_stream(
        state=state, connector_config=_config(statuses=["generated"])
    )

    assert stream._get_cursor() == "cur1"
    assert state["alerts_filters_v471"] == stream._filters_fingerprint()
    assert state["alerts_cursor_v471"] == "cur1"


def test_unchanged_filters_keep_cursor():
    config = _config(statuses=["generated"])
    stream, state = _build_alerts_stream(
        state={"alerts_cursor_v471": "cur1"}, connector_config=config
    )
    state["alerts_filters_v471"] = stream._filters_fingerprint()

    assert stream._get_cursor() == "cur1"
    assert state["alerts_cursor_v471"] == "cur1"


def test_changed_filters_discard_cursor_and_reanchor_from_lastseen():
    lastseen = 1_700_000_000_000
    old_initdate = 1_690_000_000_000
    state = {
        "alerts_cursor_v471": "cur1",
        "alerts_filters_v471": "stale-fingerprint",
        "alerts_lastseen_v471": lastseen,
        "alerts_initdate_v471": old_initdate,
    }
    stream, state = _build_alerts_stream(
        state=state, connector_config=_config(statuses=["completed"])
    )

    assert stream._get_cursor() is None
    assert state["alerts_cursor_v471"] is None
    assert state["alerts_initdate_v471"] == lastseen - ALERTS_MIGRATION_MARGIN_MS
    assert state["alerts_filters_v471"] == stream._filters_fingerprint()
    stream.helper.log_warning.assert_called_once()


def test_reanchor_never_moves_from_date_backwards():
    """A `lastseen - margin` earlier than the current floor must not move it back."""
    lastseen = 1_700_000_000_000
    high_initdate = lastseen + 5_000_000  # already ahead of the re-anchor point
    state = {
        "alerts_cursor_v471": "cur1",
        "alerts_filters_v471": "stale",
        "alerts_lastseen_v471": lastseen,
        "alerts_initdate_v471": high_initdate,
    }
    stream, state = _build_alerts_stream(
        state=state, connector_config=_config(statuses=["completed"])
    )

    assert stream._get_cursor() is None
    assert state["alerts_initdate_v471"] == high_initdate


def test_changed_filters_without_lastseen_fall_back_to_now():
    state = {
        "alerts_cursor_v471": "cur1",
        "alerts_filters_v471": "stale",
        "alerts_initdate_v471": 1_000_000_000_000,
    }
    stream, state = _build_alerts_stream(
        state=state, connector_config=_config(statuses=["completed"])
    )

    before = int(datetime.datetime.now(datetime.UTC).timestamp() * 1000)
    assert stream._get_cursor() is None
    after = int(datetime.datetime.now(datetime.UTC).timestamp() * 1000)

    new_initdate = state["alerts_initdate_v471"]
    assert (
        before - ALERTS_MIGRATION_MARGIN_MS
        <= new_initdate
        <= after - ALERTS_MIGRATION_MARGIN_MS
    )


def test_lastseen_tracks_max_creation_ts_and_persists():
    stream, state = _build_alerts_stream(connector_config=_config())
    dt1 = datetime.datetime(2023, 10, 1, tzinfo=datetime.UTC)
    dt2 = datetime.datetime(2023, 10, 2, tzinfo=datetime.UTC)
    api_response = SimpleNamespace(
        alerts=[
            SimpleNamespace(creation_ts=dt1),
            SimpleNamespace(creation_ts=dt2),
        ],
        cursor_next="next-cur",
    )

    assert stream._get_cursor_value(api_response) == "next-cur"
    assert stream._lastseen_ms == int(dt2.timestamp() * 1000)

    stream._update_cursor("next-cur")
    assert state["alerts_lastseen_v471"] == int(dt2.timestamp() * 1000)
    assert state["alerts_cursor_v471"] == "next-cur"


def test_empty_page_leaves_lastseen_untouched():
    stream, _ = _build_alerts_stream(connector_config=_config())
    stream._lastseen_ms = 123
    api_response = SimpleNamespace(alerts=None, cursor_next="c")

    assert stream._get_cursor_value(api_response) == "c"
    assert stream._lastseen_ms == 123
