"""Tests for CVEConnector._import_history.

The history import must page NVD by PUBLICATION date. The modification index
(lastModStartDate) does not retain history: NVD re-stamps a CVE whenever it
touches the record, so old windows contain no lastMod rows at all. Measured
against the live NVD API on 2026-11-10, 2016-01-01..2016-04-10:

    pubStartDate      -> 1,519 CVEs
    lastModStartDate  -> 0 CVEs

The scheduled path must keep asking for lastMod: a 2-hour incremental run that
asked "what was published" would re-import the corpus on every tick.
"""

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.connector.cve_connector import CVEConnector
from src.services.utils import MAX_AUTHORIZED

UTC = timezone.utc


def _bare_connector() -> CVEConnector:
    connector = object.__new__(CVEConnector)
    connector.helper = MagicMock()
    connector.converter = MagicMock()
    return connector


def _dt(*args) -> datetime:
    return datetime(*args, tzinfo=UTC)


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _captured(connector, start, end):
    with patch.object(connector, "_async_ingest", new=AsyncMock()) as mock_ingest:
        connector._import_history(start, end)
    return [call.args[0] for call in mock_ingest.call_args_list]


# ---------------------------------------------------------------- scheduled path


def test_update_cve_params_default_is_unchanged():
    """No date_field argument must produce exactly the pre-existing params."""
    assert CVEConnector._update_cve_params(_dt(2026, 1, 1), _dt(2026, 1, 2)) == {
        "lastModStartDate": "2026-01-01T00:00:00Z",
        "lastModEndDate": "2026-01-02T00:00:00Z",
    }


def test_maintain_data_still_queries_last_mod():
    """The incremental run must stay lastMod-based, not switch to publication."""
    connector = _bare_connector()
    now = _dt(2026, 1, 1)
    with patch.object(connector, "_async_ingest", new=AsyncMock()) as mock_ingest:
        connector._maintain_data(now, (now - timedelta(days=5)).timestamp())
    for call in mock_ingest.call_args_list:
        assert "lastModStartDate" in call.args[0]
        assert "pubStartDate" not in call.args[0]


# ------------------------------------------------------------------ history path


def test_history_queries_publication_dates_only():
    connector = _bare_connector()
    params = _captured(connector, _dt(2016, 1, 1), _dt(2016, 12, 31))

    assert len(params) == 4  # 120 + 120 + 120 + 5
    for single in params:
        assert set(single) == {"pubStartDate", "pubEndDate"}


def test_history_windows_are_contiguous_and_within_max_authorized():
    connector = _bare_connector()
    params = _captured(connector, _dt(2016, 1, 1), _dt(2016, 12, 31))

    windows = [(_parse(p["pubStartDate"]), _parse(p["pubEndDate"])) for p in params]
    assert windows[0][0] == _dt(2016, 1, 1)
    assert windows[-1][1] == _dt(2016, 12, 31)

    for previous, current in zip(windows, windows[1:]):
        assert previous[1] + timedelta(seconds=1) == current[0]

    for start, end in windows:
        assert timedelta(0) < (end - start) <= timedelta(days=MAX_AUTHORIZED)


def test_history_emits_no_empty_trailing_window():
    """Regression: both branches used to run, re-sending a zero-length window
    whenever the requested end date fell inside the current year."""
    connector = _bare_connector()
    end = _dt(2026, 3, 1)
    params = _captured(connector, _dt(2025, 12, 1), end)

    windows = [(_parse(p["pubStartDate"]), _parse(p["pubEndDate"])) for p in params]
    assert all(start < stop for start, stop in windows)
    assert windows[-1][1] == end


def test_history_honours_start_date_inside_the_first_year():
    """A mid-year start must not silently begin on 1 January, and must not
    overshoot the requested end date."""
    connector = _bare_connector()
    params = _captured(connector, _dt(2016, 5, 1), _dt(2016, 6, 1))

    windows = [(_parse(p["pubStartDate"]), _parse(p["pubEndDate"])) for p in params]
    assert windows[0][0] == _dt(2016, 5, 1)
    assert windows[-1][1] == _dt(2016, 6, 1)
    for start, end in windows:
        assert end <= _dt(2016, 6, 1)


def test_history_covers_a_multi_year_span_without_gaps():
    connector = _bare_connector()
    params = _captured(connector, _dt(2018, 1, 1), _dt(2019, 12, 31))

    windows = [(_parse(p["pubStartDate"]), _parse(p["pubEndDate"])) for p in params]
    assert windows[0][0] == _dt(2018, 1, 1)
    assert windows[-1][1] == _dt(2019, 12, 31)
    for previous, current in zip(windows, windows[1:]):
        assert previous[1] + timedelta(seconds=1) == current[0]


# ------------------------------------------------ PR #8365 review regressions


def test_history_persists_a_cursor_after_every_window():
    """A run that dies mid-import must leave a resume point. In production a
    DNS/AMQP failure killed a 2018 import after its second window and left no
    record of where it stopped, so September-December of that year were silently
    absent and the connector reported success."""
    connector = _bare_connector()
    params = _captured(connector, _dt(2016, 1, 1), _dt(2016, 12, 31))

    window_ends = [_parse(p["pubEndDate"]) for p in params]
    cursors = [
        call.args[0]["history_cursor"]
        for call in connector.helper.set_state.call_args_list
    ]
    assert cursors == [end.strftime("%Y-%m-%dT%H:%M:%SZ") for end in window_ends]


def test_history_final_window_ends_on_the_actual_timestamp():
    """A run ending mid-day must query up to that instant, not the previous
    midnight. ``date_range.days`` truncated the final part-day while last_run was
    still recorded as "now", so CVEs published in the gap were missed by both the
    history and the incremental path."""
    connector = _bare_connector()
    end = _dt(2026, 11, 12, 12, 30)
    params = _captured(connector, _dt(2026, 11, 1), end)

    windows = [(_parse(p["pubStartDate"]), _parse(p["pubEndDate"])) for p in params]
    assert windows[-1][1] == end


def test_history_windows_never_share_a_boundary():
    """NVD treats both bounds as inclusive, so a shared boundary returns the same
    CVE in two consecutive windows and queues a duplicate bundle."""
    connector = _bare_connector()
    params = _captured(connector, _dt(2016, 1, 1), _dt(2016, 12, 31))

    windows = [(_parse(p["pubStartDate"]), _parse(p["pubEndDate"])) for p in params]
    bounds = [instant for window in windows for instant in window]
    assert len(bounds) == len(set(bounds))
    for previous, current in zip(windows, windows[1:]):
        assert previous[1] < current[0]


def test_history_cursor_with_offset_is_converted_to_utc():
    """``replace(tzinfo=utc)`` relabels +05:00 as midnight UTC and would resume
    five hours late; the offset must be converted."""
    assert CVEConnector._parse_history_bound("2026-03-01T00:00:00+05:00") == _dt(
        2026, 2, 28, 19, 0
    )


def test_history_cursor_without_offset_is_read_as_utc():
    assert CVEConnector._parse_history_bound("2026-03-01T00:00:00") == _dt(2026, 3, 1)


def _processing_connector(state):
    connector = _bare_connector()
    connector.interval = 7200
    connector.config = MagicMock()
    connector.config.cve.pull_history = True
    connector.config.cve.history_start_year = 2016
    connector.config.cve.maintain_data = True
    connector.config.cve.max_date_range = 7
    connector.helper.get_state.return_value = state
    connector.update_connector_state = MagicMock()
    connector._import_history = MagicMock()
    connector._import_recent = MagicMock()
    connector._maintain_data = MagicMock()
    return connector


def test_history_runs_when_pull_history_is_enabled_on_a_running_connector():
    """The history branch was only reachable while last_run was absent, so
    enabling pull_history on a connector that had already run imported nothing
    and logged "next run in X hours" forever."""
    connector = _processing_connector({"last_run": 1794392878})

    with patch("time.sleep"):
        connector.process_data()

    start, _ = connector._import_history.call_args.args
    assert start == _dt(2016, 1, 1)
    connector._maintain_data.assert_not_called()


def test_interrupted_history_resumes_from_its_cursor():
    connector = _processing_connector(
        {"last_run": 1794392878, "history_cursor": "2016-06-01T00:00:00Z"}
    )

    with patch("time.sleep"):
        connector.process_data()

    start, _ = connector._import_history.call_args.args
    assert start == _dt(2016, 6, 1)
    connector._maintain_data.assert_not_called()


def test_completed_history_marks_done_and_records_last_run():
    """history_done stops a finished import from running again, and last_run is
    written in the same state update."""
    connector = _processing_connector({"last_run": 1794392878})

    with patch("time.sleep"):
        connector.process_data()

    connector.update_connector_state.assert_called_once()
    assert connector.update_connector_state.call_args.args[1] == {"history_done": True}


def test_completed_history_falls_through_to_the_incremental_run():
    connector = _processing_connector(
        {"last_run": int(time.time()) - 10**6, "history_done": True}
    )

    with patch("time.sleep"):
        connector.process_data()

    connector._import_history.assert_not_called()
    connector._maintain_data.assert_called_once()


def test_history_keeps_progress_when_a_window_fails():
    """One failed window must not discard the work already done: the cursor is
    written per window, so the next run resumes at the last completed one."""
    connector = _bare_connector()
    calls = {"n": 0}

    async def flaky(params):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("NVD 503")

    with patch.object(connector, "_async_ingest", new=flaky):
        with pytest.raises(RuntimeError):
            connector._import_history(_dt(2016, 1, 1), _dt(2016, 12, 31))

    cursors = [
        call.args[0]["history_cursor"]
        for call in connector.helper.set_state.call_args_list
    ]
    assert len(cursors) == 2, "both completed windows must be persisted"


def test_history_rejects_an_inverted_range():
    """A range that runs backwards used to emit no request and no log line, so
    the connector reported success while importing nothing."""
    connector = _bare_connector()
    assert _captured(connector, _dt(2027, 1, 1), _dt(2026, 1, 1)) == []


def test_process_data_restarts_history_when_the_cursor_is_ahead_of_the_clock():
    connector = _processing_connector(
        {"last_run": 1794392878, "history_cursor": "2030-01-01T00:00:00Z"}
    )

    with patch("time.sleep"):
        connector.process_data()

    start, _ = connector._import_history.call_args.args
    assert start == _dt(2016, 1, 1)


def test_unknown_date_field_is_rejected():
    """An unknown date_field must raise, not silently fall back to lastMod -
    that fallback is the original defect."""
    with pytest.raises(ValueError):
        CVEConnector._update_cve_params(
            _dt(2016, 1, 1), _dt(2016, 2, 1), date_field="publication"
        )
