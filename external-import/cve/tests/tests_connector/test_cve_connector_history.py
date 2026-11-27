"""Tests for the incremental progress of the CVE history import.

The history import (CVE_HISTORY_PULL_HISTORY) walks NVD from
CVE_HISTORY_START_YEAR to now in windows of at most MAX_AUTHORIZED days.
It saves its progress after each window is sent, so an interruption (a
restart of the connector or of the OpenCTI API, a failed send) resumes at
the first window not sent instead of starting again from 1 January of
CVE_HISTORY_START_YEAR. The maintain mode's last_run is written only once
the whole history is imported.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from src.connector.cve_connector import (
    HISTORY_PROGRESS_KEY,
    HISTORY_START_YEAR_KEY,
    CVEConnector,
)
from src.services.utils import MAX_AUTHORIZED

START_YEAR = 2024


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _make_connector(state: dict) -> CVEConnector:
    """Build a CVEConnector whose state lives in `state`, as the platform keeps it."""
    connector = object.__new__(CVEConnector)
    connector.helper = MagicMock()
    connector.helper.get_state.side_effect = lambda: dict(state) if state else None

    def set_state(new_state):
        state.clear()
        state.update(new_state)

    connector.helper.set_state.side_effect = set_state
    connector.converter = MagicMock()
    connector.config = MagicMock()
    connector.config.cve.pull_history = True
    connector.config.cve.history_start_year = START_YEAR
    connector.config.cve.maintain_data = True
    connector.interval = 2 * 60 * 60
    return connector


def _run(connector: CVEConnector, fail_on_call: int | None = None) -> list[dict]:
    """Run process_data once; the ingestion of window `fail_on_call` (1-based) fails."""
    calls: list[dict] = []

    async def fake_ingest(cve_params):
        calls.append(cve_params)
        if fail_on_call is not None and len(calls) == fail_on_call:
            raise RuntimeError("OpenCTI API unavailable")

    with (
        patch.object(
            connector, "_async_ingest", new=AsyncMock(side_effect=fake_ingest)
        ),
        patch("src.connector.cve_connector.time.sleep"),
    ):
        connector.process_data()
    return calls


def test_history_windows_are_contiguous_bounded_and_within_a_year():
    start = datetime(2022, 1, 1, tzinfo=timezone.utc)
    end = datetime(2024, 3, 15, 10, 30, tzinfo=timezone.utc)

    windows = list(CVEConnector._history_windows(start, end))

    assert windows[0][1] == start
    assert windows[-1][2] == end
    for (_, _, previous_end), (_, current_start, _) in zip(windows, windows[1:]):
        assert previous_end == current_start
    for year, window_start, window_end in windows:
        assert window_start < window_end
        assert window_end - window_start <= timedelta(days=MAX_AUTHORIZED)
        assert window_start.year == year
        assert window_end <= datetime(year + 1, 1, 1, tzinfo=timezone.utc)


def test_history_saves_its_progress_after_each_window():
    state: dict = {}
    connector = _make_connector(state)
    saved: list[dict] = []
    connector.helper.set_state.side_effect = lambda new_state: saved.append(
        dict(new_state)
    )

    calls = _run(connector)

    progress = [entry for entry in saved if HISTORY_PROGRESS_KEY in entry]
    assert len(progress) == len(calls)
    for params, entry in zip(calls, progress):
        assert entry[HISTORY_START_YEAR_KEY] == START_YEAR
        assert entry[HISTORY_PROGRESS_KEY] == int(
            _parse(params["lastModEndDate"]).timestamp()
        )
        assert "last_run" not in entry
    # Once the whole history is imported, last_run replaces the progress.
    assert set(saved[-1]) == {"last_run"}


def test_interrupted_history_resumes_at_the_next_window():
    state: dict = {}
    connector = _make_connector(state)
    interrupted_window = 4

    first_calls = _run(connector, fail_on_call=interrupted_window)

    # Windows 1 to 3 were sent and saved; window 4 failed: no last_run yet.
    assert len(first_calls) == interrupted_window
    assert "last_run" not in state
    assert state[HISTORY_PROGRESS_KEY] == int(
        _parse(first_calls[interrupted_window - 2]["lastModEndDate"]).timestamp()
    )
    connector.helper.connector_logger.error.assert_called_once()

    second_calls = _run(connector)

    # The restart starts again at window 4, the first window not sent.
    assert (
        second_calls[0]["lastModStartDate"]
        == first_calls[interrupted_window - 1]["lastModStartDate"]
    )
    assert second_calls[0]["lastModStartDate"] != f"{START_YEAR}-01-01T00:00:00Z"
    assert set(state) == {"last_run"}
    resumed_logs = [
        call.args[0]
        for call in connector.helper.connector_logger.info.call_args_list
        if "Resuming the interrupted CVE history" in call.args[0]
    ]
    assert len(resumed_logs) == 1


def test_history_starts_again_when_the_start_year_changed():
    state = {
        HISTORY_START_YEAR_KEY: START_YEAR - 1,
        HISTORY_PROGRESS_KEY: int(
            datetime(2025, 6, 1, tzinfo=timezone.utc).timestamp()
        ),
    }
    connector = _make_connector(state)

    calls = _run(connector)

    assert calls[0]["lastModStartDate"] == f"{START_YEAR}-01-01T00:00:00Z"
    assert set(state) == {"last_run"}


def test_maintain_mode_ignores_history_progress_once_last_run_is_set():
    last_run = int(datetime.now(tz=timezone.utc).timestamp()) - 3 * 60 * 60
    state = {"last_run": last_run}
    connector = _make_connector(state)

    calls = _run(connector)

    assert len(calls) == 1
    assert _parse(calls[0]["lastModStartDate"]) == datetime.fromtimestamp(
        last_run, tz=timezone.utc
    )
    assert set(state) == {"last_run"}
