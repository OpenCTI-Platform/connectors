"""Tests for CVEConnector._maintain_data date-range splitting.

The NVD API rejects any lastModStartDate/lastModEndDate range longer than
MAX_AUTHORIZED (120) days. _maintain_data must split a longer last_run-to-now
range into consecutive windows of at most MAX_AUTHORIZED days each.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from src.connector.cve_connector import CVEConnector
from src.services.utils import MAX_AUTHORIZED


def _make_bare_connector() -> CVEConnector:
    connector = object.__new__(CVEConnector)
    connector.helper = MagicMock()
    connector.converter = MagicMock()
    return connector


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def test_maintain_data_splits_ranges_exceeding_max_authorized_days():
    connector = _make_bare_connector()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    last_run = (now - timedelta(days=250)).timestamp()

    with patch.object(connector, "_async_ingest", new=AsyncMock()) as mock_ingest:
        connector._maintain_data(now, last_run)

    captured_params = [call.args[0] for call in mock_ingest.call_args_list]
    assert len(captured_params) == 3

    first_start = _parse(captured_params[0]["lastModStartDate"])
    assert first_start == datetime.fromtimestamp(last_run, tz=timezone.utc)

    last_end = _parse(captured_params[-1]["lastModEndDate"])
    assert last_end == now

    for previous, current in zip(captured_params, captured_params[1:]):
        assert previous["lastModEndDate"] == current["lastModStartDate"]

    for params in captured_params:
        start = _parse(params["lastModStartDate"])
        end = _parse(params["lastModEndDate"])
        assert (end - start) <= timedelta(days=MAX_AUTHORIZED)


def test_maintain_data_uses_single_window_within_max_authorized_days():
    connector = _make_bare_connector()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    last_run = (now - timedelta(days=5)).timestamp()

    with patch.object(connector, "_async_ingest", new=AsyncMock()) as mock_ingest:
        connector._maintain_data(now, last_run)

    captured_params = [call.args[0] for call in mock_ingest.call_args_list]
    assert len(captured_params) == 1
    assert captured_params[0]["lastModStartDate"] == datetime.fromtimestamp(
        last_run, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert captured_params[0]["lastModEndDate"] == now.strftime("%Y-%m-%dT%H:%M:%SZ")
