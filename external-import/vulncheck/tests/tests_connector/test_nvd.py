"""Tests for build_nvd2_query_params precedence (override > state > first-run)."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from connector.sources import names
from connector.util.nvd import build_nvd2_query_params

SRC = names.NIST_NVD2

# Fixed "now" so first-run window assertions can't flake on a midnight rollover
# between the test's datetime.now() and the one inside build_nvd2_query_params.
FROZEN_NOW = datetime(2026, 6, 27, 12, 0, 0)


def _config(**nvd2):
    # Mirrors post-validation types: max_date_range is a timedelta and the
    # last-mod overrides are datetimes (SimpleNamespace bypasses pydantic).
    base = dict(
        nvd2_last_mod_start_date=None,
        nvd2_last_mod_end_date=None,
        nvd2_pull_history=False,
        nvd2_max_date_range=timedelta(days=120),
    )
    base.update(nvd2)
    return SimpleNamespace(vulncheck=SimpleNamespace(**base))


def _params(config, state):
    return build_nvd2_query_params(config, state, SRC, MagicMock())


def test_explicit_override_wins_over_state():
    params = _params(
        _config(nvd2_last_mod_start_date=datetime(2024, 1, 1)),
        {SRC: "2026-06-20 10:00:00"},
    )
    assert params == {"last_mod_start_date": "2024-01-01"}


def test_state_drives_incremental():
    assert _params(_config(), {SRC: "2026-06-20 10:00:00"}) == {
        "last_mod_start_date": "2026-06-20"
    }


def test_first_run_bounded_by_max_date_range():
    with patch("connector.util.nvd.datetime") as mock_dt:
        mock_dt.now.return_value = FROZEN_NOW
        params = _params(_config(), None)
    expected = (FROZEN_NOW - timedelta(days=120)).strftime("%Y-%m-%d")
    assert params == {"last_mod_start_date": expected}


def test_first_run_custom_max_date_range():
    with patch("connector.util.nvd.datetime") as mock_dt:
        mock_dt.now.return_value = FROZEN_NOW
        params = _params(_config(nvd2_max_date_range=timedelta(days=7)), {})
    expected = (FROZEN_NOW - timedelta(days=7)).strftime("%Y-%m-%d")
    assert params == {"last_mod_start_date": expected}


def test_pull_history_means_no_filter():
    assert _params(_config(nvd2_pull_history=True), None) == {}


def test_end_date_added():
    params = _params(
        _config(nvd2_pull_history=True, nvd2_last_mod_end_date=datetime(2026, 6, 27)),
        None,
    )
    assert params == {"last_mod_end_date": "2026-06-27"}
