"""Tests for build_nvd2_query_params precedence (override > state > first-run)."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

from connector.sources import names
from connector.util.nvd import build_nvd2_query_params

SRC = names.NIST_NVD2


def _config(**nvd2):
    base = dict(
        nvd2_last_mod_start_date=None,
        nvd2_last_mod_end_date=None,
        nvd2_pull_history=False,
        nvd2_max_date_range=120,
    )
    base.update(nvd2)
    return SimpleNamespace(vulncheck=SimpleNamespace(**base))


def _params(config, state):
    return build_nvd2_query_params(config, state, SRC, MagicMock())


def test_explicit_override_wins_over_state():
    params = _params(
        _config(nvd2_last_mod_start_date="2024-01-01"), {SRC: "2026-06-20 10:00:00"}
    )
    assert params == {"last_mod_start_date": "2024-01-01"}


def test_state_drives_incremental():
    assert _params(_config(), {SRC: "2026-06-20 10:00:00"}) == {
        "last_mod_start_date": "2026-06-20"
    }


def test_first_run_bounded_by_max_date_range():
    expected = (datetime.now() - timedelta(days=120)).strftime("%Y-%m-%d")
    assert _params(_config(), None) == {"last_mod_start_date": expected}


def test_first_run_custom_max_date_range():
    expected = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
    assert _params(_config(nvd2_max_date_range=7), {}) == {
        "last_mod_start_date": expected
    }


def test_pull_history_means_no_filter():
    assert _params(_config(nvd2_pull_history=True), None) == {}


def test_end_date_added():
    params = _params(
        _config(nvd2_pull_history=True, nvd2_last_mod_end_date="2026-06-27"), None
    )
    assert params == {"last_mod_end_date": "2026-06-27"}
