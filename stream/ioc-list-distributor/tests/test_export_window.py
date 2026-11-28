"""Checks for the per-type rolling windows (EXPORT_ROLLING_WINDOW_MINUTES_<TYPE>).

Run: python tests/test_export_window.py (or pytest).
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ["DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from common import config  # noqa: E402
from ioc_distributor.exporter import FeedExporter  # noqa: E402

KEYS = ["EXPORT_ROLLING_WINDOW_MINUTES"] + [
    f"EXPORT_ROLLING_WINDOW_MINUTES_{t.upper()}" for t in config.IOC_TYPES
]


def _settings(**env):
    for key in KEYS:
        os.environ.pop(key, None)
    os.environ.update({k: str(v) for k, v in env.items()})
    return config.export_settings()


def _expect_exit(**env):
    try:
        _settings(**env)
    except SystemExit as exc:
        return str(exc)
    raise AssertionError(f"expected a startup error for {env}")


def test_defaults():
    s = _settings()
    assert all(s.window_minutes(t) == 43200 for t in config.IOC_TYPES)


def test_blank_uses_default():
    s = _settings(
        EXPORT_ROLLING_WINDOW_MINUTES=1440, EXPORT_ROLLING_WINDOW_MINUTES_IP=""
    )
    assert all(s.window_minutes(t) == 1440 for t in config.IOC_TYPES)


def test_per_type_override_and_zero():
    s = _settings(
        EXPORT_ROLLING_WINDOW_MINUTES=43200,
        EXPORT_ROLLING_WINDOW_MINUTES_HASH=129600,
        EXPORT_ROLLING_WINDOW_MINUTES_IP=10080,
        EXPORT_ROLLING_WINDOW_MINUTES_URL=0,
    )
    assert s.window_minutes("hash") == 129600
    assert s.window_minutes("ip") == 10080
    assert s.window_minutes("url") == 0
    assert s.window_minutes("domain") == 43200


def test_invalid_values_stop_startup():
    assert "EXPORT_ROLLING_WINDOW_MINUTES_IP" in _expect_exit(
        EXPORT_ROLLING_WINDOW_MINUTES_IP="7d"
    )
    assert "EXPORT_ROLLING_WINDOW_MINUTES_HASH" in _expect_exit(
        EXPORT_ROLLING_WINDOW_MINUTES_HASH=-1
    )


class _FakeStore:
    """Records the window start the exporter asks for, per type."""

    def __init__(self):
        self.cutoffs = {}

    def select_for_export(self, ioc_type, base_attribute, cutoff, now, sort_order):
        self.cutoffs[ioc_type] = cutoff
        return []

    def purge_older_than(self, cutoff):
        return 0


def _parse(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def test_exporter_uses_each_types_window():
    s = _settings(
        EXPORT_ROLLING_WINDOW_MINUTES=43200,
        EXPORT_ROLLING_WINDOW_MINUTES_HASH=129600,
        EXPORT_ROLLING_WINDOW_MINUTES_IP=10080,
        EXPORT_ROLLING_WINDOW_MINUTES_URL=0,
    )
    store = _FakeStore()
    exporter = FeedExporter(store, s)
    before = datetime.now(timezone.utc)
    exporter.export_once()
    assert exporter.status()["last_error"] is None, exporter.status()["last_error"]
    assert store.cutoffs["url"] is None  # 0 = no window
    for ioc_type, minutes in (("hash", 129600), ("ip", 10080), ("domain", 43200)):
        age = before - _parse(store.cutoffs[ioc_type])
        assert abs(age - timedelta(minutes=minutes)) < timedelta(seconds=60), (
            ioc_type,
            age,
        )
    assert exporter.status()["files"]["hash.txt"]["window_minutes"] == 129600


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("all per-type window checks passed")
