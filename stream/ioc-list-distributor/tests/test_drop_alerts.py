"""Checks for EXPORT_WARN_DROP_PERCENT / EXPORT_ERROR_DROP_PERCENT: log only, never hold a file.

Run: python tests/test_drop_alerts.py (or pytest).
"""

import logging
import os
import sys
import tempfile
from pathlib import Path

os.environ["DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from common import config  # noqa: E402
from ioc_distributor.exporter import STATE_FILE, FeedExporter  # noqa: E402

KEYS = [
    "EXPORT_MAX_DROP_PERCENT",
    "EXPORT_WARN_DROP_PERCENT",
    "EXPORT_ERROR_DROP_PERCENT",
    "EXPORT_MAX_ENTRIES",
    "BACKUP_RETENTION",
    "CUSTOM_FEED1_ENABLED",
    "CUSTOM_FEED1_MAX_ENTRIES",
]
IPS = [f"8.8.{i}.1" for i in range(100)]


def _settings(**env):
    for key in KEYS:
        os.environ.pop(key, None)
    os.environ.update({k: str(v) for k, v in env.items()})
    return config.export_settings()


class _FakeStore:
    def __init__(self, ips):
        self.ips = ips

    def select_for_export(self, ioc_type, base_attribute, cutoff, now, sort_order):
        return [(v, None) for v in (self.ips if ioc_type == "ip" else [])]

    def purge_older_than(self, cutoff):
        return 0


def _clean():
    for d in (config.FEEDS_DIR, config.BACKUP_DIR, config.TMP_DIR):
        os.makedirs(d, exist_ok=True)
        for name in os.listdir(d):
            os.remove(os.path.join(d, name))
    state = os.path.join(config.DATA_DIR, STATE_FILE)
    if os.path.exists(state):
        os.remove(state)


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        if "last export" in record.getMessage():
            self.records.append((record.levelname, record.getMessage()))


def _run(before, after, **env):
    """Export `before` IPs, then `after` IPs; return (drop log lines of the 2nd export, ip.txt status)."""
    _clean()
    FeedExporter(
        _FakeStore(IPS[:before]), _settings(EXPORT_MAX_ENTRIES=0, **env)
    ).export_once()
    e = FeedExporter(_FakeStore(IPS[:after]), _settings(EXPORT_MAX_ENTRIES=0, **env))
    cap = _Capture()
    logging.getLogger().addHandler(cap)
    try:
        e.export_once()
    finally:
        logging.getLogger().removeHandler(cap)
    return cap.records, e.status()["files"]["ip.txt"]


def test_levels_one_line_highest_level():
    env = dict(EXPORT_WARN_DROP_PERCENT=30, EXPORT_ERROR_DROP_PERCENT=70)
    assert _run(100, 90, **env)[0] == []  # -10%: nothing
    lines, info = _run(100, 50, **env)  # -50%: WARNING
    assert lines == [
        ("WARNING", "ip.txt: 50 entries vs 100 last export (-50%), published")
    ]
    assert info["status"] == "written" and info["entries"] == 50
    lines, info = _run(100, 10, **env)  # -90%: one ERROR only
    assert lines == [
        ("ERROR", "ip.txt: 10 entries vs 100 last export (-90%), published")
    ]
    assert info["status"] == "written" and info["entries"] == 10


def test_off_by_default_and_each_separately():
    assert _run(100, 1)[0] == []  # both 0: off
    assert _run(100, 1, EXPORT_ERROR_DROP_PERCENT=70)[0][0][0] == "ERROR"
    assert _run(100, 50, EXPORT_ERROR_DROP_PERCENT=70)[0] == []
    assert _run(100, 1, EXPORT_WARN_DROP_PERCENT=30)[0][0][0] == "WARNING"


def test_no_alert_on_first_file_or_growth():
    _clean()
    e = FeedExporter(_FakeStore(IPS[:5]), _settings(EXPORT_WARN_DROP_PERCENT=1))
    cap = _Capture()
    logging.getLogger().addHandler(cap)
    try:
        e.export_once()
    finally:
        logging.getLogger().removeHandler(cap)
    assert cap.records == []
    assert _run(10, 100, EXPORT_WARN_DROP_PERCENT=1)[0] == []


def test_config_bad_values_and_order():
    s = _settings(EXPORT_WARN_DROP_PERCENT="abc", EXPORT_ERROR_DROP_PERCENT=150)
    assert s.warn_drop_percent == 0 and s.error_drop_percent == 0
    assert any("EXPORT_WARN_DROP_PERCENT" in w for w in s.warnings)
    assert any("EXPORT_ERROR_DROP_PERCENT" in w for w in s.warnings)
    s = _settings(EXPORT_WARN_DROP_PERCENT=70, EXPORT_ERROR_DROP_PERCENT=30)
    assert any("is not above EXPORT_WARN_DROP_PERCENT" in w for w in s.warnings)
    lines, _ = _run(100, 50, EXPORT_WARN_DROP_PERCENT=70, EXPORT_ERROR_DROP_PERCENT=30)
    assert lines[0][0] == "ERROR"  # above ERROR value: never lost


def test_custom_feed_checked_on_its_own():
    lines, _ = _run(
        100,
        40,
        EXPORT_WARN_DROP_PERCENT=30,
        CUSTOM_FEED1_ENABLED="true",
        CUSTOM_FEED1_MAX_ENTRIES=0,
    )
    assert (
        "WARNING",
        "custom1_ip.txt: 40 entries vs 100 last export (-60%), published",
    ) in lines


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
