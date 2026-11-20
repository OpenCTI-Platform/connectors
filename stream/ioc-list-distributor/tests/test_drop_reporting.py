"""Checks for the reporting of a file held back by the drop protection:
the 'Export done' line and the /stats date of the file actually served.

Run: python tests/test_drop_reporting.py (or pytest).
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
    "EXPORT_KEEP_PREVIOUS_ON_EMPTY",
    "EXPORT_MAX_ENTRIES",
    "EXPORT_MAX_ENTRIES_IP",
    "BACKUP_RETENTION",
]


def _settings(**env):
    for key in KEYS:
        os.environ.pop(key, None)
    os.environ.update({k: str(v) for k, v in env.items()})
    return config.export_settings()


class _FakeStore:
    def __init__(self, rows=None):
        self.rows = rows or {}

    def select_for_export(self, ioc_type, base_attribute, cutoff, now, sort_order):
        return [(v, None) for v in self.rows.get(ioc_type, [])]

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
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


IPS = [f"8.8.{i}.1" for i in range(10)]


def _held_back(**env):
    _clean()
    first = FeedExporter(_FakeStore({"ip": IPS}), _settings(EXPORT_MAX_DROP_PERCENT=50))
    first.export_once()
    written_at = first.status()["files"]["ip.txt"]["generated_at"]
    e = FeedExporter(
        _FakeStore({"ip": IPS}), _settings(EXPORT_MAX_DROP_PERCENT=50, **env)
    )
    cap = _Capture()
    root = logging.getLogger()
    old_level = root.level
    root.setLevel(logging.INFO)
    root.addHandler(cap)
    try:
        e.export_once()
    finally:
        root.removeHandler(cap)
        root.setLevel(old_level)
    return e.status()["files"]["ip.txt"], written_at, cap.lines


def test_held_back_capped_file_summary_and_date():
    info, written_at, lines = _held_back(EXPORT_MAX_ENTRIES=3)  # 3 of 10: 70% drop
    assert info["status"] == "kept_previous" and info["entries"] == 10
    assert info["new_entries"] == 3
    assert info["generated_at"] == written_at  # date of the file served, not null
    done = [line for line in lines if line.startswith("Export done")][0]
    assert "ip.txt=10 (kept previous; new export 3, capped)" in done


def test_held_back_uncapped_summary():
    _clean()
    FeedExporter(
        _FakeStore({"ip": IPS}), _settings(EXPORT_MAX_DROP_PERCENT=50)
    ).export_once()
    e = FeedExporter(_FakeStore({"ip": IPS[:2]}), _settings(EXPORT_MAX_DROP_PERCENT=50))
    assert (
        FeedExporter._summary(
            "ip.txt",
            {
                "entries": 10,
                "status": "kept_previous",
                "new_entries": 2,
                "cap": {"capped": False},
            },
        )
        == "ip.txt=10 (kept previous; new export 2)"
    )
    e.export_once()
    assert e.status()["files"]["ip.txt"]["new_entries"] == 2


def test_written_summary_unchanged():
    assert (
        FeedExporter._summary(
            "ip.txt", {"entries": 5, "status": "written", "cap": {"capped": True}}
        )
        == "ip.txt=5 (capped)"
    )
    assert (
        FeedExporter._summary(
            "ip.txt", {"entries": 5, "status": "written", "cap": {"capped": False}}
        )
        == "ip.txt=5"
    )


def test_date_falls_back_to_file_time_without_state():
    _clean()
    with open(os.path.join(config.FEEDS_DIR, "ip.txt"), "w") as fh:
        fh.write("".join(f"{v}\n" for v in IPS))  # feed file without a saved state
    e = FeedExporter(_FakeStore({"ip": IPS[:1]}), _settings(EXPORT_MAX_DROP_PERCENT=50))
    e.export_once()
    info = e.status()["files"]["ip.txt"]
    assert info["status"] == "kept_previous" and info["generated_at"]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
