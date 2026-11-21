"""Checks for the exporter: filtering separate from formatting, drop protection
from the saved export state, backups named after the feed's own extension.

Run: python tests/test_exporter_cleanup.py (or pytest).
"""

import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

os.environ["DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from common import config  # noqa: E402
from ioc_distributor import exporter as exporter_module  # noqa: E402
from ioc_distributor.exporter import STATE_FILE, FeedExporter  # noqa: E402

KEYS = [
    "EXPORT_URL_STRIP_SCHEME",
    "EXPORT_DOMAIN_EXCLUDE",
    "EXPORT_MAX_DROP_PERCENT",
    "EXPORT_KEEP_PREVIOUS_ON_EMPTY",
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


def _read(name):
    with open(os.path.join(config.FEEDS_DIR, name), encoding="utf-8") as fh:
        return fh.read()


# --------------------------------------------------------- filter vs format
def test_filter_and_format_are_separate():
    s = _settings(EXPORT_DOMAIN_EXCLUDE="example.com", EXPORT_URL_STRIP_SCHEME="true")
    e = FeedExporter(_FakeStore(), s)
    assert (
        e._drop_reason("url", "https://www.example.com/a")
        == "exclude list: matches example.com"
    )
    assert e._drop_reason("url", "https://evil.test/a") is None
    assert (
        e._drop_reason("domain", "sub.example.com")
        == "exclude list: matches example.com"
    )
    assert e._drop_reason("hash", "d41d8cd98f00b204e9800998ecf8427e") is None
    assert e._format_entry("url", "https://evil.test/a") == "evil.test/a"
    assert e._format_entry("domain", "evil.test") == "evil.test"
    s2 = _settings(EXPORT_URL_STRIP_SCHEME="false")
    assert (
        FeedExporter(_FakeStore(), s2)._format_entry("url", "https://evil.test/a")
        == "https://evil.test/a"
    )


def test_render_file_format_unchanged():
    assert FeedExporter._render_file([]) == ""
    assert FeedExporter._render_file(["a", "b"]) == "a\nb\n"


def test_dedup_after_formatting():
    _clean()
    s = _settings(EXPORT_URL_STRIP_SCHEME="true")
    e = FeedExporter(
        _FakeStore({"url": ["http://evil.test/a", "https://evil.test/a"]}), s
    )
    e.export_once()
    assert _read("url.txt") == "evil.test/a\n"


# --------------------------------------------------------- drop protection
def test_drop_check_uses_saved_count_not_file_lines():
    _clean()
    s = _settings(EXPORT_MAX_DROP_PERCENT=50)
    ips = [f"8.8.{i}.1" for i in range(10)]
    e = FeedExporter(_FakeStore({"ip": ips}), s)
    e.export_once()
    state = json.load(open(os.path.join(config.DATA_DIR, STATE_FILE)))
    assert state["ip.txt"]["entries"] == 10
    # Someone truncates the file by hand: the saved count (10) still protects it.
    with open(os.path.join(config.FEEDS_DIR, "ip.txt"), "w") as fh:
        fh.write("8.8.0.1\n")
    e2 = FeedExporter(_FakeStore({"ip": ips[:3]}), s)  # 3 of 10 = 70% drop
    e2.export_once()
    assert e2.status()["files"]["ip.txt"]["status"] == "kept_previous"


def test_keep_previous_on_empty_from_state():
    _clean()
    s = _settings(EXPORT_KEEP_PREVIOUS_ON_EMPTY="true")
    FeedExporter(_FakeStore({"ip": ["8.8.8.8"]}), s).export_once()
    e = FeedExporter(_FakeStore({}), s)
    e.export_once()
    info = e.status()["files"]["ip.txt"]
    assert info["status"] == "kept_previous" and info["entries"] == 1
    assert _read("ip.txt") == "8.8.8.8\n"


def test_missing_state_falls_back_to_counting_once():
    _clean()
    s = _settings(EXPORT_MAX_DROP_PERCENT=50)
    with open(os.path.join(config.FEEDS_DIR, "ip.txt"), "w") as fh:
        fh.write(
            "".join(f"8.8.{i}.1\n" for i in range(10))
        )  # feed file without a saved state
    e = FeedExporter(_FakeStore({"ip": ["8.8.0.1"]}), s)
    e.export_once()
    assert e.status()["files"]["ip.txt"]["status"] == "kept_previous"


def test_corrupt_state_is_ignored():
    _clean()
    with open(os.path.join(config.DATA_DIR, STATE_FILE), "w") as fh:
        fh.write("{not json")
    e = FeedExporter(_FakeStore({"ip": ["8.8.8.8"]}), _settings())
    e.export_once()
    assert e.status()["last_error"] is None
    assert (
        json.load(open(os.path.join(config.DATA_DIR, STATE_FILE)))["ip.txt"]["entries"]
        == 1
    )


# --------------------------------------------------------- backups
def test_backup_name_keeps_extension():
    ts = datetime(2026, 10, 28, 11, 3, 7, tzinfo=timezone.utc)
    assert FeedExporter.backup_name("ip.txt", ts) == "ip_20261028T110307Z.txt"
    assert (
        FeedExporter.backup_name("hash_sha256.txt", ts)
        == "hash_sha256_20261028T110307Z.txt"
    )
    assert FeedExporter.backup_name("ip.json", ts) == "ip_20261028T110307Z.json"
    assert FeedExporter.backup_name("noext", ts) == "noext_20261028T110307Z"


def test_backups_written_and_pruned():
    _clean()
    s = _settings(BACKUP_RETENTION=2)
    store = _FakeStore({"ip": ["8.8.8.8"]})
    for i in range(5):
        e = FeedExporter(store, s)
        e.export_once()
        # distinct mtimes so each backup gets its own timestamp
        p = os.path.join(config.FEEDS_DIR, "ip.txt")
        t = time.time() - (10 - i) * 60
        os.utime(p, (t, t))
    names = sorted(n for n in os.listdir(config.BACKUP_DIR) if n.startswith("ip_"))
    assert len(names) == 2, names
    assert all(
        exporter_module._BACKUP_NAME.match(n) and n.endswith(".txt") for n in names
    )


def test_backup_name_pattern():
    m = exporter_module._BACKUP_NAME.match("domain_20261028T110307Z.txt")
    assert m and m["stem"] == "domain" and m["ext"] == ".txt"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("all exporter checks passed")
