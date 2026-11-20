"""Checks for custom feeds, the hard limit, the per-type switches, consistent output
(same data -> same bytes; every smaller feed a subset of every larger one) and the
keep-previous check applied to the files of one type together (option B).

Run: python tests/test_custom_feeds.py (or pytest).
"""

import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path

os.environ["DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from common import config  # noqa: E402
from ioc_distributor.exporter import STATE_FILE, FeedExporter  # noqa: E402


def _clear_env():
    for key in list(os.environ):
        if key.startswith(("EXPORT_", "CUSTOM_FEED", "BACKUP_RETENTION")):
            del os.environ[key]


def _settings(**env):
    _clear_env()
    os.environ.update({k: str(v) for k, v in env.items()})
    return config.export_settings()


def _clean():
    for d in (config.FEEDS_DIR, config.BACKUP_DIR, config.TMP_DIR):
        os.makedirs(d, exist_ok=True)
        for name in os.listdir(d):
            os.remove(os.path.join(d, name))
    state = os.path.join(config.DATA_DIR, STATE_FILE)
    if os.path.exists(state):
        os.remove(state)


class _Store:
    """Ranked rows as select_for_export returns them; counts how often each type is read."""

    def __init__(self, rows):
        self.rows = rows  # type -> [(value, sub_type)]
        self.reads = {}

    def select_for_export(self, ioc_type, base_attribute, cutoff, now, sort_order):
        self.reads[ioc_type] = self.reads.get(ioc_type, 0) + 1
        return list(self.rows.get(ioc_type, []))

    def purge_older_than(self, cutoff):
        return 0


def _read(name):
    path = os.path.join(config.FEEDS_DIR, name)
    with open(path, encoding="utf-8") as fh:
        return [line for line in fh.read().splitlines() if line]


def _digest(names):
    out = {}
    for name in names:
        with open(os.path.join(config.FEEDS_DIR, name), "rb") as fh:
            out[name] = hashlib.sha256(fh.read()).hexdigest()
    return out


IPS = [(f"8.{i // 250}.{i % 250}.1", None) for i in range(300)]
URLS = [
    ("http://dup.test/a", None),
    ("https://dup.test/a", None),
] + [  # same entry once the scheme is stripped
    (f"https://u{i:03d}.test/p", None) for i in range(50)
]
HASHES = [("a" * 32, "md5"), ("b" * 40, "sha1"), ("c" * 64, "sha256")] + [
    (f"{i:032x}", "md5") for i in range(20)
]


def _store():
    return _Store(
        {
            "ip": IPS,
            "domain": [(f"d{i}.test", None) for i in range(40)],
            "url": URLS,
            "hash": HASHES,
        }
    )


# ------------------------------------------------------------------ settings
def test_defaults_reproduce_1_0_0():
    s = _settings(EXPORT_MAX_ENTRIES=100000)
    assert s.custom_feeds == () and s.enabled_types() == config.IOC_TYPES
    assert s.hard_max_entries == 500000 and s.max_entries["ip"] == 100000
    assert [f for f, _t, _a in FeedExporter(_store(), s).feeds()] == [
        "ip.txt",
        "domain.txt",
        "url.txt",
        "hash.txt",
    ]
    assert not s.warnings


def test_hard_limit_reduces_zero_and_large_caps():
    s = _settings(EXPORT_MAX_ENTRIES=0)
    assert all(v == 500000 for v in s.max_entries.values())
    assert any("reduced to the hard limit" in w for w in s.warnings)
    s = _settings(EXPORT_MAX_ENTRIES=0, EXPORT_HARD_MAX_ENTRIES=0)
    assert all(v == 0 for v in s.max_entries.values())
    assert any("no hard limit" in w for w in s.warnings)
    s = _settings(EXPORT_HARD_MAX_ENTRIES="50o000")
    assert s.hard_max_entries == 500000 and any(
        "not a whole number" in w for w in s.warnings
    )


def test_custom_caps_blank_override_and_above_main():
    s = _settings(
        EXPORT_MAX_ENTRIES=100,
        EXPORT_MAX_ENTRIES_HASH=10,
        EXPORT_HARD_MAX_ENTRIES=1000,
        CUSTOM_FEED1_ENABLED="true",  # blank -> main caps
        CUSTOM_FEED2_ENABLED="true",
        CUSTOM_FEED2_NAME="Partner-New",
        CUSTOM_FEED2_MAX_ENTRIES=250,
        CUSTOM_FEED2_MAX_ENTRIES_HASH=20,
        CUSTOM_FEED3_ENABLED="true",
        CUSTOM_FEED3_MAX_ENTRIES=5000,
    )  # above the hard limit
    one, two, three = s.custom_feeds
    assert one.name == "custom1" and one.max_entries == s.max_entries
    assert two.name == "partner-new" and two.max_entries == {
        "ip": 250,
        "domain": 250,
        "url": 250,
        "hash": 20,
    }
    assert three.max_entries["ip"] == 1000
    assert any("CUSTOM_FEED3_MAX_ENTRIES [ip]: 5000 reduced" in w for w in s.warnings)


def test_disabled_and_out_of_count_blocks():
    s = _settings(
        CUSTOM_FEED1_ENABLED="false",
        CUSTOM_FEED2_ENABLED="maybe",
        CUSTOM_FEED4_ENABLED="true",
    )
    assert s.custom_feeds == ()
    assert any("CUSTOM_FEED2_ENABLED='maybe'" in w for w in s.warnings)
    assert any("CUSTOM_FEED4_ENABLED=true is ignored" in w for w in s.warnings)


def test_bad_names_stop_startup():
    for env in (
        {"CUSTOM_FEED1_NAME": "ip"},
        {"CUSTOM_FEED1_NAME": "bad name"},
        {
            "CUSTOM_FEED1_NAME": "x",
            "CUSTOM_FEED2_ENABLED": "true",
            "CUSTOM_FEED2_NAME": "X",
        },
    ):
        try:
            _settings(CUSTOM_FEED1_ENABLED="true", **env)
        except SystemExit:
            continue
        raise AssertionError(f"accepted {env}")


def test_type_switches():
    s = _settings(
        EXPORT_ENABLED_HASH="false",
        EXPORT_ENABLED_URL="nope",
        CUSTOM_FEED1_ENABLED="true",
    )
    assert s.enabled_types() == ("ip", "domain", "url")
    assert any("EXPORT_ENABLED_URL='nope'" in w for w in s.warnings)
    served = FeedExporter(_store(), s).served_files()
    assert (
        "hash.txt" not in served
        and "custom1_hash.txt" not in served
        and "custom1_url.txt" in served
    )


# ------------------------------------------------------------------- export
def test_one_query_per_type_and_nested_feeds():
    _clean()
    store = _store()
    s = _settings(
        EXPORT_MAX_ENTRIES=100,
        EXPORT_HASH_SPLIT_FILES="true",
        EXPORT_HARD_MAX_ENTRIES=0,
        CUSTOM_FEED1_ENABLED="true",
        CUSTOM_FEED1_NAME="small",
        CUSTOM_FEED1_MAX_ENTRIES=30,
        CUSTOM_FEED2_ENABLED="true",
        CUSTOM_FEED2_NAME="big",
        CUSTOM_FEED2_MAX_ENTRIES=250,
        CUSTOM_FEED3_ENABLED="true",
        CUSTOM_FEED3_NAME="all",
        CUSTOM_FEED3_MAX_ENTRIES=0,
    )
    e = FeedExporter(store, s)
    e.export_once()
    assert e.status()["last_error"] is None
    assert store.reads == {
        "ip": 1,
        "domain": 1,
        "url": 1,
        "hash": 1,
    }  # split hash files share one read
    sizes = {p: len(_read(f"{p}ip.txt")) for p in ("small_", "", "big_", "all_")}
    assert sizes == {"small_": 30, "": 100, "big_": 250, "all_": 300}
    for kind in ("ip", "domain", "url", "hash", "hash_md5"):
        files = [_read(f"{p}{kind}.txt") for p in ("small_", "", "big_", "all_")]
        for smaller, larger in zip(files, files[1:]):
            assert set(smaller) <= set(larger), kind
    # the top-ranked IPs are in every feed; de-duplicated URL appears once
    assert "8.0.0.1" in _read("small_ip.txt")
    assert _read("all_url.txt").count("dup.test/a") == 1


def test_same_data_gives_identical_bytes():
    _clean()
    s = _settings(
        EXPORT_MAX_ENTRIES=100,
        CUSTOM_FEED1_ENABLED="true",
        CUSTOM_FEED1_MAX_ENTRIES=250,
    )
    e = FeedExporter(_store(), s)
    e.export_once()
    names = [f for f, _t, _a in e.feeds()]
    first = _digest(names)
    for _ in range(3):
        FeedExporter(_store(), s).export_once()
        assert _digest(names) == first


def test_main_feed_unchanged_by_custom_feeds():
    _clean()
    FeedExporter(_store(), _settings(EXPORT_MAX_ENTRIES=100)).export_once()
    before = _digest(["ip.txt", "domain.txt", "url.txt", "hash.txt"])
    _clean()
    FeedExporter(
        _store(),
        _settings(
            EXPORT_MAX_ENTRIES=100,
            CUSTOM_FEED1_ENABLED="true",
            CUSTOM_FEED1_MAX_ENTRIES=250,
        ),
    ).export_once()
    assert _digest(["ip.txt", "domain.txt", "url.txt", "hash.txt"]) == before


def test_disabled_type_not_written():
    _clean()
    FeedExporter(
        _store(), _settings(EXPORT_ENABLED_IP="false", CUSTOM_FEED1_ENABLED="true")
    ).export_once()
    files = set(os.listdir(config.FEEDS_DIR))
    assert (
        "ip.txt" not in files
        and "custom1_ip.txt" not in files
        and "custom1_domain.txt" in files
    )


def test_keep_previous_holds_the_whole_type():
    """Option B: one file of a type failing the check keeps every feed's previous file of that type."""
    _clean()
    env = dict(
        EXPORT_MAX_ENTRIES=100,
        EXPORT_MAX_DROP_PERCENT=50,
        CUSTOM_FEED1_ENABLED="true",
        CUSTOM_FEED1_NAME="big",
        CUSTOM_FEED1_MAX_ENTRIES=250,
    )
    FeedExporter(_store(), _settings(**env)).export_once()
    assert len(_read("ip.txt")) == 100 and len(_read("big_ip.txt")) == 250
    shrunk = _store()
    shrunk.rows["ip"] = IPS[
        :80
    ]  # main 100 -> 80 (20%, passes); big 250 -> 80 (68%, fails)
    e = FeedExporter(shrunk, _settings(**env))
    e.export_once()
    files = e.status()["files"]
    assert files["big_ip.txt"]["status"] == "kept_previous"
    assert (
        files["ip.txt"]["status"] == "kept_previous"
        and "held with big_ip.txt" in files["ip.txt"]["reason"]
    )
    assert len(_read("ip.txt")) == 100 and len(_read("big_ip.txt")) == 250
    assert (
        files["domain.txt"]["status"] == "written"
        and files["big_domain.txt"]["status"] == "written"
    )


def test_new_feed_written_even_when_group_held():
    _clean()
    env = dict(EXPORT_MAX_ENTRIES=100, EXPORT_MAX_DROP_PERCENT=50)
    FeedExporter(_store(), _settings(**env)).export_once()
    shrunk = _store()
    shrunk.rows["ip"] = IPS[:10]
    e = FeedExporter(shrunk, _settings(CUSTOM_FEED1_ENABLED="true", **env))
    e.export_once()
    files = e.status()["files"]
    assert (
        files["ip.txt"]["status"] == "kept_previous"
        and files["custom1_ip.txt"]["status"] == "written"
    )


def test_cap_log_names_the_custom_setting():
    _clean()
    e = FeedExporter(
        _store(),
        _settings(
            EXPORT_MAX_ENTRIES=100,
            CUSTOM_FEED1_ENABLED="true",
            CUSTOM_FEED1_NAME="fw",
            CUSTOM_FEED1_MAX_ENTRIES_IP=50,
        ),
    )
    e.export_once()
    files = e.status()["files"]
    assert (
        files["fw_ip.txt"]["cap"]["limit"] == 50
        and files["fw_ip.txt"]["feed"] == "custom: fw"
    )
    assert files["fw_ip.txt"]["dropped"]["see"] == "ip.txt"
    assert any(re.search(r"custom: fw", line) for line in e.describe_feeds())


if __name__ == "__main__":
    tests = [
        v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)
    ]
    for test in tests:
        test()
        print("ok", test.__name__)
    print(f"all {len(tests)} custom-feed checks passed")
