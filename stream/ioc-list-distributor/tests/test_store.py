"""Checks for the IocStore interface, run against SQLite.

Run: python tests/test_store.py (or pytest).
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from common.storage import IocStore  # noqa: E402
from common.storage.sqlite_store import SqliteIocStore  # noqa: E402


def _sqlite_store():
    folder = tempfile.mkdtemp()
    return SqliteIocStore(os.path.join(folder, "test.db"))


STORE_FACTORIES = {"sqlite": _sqlite_store}

T1, T2, T3 = (
    "2026-10-01T00:00:00.000000Z",
    "2026-10-10T00:00:00.000000Z",
    "2026-10-20T00:00:00.000000Z",
)


def _put(store, ind, iocs, *, score=50, modified=T2, valid_until=None, stix=None):
    return store.upsert_indicator(
        ind,
        stix or f"indicator--{ind}",
        iocs,
        name=ind,
        score=score,
        valid_until=valid_until,
        created=T1,
        modified=modified,
    )


def check_store(store: IocStore) -> None:
    assert isinstance(store, IocStore)

    # create, then edit the pattern: the old value is replaced, one row per value
    assert _put(store, "a", [("ip", "ipv4", "1.1.1.1")]) == (1, 0, 0)
    assert _put(store, "a", [("ip", "ipv4", "2.2.2.2")]) == (1, 0, 1)
    assert store.select_for_export("ip", "modified", None, None, "base_attribute") == [
        ("2.2.2.2", "ipv4")
    ]

    # OR pattern: several values for one indicator; update keeps them
    assert _put(
        store, "h", [("hash", "md5", "b" * 32), ("hash", "sha256", "a" * 64)]
    ) == (2, 0, 0)
    assert _put(
        store, "h", [("hash", "md5", "b" * 32), ("hash", "sha256", "a" * 64)], score=80
    ) == (0, 2, 0)

    # the same value held by two indicators is exported once
    _put(store, "d1", [("domain", "domain", "evil.example")], score=20, modified=T1)
    _put(store, "d2", [("domain", "domain", "evil.example")], score=90, modified=T3)
    _put(store, "d3", [("domain", "domain", "old.example")], score=95, modified=T1)
    assert store.counts_by_type() == {"ip": 1, "hash": 2, "domain": 2}
    assert store.count_indicators() == 5

    # rolling window (base attribute >= cutoff) and both sort orders
    assert store.select_for_export(
        "domain", "modified", T2, None, "base_attribute"
    ) == [("evil.example", "domain")]
    assert [
        v
        for v, _ in store.select_for_export(
            "domain", "modified", None, None, "base_attribute"
        )
    ] == ["evil.example", "old.example"]
    assert [
        v for v, _ in store.select_for_export("domain", "modified", None, None, "score")
    ] == ["old.example", "evil.example"]

    # score at the cap (export_score_of): best score of a value's rows inside the window
    assert store.export_score_of("domain", "modified", None, None, "evil.example") == 90
    assert store.export_score_of("domain", "modified", T2, None, "evil.example") == 90
    assert store.export_score_of("domain", "modified", None, None, "old.example") == 95
    _put(
        store, "ns", [("domain", "domain", "noscore.example")], score=None, modified=T1
    )
    assert (
        store.export_score_of("domain", "modified", None, None, "noscore.example") == 0
    )
    assert [
        v for v, _ in store.select_for_export("domain", "modified", None, None, "score")
    ][
        -1
    ] == "noscore.example"  # no score counts as 0: last in score order
    store.delete_indicator("ns")
    _put(
        store, "lw", [("domain", "domain", "evil.example")], score=99, modified=T1
    )  # outside a T2 window
    assert store.export_score_of("domain", "modified", None, None, "evil.example") == 99
    assert store.export_score_of("domain", "modified", T2, None, "evil.example") == 90
    store.delete_indicator("lw")
    assert (
        store.export_score_of("domain", "modified", None, None, "not-stored.example")
        is None
    )
    assert store.export_score_of("domain", "modified", None, None, None) is None

    # equal dates: ties are broken by value, so the same entries are kept at a cap
    _put(store, "t2", [("domain", "domain", "tie-b.example")], modified=T3)
    _put(store, "t1", [("domain", "domain", "tie-a.example")], modified=T3)
    assert [
        v
        for v, _ in store.select_for_export(
            "domain", "modified", T3, None, "base_attribute"
        )
    ] == ["evil.example", "tie-a.example", "tie-b.example"]
    store.delete_indicator("t1")
    store.delete_indicator("t2")

    # expiry: valid_until in the past is left out, in the future kept
    _put(store, "e1", [("url", "url", "x.example/past")], valid_until=T1)
    _put(store, "e2", [("url", "url", "x.example/future")], valid_until=T3)
    assert store.select_for_export("url", "modified", None, T2, "base_attribute") == [
        ("x.example/future", "url")
    ]

    # an unknown base attribute is refused (it would be a column name)
    try:
        store.select_for_export(
            "url", "value; DROP TABLE ioc", None, None, "base_attribute"
        )
        raise AssertionError("unsafe base attribute accepted")
    except ValueError:
        pass

    # delete by OpenCTI id, and by STIX id as a fallback
    assert store.delete_indicator("d1") == 1
    assert store.delete_indicator("unknown-id", "indicator--d2") == 1
    assert store.delete_indicator("never-stored") == 0

    # age purge on modified
    assert store.purge_older_than(T2) == 1  # d3 (modified T1)

    # meta / stream bookkeeping
    # modified never moves backwards: a stale event arriving second keeps the newer date
    def _mod(ind):
        value = {"m": "http://m.example/", "n": "9.9.9.9"}[ind]
        return {store.export_date_of("url" if ind == "m" else "ip", "modified", value)}

    _put(store, "m", [("url", "url", "http://m.example/")], modified=T3)
    assert _put(
        store, "m", [("url", "url", "http://m.example/")], modified=T2, score=10
    ) == (0, 1, 0)
    assert _mod("m") == {T3}  # stale date ignored
    _put(store, "m", [("url", "url", "http://m.example/")], modified=None)
    assert _mod("m") == {T3}  # missing date keeps the stored one
    _put(
        store,
        "m",
        [("url", "url", "http://m.example/")],
        modified="2026-10-25T00:00:00.000000Z",
    )
    assert _mod("m") == {"2026-10-25T00:00:00.000000Z"}  # newer date applied
    _put(store, "n", [("ip", "ipv4", "9.9.9.9")], modified=T1)
    _put(store, "n", [("ip", "ipv4", "9.9.9.9")], modified=T3)
    assert _mod("n") == {T3}  # normal in-order update

    store.record_event("create", False)
    store.record_event("update", True)
    meta = store.get_all_meta()
    assert meta["stream_events_total"] == "2"
    assert meta["stream_indicators_skipped_total"] == "1"
    assert meta["stream_last_event_type"] == "update"
    assert meta["stream_last_event_at"]

    store.close()


def test_all_backends():
    for name, factory in STORE_FACTORIES.items():
        check_store(factory())
        print(f"{name}: ok")


if __name__ == "__main__":
    test_all_backends()
    print("All store checks passed")
