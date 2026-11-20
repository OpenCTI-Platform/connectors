"""Checks for the entry-limit (cap) report: log warning and /stats fields.

Run: python tests/test_cap_report.py (or pytest).
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
    "EXPORT_HARD_MAX_ENTRIES",
    "EXPORT_MAX_ENTRIES",
    "EXPORT_MAX_ENTRIES_DOMAIN",
    "EXPORT_MAX_DROP_PERCENT",
    "EXPORT_URL_STRIP_SCHEME",
    "EXPORT_DOMAIN_EXCLUDE",
    "EXPORT_SORT_ORDER",
]


def _settings(**env):
    for key in KEYS:
        os.environ.pop(key, None)
    os.environ.update({k: str(v) for k, v in env.items()})
    return config.export_settings()


class _Store:
    """Rows newest first, as select_for_export returns them; dates per value."""

    def __init__(self, rows):
        self.rows = rows  # type -> [(value, date)]

    def select_for_export(self, ioc_type, base_attribute, cutoff, now, sort_order):
        return [(v, None) for v, _ in self.rows.get(ioc_type, [])]

    def export_date_of(self, ioc_type, base_attribute, value):
        return dict(self.rows.get(ioc_type, [])).get(value)

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


def _domains(n):
    return [
        (f"d{i:03d}.test", f"2026-10-{28 - i % 28:02d}T00:00:00Z") for i in range(n)
    ]


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _run(exporter):
    h = _Capture()
    logging.getLogger().addHandler(h)
    logging.getLogger().setLevel(logging.DEBUG)
    try:
        exporter.export_once()
    finally:
        logging.getLogger().removeHandler(h)
    return [(r.levelname, r.getMessage()) for r in h.records]


def test_capped_file_reported_and_contents_unchanged():
    _clean()
    rows = _domains(10)
    e = FeedExporter(_Store({"domain": rows}), _settings(EXPORT_MAX_ENTRIES=4))
    logs = _run(e)
    cap = e.status()["files"]["domain.txt"]["cap"]
    assert (
        cap["capped"] is True
        and cap["limit"] == 4
        and cap["available"] == 10
        and cap["left_out"] == 6
    )
    assert cap["last_kept_modified"] == rows[3][1]  # 4th newest
    with open(os.path.join(config.FEEDS_DIR, "domain.txt")) as fh:
        assert fh.read().split() == sorted(v for v, _ in rows[:4])
    warnings = [m for lvl, m in logs if lvl == "WARNING" and "capped at 4 of 10" in m]
    assert warnings and "6 left out" in warnings[0] and rows[3][1] in warnings[0], logs
    assert any("domain.txt=4 (capped)" in m for _, m in logs)


def test_warning_once_then_info_then_recovery():
    _clean()
    store = _Store({"domain": _domains(10)})
    e = FeedExporter(store, _settings(EXPORT_MAX_ENTRIES=4))
    _run(e)
    second = _run(e)
    assert any(lvl == "INFO" and "capped at 4 of 10" in m for lvl, m in second)
    assert not any(lvl == "WARNING" and "capped" in m for lvl, m in second)
    store.rows["domain"] = _domains(3)
    third = _run(e)
    assert any("domain.txt no longer capped" in m for _, m in third), third
    assert e.status()["files"]["domain.txt"]["cap"]["capped"] is False


def test_exactly_at_limit_is_not_capped():
    _clean()
    e = FeedExporter(_Store({"domain": _domains(4)}), _settings(EXPORT_MAX_ENTRIES=4))
    logs = _run(e)
    cap = e.status()["files"]["domain.txt"]["cap"]
    assert cap["capped"] is False and cap["available"] == 4 and cap["left_out"] == 0
    assert not any("capped" in m for _, m in logs if "Export done" not in m)


def test_available_counts_after_dedup_and_filters():
    _clean()
    rows = [
        ("https://a.test/x", "2026-10-28"),
        ("http://a.test/x", "2026-10-27"),
        ("https://ok.example.com/y", "2026-10-26"),
        ("https://b.test/z", "2026-10-25"),
    ]
    s = _settings(
        EXPORT_MAX_ENTRIES=1,
        EXPORT_URL_STRIP_SCHEME="true",
        EXPORT_DOMAIN_EXCLUDE="example.com",
    )
    e = FeedExporter(_Store({"url": rows}), s)
    _run(e)
    cap = e.status()["files"]["url.txt"]["cap"]
    assert (
        cap["available"] == 2 and cap["left_out"] == 1
    )  # a.test/x once, excluded dropped


def test_unlimited_and_store_without_date_method():
    _clean()
    # EXPORT_MAX_ENTRIES=0 means "no cap" only with the hard limit off;
    # with the default hard limit it is reduced to 500000 (see test_custom_feeds.py).
    e = FeedExporter(
        _Store({"domain": _domains(5)}),
        _settings(EXPORT_MAX_ENTRIES=0, EXPORT_HARD_MAX_ENTRIES=0),
    )
    _run(e)
    cap = e.status()["files"]["domain.txt"]["cap"]
    assert cap["capped"] is False and cap["limit"] is None and cap["available"] == 5

    class _NoDate(_Store):
        export_date_of = None

    _clean()
    e = FeedExporter(_NoDate({"domain": _domains(5)}), _settings(EXPORT_MAX_ENTRIES=2))
    logs = _run(e)
    assert e.status()["files"]["domain.txt"]["cap"]["last_kept_modified"] is None
    assert any("last kept modified unknown" in m for _, m in logs)


class _ScoredStore:
    """Rows as (value, score, date); select_for_export sorts like the real stores:
    score order = highest score, then newest, then value; otherwise newest, then value.
    """

    def __init__(self, rows):
        self.rows = rows  # type -> [(value, score, date)]

    def select_for_export(self, ioc_type, base_attribute, cutoff, now, sort_order):
        rows = self.rows.get(ioc_type, [])
        if sort_order == "score":
            ordered = sorted(rows, key=lambda r: (-(r[1] or 0), _neg(r[2]), r[0]))
        else:
            ordered = sorted(rows, key=lambda r: (_neg(r[2]), r[0]))
        return [(v, None) for v, _, _ in ordered]

    def export_date_of(self, ioc_type, base_attribute, value):
        return {v: d for v, _, d in self.rows.get(ioc_type, [])}.get(value)

    def export_score_of(self, ioc_type, base_attribute, cutoff, now, value):
        return {v: (s or 0) for v, s, _ in self.rows.get(ioc_type, [])}.get(value)

    def purge_older_than(self, cutoff):
        return 0


def _neg(date):
    """Newest first as an ascending key."""
    return tuple(-ord(c) for c in (date or ""))


def _scored_domains():
    # Newest IOCs have the LOWEST scores, so date order and score order keep different sets.
    return [
        (f"s{i:02d}.test", i * 10, f"2026-10-{10 + i:02d}T00:00:00Z") for i in range(10)
    ]  # scores 0..90


def test_score_order_keeps_highest_scores_at_cap():
    _clean()
    rows = _scored_domains()
    rows.append(
        ("noscore.test", None, "2026-10-28T00:00:00Z")
    )  # newest, no score -> counts as 0
    e = FeedExporter(
        _ScoredStore({"domain": rows}),
        _settings(EXPORT_MAX_ENTRIES=4, EXPORT_SORT_ORDER="score"),
    )
    logs = _run(e)
    with open(os.path.join(config.FEEDS_DIR, "domain.txt")) as fh:
        kept = fh.read().split()
    assert kept == [
        "s06.test",
        "s07.test",
        "s08.test",
        "s09.test",
    ], kept  # scores 60-90
    cap = e.status()["files"]["domain.txt"]["cap"]
    assert cap["capped"] and cap["sort_order"] == "score" and cap["left_out"] == 7
    assert cap["lowest_kept_score"] == 60 and cap["highest_left_out_score"] == 50
    warnings = [m for lvl, m in logs if lvl == "WARNING" and "capped at 4 of 11" in m]
    assert (
        warnings
        and "sort score, lowest kept score 60, highest left out score 50" in warnings[0]
    ), logs


def test_date_order_keeps_newest_at_cap_and_has_no_score_fields():
    _clean()
    rows = _scored_domains()
    e = FeedExporter(
        _ScoredStore({"domain": rows}),
        _settings(EXPORT_MAX_ENTRIES=4, EXPORT_SORT_ORDER="base_attribute"),
    )
    logs = _run(e)
    with open(os.path.join(config.FEEDS_DIR, "domain.txt")) as fh:
        assert fh.read().split() == [
            "s06.test",
            "s07.test",
            "s08.test",
            "s09.test",
        ]  # newest 4
    cap = e.status()["files"]["domain.txt"]["cap"]
    assert "lowest_kept_score" not in cap
    assert not any("lowest kept score" in m for _, m in logs)


def test_score_ties_broken_by_newest_then_value():
    _clean()
    rows = [
        ("old-90.test", 90, "2026-10-01T00:00:00Z"),
        ("new-90.test", 90, "2026-10-20T00:00:00Z"),
        ("b-50.test", 50, "2026-10-15T00:00:00Z"),
        ("a-50.test", 50, "2026-10-15T00:00:00Z"),
        ("low.test", 10, "2026-10-28T00:00:00Z"),
    ]
    e = FeedExporter(
        _ScoredStore({"domain": rows}),
        _settings(EXPORT_MAX_ENTRIES=3, EXPORT_SORT_ORDER="score"),
    )
    _run(e)
    with open(os.path.join(config.FEEDS_DIR, "domain.txt")) as fh:
        assert fh.read().split() == ["a-50.test", "new-90.test", "old-90.test"]
    cap = e.status()["files"]["domain.txt"]["cap"]
    assert (
        cap["lowest_kept_score"] == 50 and cap["highest_left_out_score"] == 50
    )  # b-50 lost the tie


def test_score_order_store_without_score_method():
    _clean()

    class _NoScore(_ScoredStore):
        export_score_of = None

    e = FeedExporter(
        _NoScore({"domain": _scored_domains()}),
        _settings(EXPORT_MAX_ENTRIES=4, EXPORT_SORT_ORDER="score"),
    )
    logs = _run(e)
    assert e.status()["files"]["domain.txt"]["cap"]["lowest_kept_score"] is None
    assert any("lowest kept score unknown" in m for _, m in logs)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("all cap report checks passed")
