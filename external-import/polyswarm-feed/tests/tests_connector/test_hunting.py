"""Tests for the PolySwarm live hunting source (mapping, window, dedup, state)."""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import stix2
from connector import hunting
from connector.hunting import (
    LAG_MARGIN_SECONDS,
    MAX_SINCE_SECONDS,
    SEEN_IDS_LIMIT,
    HuntingSource,
)
from pycti import Identity, Indicator, Malware, StixCoreRelationship
from pydantic import SecretStr

NOW = datetime(2026, 11, 10, 15, 0, 0, tzinfo=timezone.utc)

AUTHOR = {
    "type": "identity",
    "spec_version": "2.1",
    "id": Identity.generate_id("PolySwarm", "organization"),
    "name": "PolySwarm",
    "identity_class": "organization",
}
TLP = {"type": "marking-definition", "id": stix2.TLP_WHITE.id}

SHA256_A = "a" * 64
SHA256_B = "b" * 64


class FakeLogger:
    def __init__(self):
        self.messages = []

    def _log(self, level, message, meta=None):
        self.messages.append((level, message, meta))

    def info(self, message, meta=None):
        self._log("info", message, meta)

    def warning(self, message, meta=None):
        self._log("warning", message, meta)

    def debug(self, message, meta=None):
        self._log("debug", message, meta)

    def error(self, message, meta=None):
        self._log("error", message, meta)


class FakeReader:
    """Stands in for the client's live hits reader."""

    def __init__(self, hits, complete, stop_reason):
        self.hits = hits
        self.yielded = 0
        self.complete = False
        self._complete_at_end = complete
        self.stop_reason = stop_reason

    def __iter__(self):
        for hit in self.hits:
            self.yielded += 1
            yield hit
        self.complete = self._complete_at_end


class FakeClient:
    def __init__(self, hits=None, error=None, complete=True, stop_reason=None):
        self.hits = hits or []
        self.error = error
        self.complete = complete
        self.stop_reason = stop_reason
        self.calls = []
        self.readers = []

    def read_live_hits(self, since_seconds):
        self.calls.append(since_seconds)
        if self.error:
            raise self.error
        reader = FakeReader(list(self.hits), self.complete, self.stop_reason)
        self.readers.append(reader)
        return reader


def make_config(**overrides):
    values = {
        "api_key": SecretStr("0" * 32),
        "api_url": "https://api.polyswarm.network",
        "hunting_backfill_hours": 24,
        "hunting_indicator_valid_days": 30,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def make_hit(hit_id="1001", sha256=SHA256_A, **overrides):
    hit = {
        "id": hit_id,
        "rule_name": "example_rule",
        "malware_family": None,
        "polyscore": 0.44,
        "detections": {"benign": 8, "malicious": 1, "total": 9},
        "matched_strings": None,
        "matched_strings_dropped": None,
        "yara": None,
        "md5": "c" * 32,
        "sha1": "d" * 40,
        "sha256": sha256,
        "community": "mainnet1",
        "created": "2026-11-10T14:45:46.251666+00:00",
        "first_seen": "2024-07-30T17:50:11.799045+00:00",
        "instance_id": "2002",
        "livescan_id": "3003",
        "tags": "{}",
        "download_url": None,
    }
    hit.update(overrides)
    return hit


@pytest.fixture(autouse=True)
def frozen_now(monkeypatch):
    monkeypatch.setattr(HuntingSource, "_now", staticmethod(lambda: NOW))


def make_source(hits=None, config=None, client=None):
    logger = FakeLogger()
    client = client or FakeClient(hits)
    source = HuntingSource(config or make_config(), AUTHOR, TLP, logger, client=client)
    return source, client, logger


def by_type(objects, stix_type):
    return [o for o in objects if o["type"] == stix_type]


# ----------------------------------------------------------------------
# Mapping
# ----------------------------------------------------------------------


def test_maps_hit_to_observable_indicator_note_relationship():
    source, _, _ = make_source([make_hit()])
    objects, _ = source.collect({})

    assert sorted(o["type"] for o in objects) == [
        "file",
        "indicator",
        "note",
        "relationship",
    ]
    file_obj = by_type(objects, "file")[0]
    indicator = by_type(objects, "indicator")[0]
    note = by_type(objects, "note")[0]
    rel = by_type(objects, "relationship")[0]

    assert file_obj["hashes"] == {
        "MD5": "c" * 32,
        "SHA-1": "d" * 40,
        "SHA-256": SHA256_A,
    }
    pattern = f"[file:hashes.'SHA-256' = '{SHA256_A}']"
    assert indicator["pattern"] == pattern
    assert indicator["pattern_type"] == "stix"
    assert indicator["id"] == Indicator.generate_id(pattern)
    assert indicator["labels"] == ["polyswarm-hunt:example_rule"]
    assert indicator["x_opencti_main_observable_type"] == "StixFile"
    assert indicator["x_opencti_score"] == 11  # 1 of 9 engines
    assert "1 of 9" in indicator["description"]

    assert rel["relationship_type"] == "based-on"
    assert rel["source_ref"] == indicator["id"]
    assert rel["target_ref"] == file_obj["id"]
    assert rel["id"] == StixCoreRelationship.generate_id(
        "based-on", indicator["id"], file_obj["id"]
    )

    assert set(note["object_refs"]) == {file_obj["id"], indicator["id"]}
    assert note["labels"] == ["polyswarm-hunt:example_rule"]
    assert "example_rule" in note["abstract"]
    for expected in [
        "Rule name: example_rule",
        "1 malicious, 8 benign, 9 total",
        "First seen on PolySwarm: 2024-07-30T17:50:11.799045+00:00",
        "PolyScore as reported: 0.44",
        "Matched strings: not provided by the API for this hit",
    ]:
        assert expected in note["content"]


def test_every_object_has_author_and_marking():
    source, _, _ = make_source([make_hit(malware_family="Copak")])
    objects, _ = source.collect({})
    for obj in objects:
        assert obj["object_marking_refs"] == [TLP["id"]]
        if obj["type"] == "file":
            assert obj["x_opencti_created_by_ref"] == AUTHOR["id"]
        else:
            assert obj["created_by_ref"] == AUTHOR["id"]


def test_objects_are_plain_json_dicts_and_valid_stix():
    source, _, _ = make_source([make_hit(malware_family="Copak")])
    objects, _ = source.collect({})
    assert all(isinstance(o, dict) for o in objects)
    json.dumps(objects)
    bundle = stix2.parse(
        {
            "type": "bundle",
            "id": "bundle--" + "0" * 8 + "-0000-4000-8000-" + "0" * 12,
            "objects": objects,
        },
        allow_custom=True,
    )
    assert len(bundle.objects) == len(objects)


def test_malware_family_adds_malware_and_indicates():
    source, _, _ = make_source([make_hit(malware_family="Copak")])
    objects, _ = source.collect({})
    malware = by_type(objects, "malware")
    assert len(malware) == 1
    assert malware[0]["name"] == "Copak"
    assert malware[0]["is_family"] is True
    assert malware[0]["id"] == Malware.generate_id("Copak")
    indicator = by_type(objects, "indicator")[0]
    indicates = [
        r
        for r in by_type(objects, "relationship")
        if r["relationship_type"] == "indicates"
    ]
    assert len(indicates) == 1
    assert indicates[0]["source_ref"] == indicator["id"]
    assert indicates[0]["target_ref"] == malware[0]["id"]
    note = by_type(objects, "note")[0]
    assert malware[0]["id"] in note["object_refs"]
    assert indicates[0]["id"] in note["object_refs"]


@pytest.mark.parametrize("family", [None, "", "   ", 123.0])
def test_no_or_blank_family_creates_no_malware(family):
    hit = make_hit(malware_family=family)
    source, _, _ = make_source([hit])
    objects, _ = source.collect({})
    if family == 123.0:
        # Non string values are turned into text, which is not a family name.
        assert by_type(objects, "malware") == []
    else:
        assert by_type(objects, "malware") == []
        assert all(
            r["relationship_type"] != "indicates"
            for r in by_type(objects, "relationship")
        )


def test_long_family_name_truncated():
    source, _, _ = make_source([make_hit(malware_family="F" * 1000)])
    objects, _ = source.collect({})
    # Far too long to be a family name: no Malware, and the label stays bounded.
    assert by_type(objects, "malware") == []
    label = by_type(objects, "indicator")[0]["labels"][0]
    assert len(label) <= len("polyswarm-family:") + 128


def test_score_omitted_without_detections():
    source, _, _ = make_source([make_hit(detections=None)])
    objects, _ = source.collect({})
    indicator = by_type(objects, "indicator")[0]
    assert "x_opencti_score" not in indicator
    note = by_type(objects, "note")[0]
    assert "Engine detections at hit time: not provided" in note["content"]


@pytest.mark.parametrize(
    "detections",
    [
        {},
        {"malicious": 1},
        {"malicious": 1, "total": 0},
        {"malicious": "x", "total": 9},
    ],
)
def test_unusable_detections_give_no_score(detections):
    source, _, _ = make_source([make_hit(detections=detections)])
    objects, _ = source.collect({})
    assert "x_opencti_score" not in by_type(objects, "indicator")[0]


def test_score_is_clamped_when_malicious_exceeds_total():
    hit = make_hit(detections={"malicious": 20, "benign": 0, "total": 10})
    source, _, _ = make_source([hit])
    objects, _ = source.collect({})
    assert by_type(objects, "indicator")[0]["x_opencti_score"] == 100


def test_valid_until_from_import_time_and_after_valid_from():
    source, _, _ = make_source(
        [make_hit()], config=make_config(hunting_indicator_valid_days=30)
    )
    objects, _ = source.collect({})
    indicator = by_type(objects, "indicator")[0]
    valid_from = datetime.fromisoformat(indicator["valid_from"].replace("Z", "+00:00"))
    valid_until = datetime.fromisoformat(
        indicator["valid_until"].replace("Z", "+00:00")
    )
    assert valid_until == NOW + timedelta(days=30)
    assert valid_from == datetime(2026, 11, 10, 14, 45, 46, 251666, tzinfo=timezone.utc)
    assert valid_until > valid_from


def test_valid_until_never_before_valid_from_with_zero_days():
    source, _, _ = make_source(
        [make_hit()], config=make_config(hunting_indicator_valid_days=0)
    )
    objects, _ = source.collect({})
    indicator = by_type(objects, "indicator")[0]
    assert indicator["valid_until"] > indicator["valid_from"]


@pytest.mark.parametrize("created", [None, "", "not a date", "2099-01-01T00:00:00Z"])
def test_bad_or_future_created_falls_back_to_now(created):
    source, _, _ = make_source([make_hit(created=created)])
    objects, _ = source.collect({})
    indicator = by_type(objects, "indicator")[0]
    valid_from = datetime.fromisoformat(indicator["valid_from"].replace("Z", "+00:00"))
    assert valid_from == NOW
    assert indicator["valid_until"] > indicator["valid_from"]


def test_missing_or_bad_md5_sha1_are_left_out():
    hit = make_hit(md5=None, sha1="not-a-hash")
    source, _, _ = make_source([hit])
    objects, _ = source.collect({})
    assert by_type(objects, "file")[0]["hashes"] == {"SHA-256": SHA256_A}


def test_uppercase_hashes_are_normalised():
    hit = make_hit(sha256=SHA256_A.upper(), md5=("C" * 32))
    source, _, _ = make_source([hit])
    objects, _ = source.collect({})
    assert by_type(objects, "file")[0]["hashes"]["SHA-256"] == SHA256_A
    assert by_type(objects, "file")[0]["hashes"]["MD5"] == "c" * 32


@pytest.mark.parametrize(
    "bad",
    [
        {"sha256": None},
        {"sha256": "abc"},
        {"sha256": "z" * 64},
        {"sha256": SHA256_A + "' OR '1'='1"},
        {"rule_name": None},
        {"rule_name": "   "},
    ],
)
def test_hits_without_usable_sha256_or_rule_are_skipped(bad):
    source, _, logger = make_source([make_hit(**bad)])
    objects, state = source.collect({})
    assert objects == []
    # The id is not remembered, so a later complete copy is still imported.
    assert state["seen_hit_ids"] == []
    summary = [m for m in logger.messages if m[1].endswith("processed.")][0][2]
    assert summary["hits_skipped_invalid"] == 1


def test_non_dict_hits_are_skipped():
    source, _, _ = make_source([None, "junk", make_hit()])
    objects, _ = source.collect({})
    assert len(by_type(objects, "indicator")) == 1


def test_unsafe_rule_name_is_sanitised_in_label():
    rule = "bad rule\n<script>alert(1)</script>" + "x" * 500
    source, _, _ = make_source([make_hit(rule_name=rule)])
    objects, _ = source.collect({})
    label = by_type(objects, "indicator")[0]["labels"][0]
    assert label.startswith("polyswarm-hunt:bad_rule_")
    suffix = label.split(":", 1)[1]
    assert all(ch.isalnum() or ch in "_.-" for ch in suffix)
    assert len(label) <= len("polyswarm-hunt:") + 128
    note = by_type(objects, "note")[0]
    assert "\n<script>" not in note["content"]


def test_long_matched_strings_are_truncated():
    matched = ["A" * 10000 for _ in range(500)]
    source, _, _ = make_source([make_hit(matched_strings=matched)])
    objects, _ = source.collect({})
    content = by_type(objects, "note")[0]["content"]
    assert "(and 480 more not shown)" in content
    assert len(content) < 6000
    assert "A" * 201 not in content


@pytest.mark.parametrize(
    "matched,expected",
    [
        ("single string", "`single string`"),
        (["one", "two"], "`one`, `two`"),
        ([{"identifier": "$a", "data": "evil"}], '"identifier": "$a"'),
        ({"$a": "evil"}, "`$a: evil`"),
        (["has `backtick` and\x00nul\nnewline"], "`has 'backtick' and nul newline`"),
    ],
)
def test_matched_strings_shapes(matched, expected):
    source, _, _ = make_source([make_hit(matched_strings=matched)])
    objects, _ = source.collect({})
    assert expected in by_type(objects, "note")[0]["content"]


def test_matched_strings_dropped_is_mentioned():
    hit = make_hit(matched_strings=["x"], matched_strings_dropped=True)
    source, _, _ = make_source([hit])
    objects, _ = source.collect({})
    assert "dropped" in by_type(objects, "note")[0]["content"]


def test_same_file_same_rule_folds_into_one_note():
    hits = [
        make_hit("3", detections={"malicious": 3, "benign": 6, "total": 9}),
        make_hit("2", detections={"malicious": 1, "benign": 8, "total": 9}),
        make_hit("1"),
    ]
    source, _, _ = make_source(hits)
    objects, state = source.collect({})
    assert len(by_type(objects, "note")) == 1
    assert len(by_type(objects, "indicator")) == 1
    assert len(by_type(objects, "file")) == 1
    note = by_type(objects, "note")[0]
    # Described from the newest hit (the API returns newest first).
    assert "3 malicious" in note["content"]
    assert "Hits for this rule and file in this import: 3" in note["content"]
    assert state["seen_hit_ids"] == ["3", "2", "1"]


def test_same_file_two_rules_two_notes_one_indicator_with_both_labels():
    hits = [make_hit("2", rule_name="rule_b"), make_hit("1", rule_name="rule_a")]
    source, _, _ = make_source(hits)
    objects, _ = source.collect({})
    assert len(by_type(objects, "indicator")) == 1
    assert by_type(objects, "indicator")[0]["labels"] == [
        "polyswarm-hunt:rule_a",
        "polyswarm-hunt:rule_b",
    ]
    assert len(by_type(objects, "note")) == 2


def test_note_id_is_stable_across_runs_for_same_rule_and_file():
    first, _, _ = make_source([make_hit("1")])
    second, _, _ = make_source([make_hit("2", polyscore=0.9)])
    note_1 = by_type(first.collect({})[0], "note")[0]
    note_2 = by_type(second.collect({})[0], "note")[0]
    assert note_1["id"] == note_2["id"]


def test_two_files_two_indicators_and_unique_ids():
    hits = [
        make_hit("2", sha256=SHA256_B, malware_family="Copak"),
        make_hit("1", malware_family="Copak"),
    ]
    source, _, _ = make_source(hits)
    objects, _ = source.collect({})
    ids = [o["id"] for o in objects]
    assert len(ids) == len(set(ids))
    assert len(by_type(objects, "indicator")) == 2
    assert len(by_type(objects, "malware")) == 1


# ----------------------------------------------------------------------
# Window, dedup and state
# ----------------------------------------------------------------------


def test_first_run_uses_backfill_hours():
    source, client, _ = make_source([], config=make_config(hunting_backfill_hours=24))
    source.collect({})
    assert client.calls == [24 * 3600]


def test_next_run_uses_elapsed_plus_lag():
    source, client, _ = make_source([])
    last_run = (NOW - timedelta(hours=1)).isoformat()
    source.collect({"last_run": last_run})
    assert client.calls == [3600 + LAG_MARGIN_SECONDS]


def test_window_capped():
    source, client, logger = make_source(
        [], config=make_config(hunting_backfill_hours=24 * 365)
    )
    source.collect({})
    assert client.calls == [MAX_SINCE_SECONDS]
    assert any(level == "warning" for level, _, _ in logger.messages)


def test_window_never_zero():
    # since=0 disables the API's time filter, so it must never be sent.
    source, client, _ = make_source([], config=make_config(hunting_backfill_hours=0))
    source.collect({})
    assert client.calls == [1]


def test_last_run_in_future_uses_lag_only():
    source, client, _ = make_source([])
    source.collect({"last_run": (NOW + timedelta(hours=2)).isoformat()})
    assert client.calls == [LAG_MARGIN_SECONDS]


@pytest.mark.parametrize(
    "bad_state", [None, "x", {"last_run": "garbage"}, {"last_run": 5}]
)
def test_bad_state_treated_as_first_run(bad_state):
    source, client, _ = make_source([])
    source.collect(bad_state)
    assert client.calls == [24 * 3600]


def test_new_state_has_last_run_and_ids():
    source, _, _ = make_source([make_hit("9"), make_hit("8", sha256=SHA256_B)])
    _, state = source.collect({})
    assert state["last_run"] == NOW.isoformat()
    assert state["seen_hit_ids"] == ["9", "8"]


def test_empty_run_still_advances_last_run_and_keeps_ids():
    source, _, _ = make_source([])
    _, state = source.collect(
        {"last_run": "2026-11-10T14:00:00+00:00", "seen_hit_ids": ["1", "2"]}
    )
    assert state == {"last_run": NOW.isoformat(), "seen_hit_ids": ["1", "2"]}


def test_dedup_across_runs():
    hits = [make_hit("2", sha256=SHA256_B), make_hit("1")]
    source, _, _ = make_source(hits)
    objects, state = source.collect(
        {"seen_hit_ids": ["1"], "last_run": "2026-11-10T14:00:00+00:00"}
    )
    files = by_type(objects, "file")
    assert [f["hashes"]["SHA-256"] for f in files] == [SHA256_B]
    assert state["seen_hit_ids"] == ["2", "1"]


def test_all_seen_returns_no_objects():
    source, _, _ = make_source([make_hit("1"), make_hit("2")])
    objects, state = source.collect({"seen_hit_ids": ["2", "1"]})
    assert objects == []
    assert state["seen_hit_ids"] == ["2", "1"]


def test_duplicate_ids_within_one_response_are_counted_once():
    source, _, _ = make_source([make_hit("1"), make_hit("1")])
    objects, state = source.collect({})
    assert state["seen_hit_ids"] == ["1"]
    note = by_type(objects, "note")[0]
    assert "Hits for this rule and file in this import: 1" in note["content"]


def test_integer_ids_are_normalised_to_strings():
    source, _, _ = make_source([make_hit(7)])
    _, state = source.collect({"seen_hit_ids": [5]})
    assert state["seen_hit_ids"] == ["7", "5"]


def test_hits_without_id_are_imported_but_not_remembered():
    source, _, _ = make_source([make_hit(None)])
    objects, state = source.collect({})
    assert len(by_type(objects, "indicator")) == 1
    assert state["seen_hit_ids"] == []


def test_seen_ids_bounded_newest_first():
    old_ids = [f"old{i}" for i in range(SEEN_IDS_LIMIT)]
    hits = [make_hit(f"new{i}") for i in range(10)]
    source, _, _ = make_source(hits)
    _, state = source.collect({"seen_hit_ids": old_ids})
    ids = state["seen_hit_ids"]
    assert len(ids) == SEEN_IDS_LIMIT
    assert ids[:10] == [f"new{i}" for i in range(10)]
    assert ids[-1] == f"old{SEEN_IDS_LIMIT - 11}"


@pytest.mark.parametrize("reason", ["missing cursor", "repeated cursor", "page limit"])
def test_incomplete_paging_advances_the_checkpoint_and_warns(reason):
    previous = NOW - timedelta(hours=1)
    client = FakeClient(
        [
            make_hit("2", sha256=SHA256_B, created="2026-11-10T14:50:00+00:00"),
            make_hit("1", created="2026-11-10T14:40:00+00:00"),
        ],
        complete=False,
        stop_reason=reason,
    )
    source, _, logger = make_source(client=client)
    objects, state = source.collect(
        {"last_run": previous.isoformat(), "seen_hit_ids": ["0"]}
    )

    # The hits that were read are imported and remembered.
    assert len(by_type(objects, "indicator")) == 2
    assert state["seen_hit_ids"] == ["2", "1", "0"]
    # The checkpoint always moves forward, so the next run never pages
    # through the same hits again.
    assert state["last_run"] == NOW.isoformat()
    (warning,) = [m for level, _, m in logger.messages if level == "warning"]
    assert warning["reason"] == reason
    assert warning["hits_read"] == 2
    assert warning["hits_imported"] == 2
    assert warning["oldest_hit_read"] == "2026-11-10T14:40:00+00:00"


def test_run_after_incomplete_paging_asks_only_for_the_new_window():
    client = FakeClient([make_hit("1")], complete=False, stop_reason="page limit")
    source, _, _ = make_source(client=client)
    _, state = source.collect({})

    source._now = lambda: NOW + timedelta(hours=1)
    source.collect(state)
    assert client.calls == [24 * 3600, 3600 + LAG_MARGIN_SECONDS]


def _distinct_hits(count, created=None):
    """Hits for ``count`` different files, newest (highest id) first."""
    hits = []
    for n in range(count, 0, -1):
        hit = make_hit(str(n), sha256=f"{n:064x}", md5=f"{n:032x}", sha1=f"{n:040x}")
        if created is not None:
            hit["created"] = created(n).isoformat()
        hits.append(hit)
    return hits


def test_object_budget_stops_reading_advances_and_warns():
    previous = NOW - timedelta(hours=1)
    client = FakeClient(_distinct_hits(10))
    source, _, logger = make_source(client=client)
    # Each new file with a new rule can produce up to six objects.
    objects, state = source.collect({"last_run": previous.isoformat()}, max_objects=12)

    assert len(by_type(objects, "file")) == 2
    assert len(objects) <= 12
    assert state["seen_hit_ids"] == ["10", "9"]
    assert state["last_run"] == NOW.isoformat()
    # Reading stopped at the first hit over the budget, not at the end.
    assert client.readers[0].yielded == 3
    (warning,) = [m for level, _, m in logger.messages if level == "warning"]
    assert warning["reason"] == "object budget"
    assert warning["hits_imported"] == 2


class TimedClient:
    """Honours ``since`` like the API: hits created in the window, newest
    first, with at most ``page_cap`` hits per read (then incomplete)."""

    def __init__(self, hits, clock, page_cap=None):
        self.hits = sorted(hits, key=lambda h: h["created"], reverse=True)
        self.clock = clock
        self.page_cap = page_cap
        self.calls = []

    def read_live_hits(self, since_seconds):
        self.calls.append(since_seconds)
        start = self.clock() - timedelta(seconds=since_seconds)
        window = [h for h in self.hits if datetime.fromisoformat(h["created"]) >= start]
        if self.page_cap is not None and len(window) > self.page_cap:
            return FakeReader(window[: self.page_cap], False, "page limit")
        return FakeReader(window, True, None)


def _run_series(client, source, clock_times, max_objects):
    """Run collect once per clock time; return the hit ids sent per run."""
    state: dict = {}
    sent_per_run = []
    for when in clock_times:
        source._now = lambda when=when: when
        client.clock = lambda when=when: when
        objects, state = source.collect(state, max_objects=max_objects)
        sent_per_run.append(
            sorted(
                f["hashes"]["SHA-256"].lstrip("0") or "0"
                for f in by_type(objects, "file")
            )
        )
    return sent_per_run, state


def test_repeated_incomplete_reads_make_progress_and_never_resend():
    # 300 hits over the last 50 minutes; each read sees at most 40 of them.
    hits = _distinct_hits(300, created=lambda n: NOW - timedelta(seconds=10 * n))
    client = TimedClient(hits, clock=lambda: NOW, page_cap=40)
    source, _, _ = make_source(client=client)
    runs = [NOW + timedelta(hours=h) for h in range(4)]

    sent_per_run, state = _run_series(client, source, runs, max_objects=None)

    all_sent = [h for run in sent_per_run for h in run]
    assert len(all_sent) == len(set(all_sent))
    assert len(sent_per_run[0]) == 40
    # Later windows start after the previous run, so nothing is re-read.
    assert all(run == [] for run in sent_per_run[1:])
    assert client.calls[1:] == [3600 + LAG_MARGIN_SECONDS] * 3
    assert state["last_run"] == runs[-1].isoformat()


@pytest.mark.parametrize("max_objects", [None, 6 * 2000])
def test_backlog_beyond_seen_ids_limit_never_resends(max_objects):
    count = SEEN_IDS_LIMIT + 500
    # One hit every 600 ms over the last 55 minutes.
    hits = _distinct_hits(
        count, created=lambda n: NOW - timedelta(milliseconds=600 * n)
    )
    client = TimedClient(hits, clock=lambda: NOW)
    source, _, _ = make_source(client=client)
    runs = [NOW + timedelta(hours=h) for h in range(3)]

    sent_per_run, state = _run_series(client, source, runs, max_objects=max_objects)

    all_sent = [h for run in sent_per_run for h in run]
    assert len(all_sent) == len(set(all_sent))
    expected_first = count if max_objects is None else max_objects // 6
    assert len(sent_per_run[0]) == expected_first
    # The next windows only overlap the newest hits, which are remembered.
    assert sent_per_run[1:] == [[], []]
    assert len(state["seen_hit_ids"]) <= SEEN_IDS_LIMIT
    assert state["last_run"] == runs[-1].isoformat()


def test_hits_without_an_id_are_not_resent_once_the_window_moves():
    created = (NOW - timedelta(minutes=30)).isoformat()
    hits = [
        make_hit(None, created=created),
        make_hit(None, sha256=SHA256_B, created=created),
    ]
    client = TimedClient(hits, clock=lambda: NOW)
    source, _, _ = make_source(client=client)
    runs = [NOW, NOW + timedelta(hours=1), NOW + timedelta(hours=2)]

    sent_per_run, state = _run_series(client, source, runs, max_objects=6)

    # Without an id a hit cannot be remembered, but the checkpoint moves on,
    # so it is not read (or sent) again once it is out of the window.
    assert [len(run) for run in sent_per_run] == [1, 0, 0]
    assert state["seen_hit_ids"] == []


def test_already_seen_hits_do_not_use_the_object_budget():
    hits = _distinct_hits(3)
    source, _, _ = make_source(hits)
    objects, state = source.collect({"seen_hit_ids": ["3", "2"]}, max_objects=1)
    assert [f["hashes"]["SHA-256"] for f in by_type(objects, "file")] == [f"{1:064x}"]
    assert state["last_run"] == NOW.isoformat()


def test_collect_batches_splits_by_file_and_keeps_references_together():
    hits = _distinct_hits(5) + [
        make_hit(
            "x",
            sha256=f"{5:064x}",
            md5=f"{5:032x}",
            sha1=f"{5:040x}",
            rule_name="other_rule",
            malware_family="Emotet",
        )
    ]
    source, _, _ = make_source(hits)
    batches, state = source.collect_batches({}, batch_size=5)

    assert len(batches) > 1
    known = {AUTHOR["id"], TLP["id"]}
    files = []
    for batch in batches:
        ids = {o["id"] for o in batch} | known
        for obj in batch:
            for key in ("source_ref", "target_ref", "created_by_ref"):
                if key in obj:
                    assert obj[key] in ids
            for ref in obj.get("object_refs", []) + obj.get("object_marking_refs", []):
                assert ref in ids
        files += [o["hashes"]["SHA-256"] for o in by_type(batch, "file")]
    assert sorted(files) == sorted(f"{n:064x}" for n in range(1, 6))

    # The flat result holds the same objects, once each.
    flat, _ = make_source(hits)[0].collect({})
    assert sorted(o["id"] for o in flat) == sorted(
        {o["id"] for batch in batches for o in batch}
    )
    assert state["seen_hit_ids"][0] == "5"


def test_client_error_propagates_and_state_is_not_returned():
    error = RuntimeError("boom")
    source, _, _ = make_source(client=FakeClient(error=error))
    with pytest.raises(RuntimeError):
        source.collect({"last_run": "2026-11-10T14:00:00+00:00"})


def test_default_client_built_from_config(monkeypatch):
    created = {}

    class Recorder:
        def __init__(self, api_url, api_key):
            created["api_url"] = api_url
            created["api_key"] = api_key

    monkeypatch.setattr(hunting, "PolySwarmHuntingClient", Recorder)
    HuntingSource(make_config(), AUTHOR, TLP, FakeLogger())
    assert created == {
        "api_url": "https://api.polyswarm.network",
        "api_key": "0" * 32,
    }


# ----------------------------------------------------------------------
# Review fixes: transient incomplete hits, grouped family selection
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "broken",
    [{"sha256": None}, {"sha256": "xyz"}, {"rule_name": ""}, {"rule_name": None}],
)
def test_incomplete_hit_is_not_remembered_and_later_copy_is_imported(broken):
    source, _, logger = make_source([make_hit("77", **broken)])
    objects, state = source.collect({})
    assert objects == []
    assert "77" not in state["seen_hit_ids"]
    skipped = [m for m in logger.messages if m[1].endswith("hits processed.")][0][2]
    assert skipped["hits_skipped_invalid"] == 1

    source2, _, _ = make_source([make_hit("77")])
    objects, state = source2.collect(state)
    assert len(by_type(objects, "note")) == 1
    assert "77" in state["seen_hit_ids"]


def test_complete_hit_is_still_deduplicated_by_id():
    source, _, _ = make_source([make_hit("5"), make_hit("5")])
    objects, state = source.collect({})
    assert state["seen_hit_ids"] == ["5"]
    note = by_type(objects, "note")[0]
    assert "Hits for this rule and file in this import: 1" in note["content"]


def test_group_uses_newest_real_family_not_only_newest_hit():
    hits = [
        make_hit("3", malware_family="Trojan.Packed2"),
        make_hit("2", malware_family="AsyncRat"),
        make_hit("1", malware_family="Copak"),
    ]
    source, _, _ = make_source(hits)
    objects, _ = source.collect({})
    assert [m["name"] for m in by_type(objects, "malware")] == ["AsyncRat"]
    indicates = [
        r
        for r in by_type(objects, "relationship")
        if r["relationship_type"] == "indicates"
    ]
    assert len(indicates) == 1
    note = by_type(objects, "note")[0]
    assert indicates[0]["id"] in note["object_refs"]
    for name in ("Trojan.Packed2", "AsyncRat", "Copak"):
        assert name in note["content"]
        assert f"polyswarm-family:{name}" in note["labels"]
    assert "no malware object was created" not in note["content"]


def test_group_with_only_labels_creates_no_malware_and_lists_them():
    hits = [
        make_hit("2", malware_family="Trojan.Packed2"),
        make_hit("1", malware_family="PUA.Generic"),
    ]
    source, _, _ = make_source(hits)
    objects, _ = source.collect({})
    assert by_type(objects, "malware") == []
    note = by_type(objects, "note")[0]
    assert "Trojan.Packed2, PUA.Generic" in note["content"]
    assert "no malware object was created" in note["content"]
