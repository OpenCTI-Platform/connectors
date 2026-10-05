# pragma: no cover
# type: ignore
"""Tests of the hunt result post-processing helpers."""

import time
from datetime import datetime, timedelta, timezone

import pytest
from connectors_sdk.connectors.internal_hunt import (
    BenignMatcher,
    HitFields,
    HuntEvent,
    HuntHitEvidence,
    HuntHitField,
    HuntLimits,
    HuntResult,
    HuntTimeoutError,
    HuntTimeWindow,
    RunDeadline,
    build_evidence,
    build_hit_evidence,
    build_hit_keys,
    count_distinct_entities,
    event_time_bounds,
    flatten_fields,
    hit_key,
    present_fields,
    sha256_hex,
    suppress_benign,
    value_strings,
)


def _events(*field_sets):
    return [HuntEvent(fields=fields) for fields in field_sets]


def _deadline():
    return RunDeadline(60)


def test_flatten_fields_uses_dotted_names():
    # Given/When a nested document is flattened
    flat = flatten_fields({"process": {"pid": 4, "parent": {"name": "x"}}, "e": {}})

    # Then nested keys become dotted names and empty mappings are kept as values
    assert flat == {"process.pid": 4, "process.parent.name": "x", "e": {}}


def test_value_strings_normalizes_values():
    # Given/When/Then each kind of value gives its string forms
    assert value_strings(None) == []
    assert value_strings("  ") == []
    assert value_strings(True) == ["true"]
    assert value_strings(42) == ["42"]
    assert value_strings(["a", None, ["b"]]) == ["a", "b"]
    assert value_strings({"k": 1}) == ['{"k": 1}']
    assert value_strings({}) == []


def test_sha256_hex():
    # Given/When/Then the digest is the SHA-256 hex of the UTF-8 value
    assert sha256_hex("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_benign_matcher_substrings_and_regexes():
    # Given substrings, a regex and an invalid regex
    matcher = BenignMatcher(
        ["SCCM", "/^svc_backup[0-9]+$/", "/[unclosed/", " "], _deadline()
    )

    # When/Then events matching any of them are benign
    assert bool(matcher) is True
    assert matcher.matches(HuntEvent(fields={"cmd": "run sccm agent"}))
    assert matcher.matches(HuntEvent(fields={"user": "SVC_BACKUP01"}))
    assert matcher.matches(HuntEvent(fields={"x": "a /[unclosed/ b"}))
    assert not matcher.matches(HuntEvent(fields={"user": "alice", "n": None}))
    assert bool(BenignMatcher(["", "  "], _deadline())) is False


def test_benign_matcher_bounds_regexes_by_the_run_deadline():
    # Given a backtracking regex and a value that makes it explode
    matcher = BenignMatcher(["/(a|aa)+$/"], RunDeadline(0.2))
    event = HuntEvent(fields={"user": "a" * 60 + "!"})

    # When/Then matching stops at the deadline with a run timeout
    started = time.monotonic()
    with pytest.raises(HuntTimeoutError, match=r"/\(a\|aa\)\+\$/ did not complete"):
        matcher.matches(event)
    assert time.monotonic() - started < 5


def test_benign_matcher_refuses_regexes_once_the_deadline_is_reached():
    # Given an expired run deadline
    matcher = BenignMatcher(["/^svc/"], RunDeadline(0))

    # When/Then no regular expression runs past it
    with pytest.raises(HuntTimeoutError, match="run timeout"):
        matcher.matches(HuntEvent(fields={"user": "svc_backup"}))


def test_suppress_benign_without_patterns_returns_the_result():
    # Given a result and no benign pattern
    result = HuntResult(events=_events({"a": "x"}))

    # When/Then the result is unchanged
    assert suppress_benign(result, [], _deadline()) is result
    assert suppress_benign(result, ["nomatch"], _deadline()) is result


def test_suppress_benign_removes_matching_events():
    # Given a complete result with one benign event
    result = HuntResult(events=_events({"u": "alice"}, {"u": "svc"}), total_hits=2)

    # When benign events are suppressed
    suppressed = suppress_benign(result, ["svc"], _deadline())

    # Then the hit count only counts the remaining events
    assert [e.fields["u"] for e in suppressed.events] == ["alice"]
    assert suppressed.hits_count == 1


def test_suppress_benign_counts_the_detections_left_with_relevant_events():
    # Given two detections: one referencing a benign and a relevant event, the
    # other only a benign one
    result = HuntResult(
        events=[
            HuntEvent(fields={"u": "svc"}, detection="d1"),
            HuntEvent(fields={"u": "alice"}, detection="d1"),
            HuntEvent(fields={"u": "svc"}, detection="d2"),
        ],
        total_hits=2,
    )

    # When benign events are suppressed
    suppressed = suppress_benign(result, ["svc"], _deadline())

    # Then the detection left with a relevant event is the only hit
    assert [e.fields["u"] for e in suppressed.events] == ["alice"]
    assert suppressed.hits_count == 1


def test_suppress_benign_on_truncated_results_reports_the_verified_hits_only():
    # Given a truncated result whose returned events include a benign one
    result = HuntResult(
        events=_events({"u": "alice"}, {"u": "svc"}), total_hits=50, truncated=True
    )

    # When benign events are suppressed
    suppressed = suppress_benign(result, ["svc"], _deadline())

    # Then the unknowable post-suppression total is not derived from the sample:
    # the hit count is the non-benign returned events
    assert suppressed.total_hits is None
    assert suppressed.hits_count == 1
    assert suppressed.truncated is True


def test_suppress_benign_drops_the_total_of_a_truncated_result_without_benign_events():
    # Given a truncated result whose returned events are all relevant
    result = HuntResult(
        events=_events({"u": "alice"}, {"u": "bob"}), total_hits=50, truncated=True
    )

    # When benign events are suppressed
    suppressed = suppress_benign(result, ["svc"], _deadline())

    # Then the platform total is still an upper bound (unreturned events may be
    # benign): the hit count is the returned events, kept partial
    assert suppressed.total_hits is None
    assert suppressed.hits_count == 2
    assert suppressed.truncated is True


def test_suppress_benign_keeps_a_complete_result_without_benign_events():
    # Given a complete result whose events are all relevant
    result = HuntResult(events=_events({"u": "alice"}, {"u": "bob"}), total_hits=2)

    # When/Then nothing is suppressed and the result stands
    assert suppress_benign(result, ["svc"], _deadline()) is result


def test_build_evidence_hashes_truncates_and_spreads_over_fields():
    # Given events with repeated values over several fields
    events = _events(
        {"CommandLine": "powershell -enc AAAA" * 3, "host": "ws1", "_raw": "secret"},
        {"CommandLine": "powershell -enc AAAA" * 3, "host": "ws2", "empty": None},
        {"CommandLine": "cmd /c whoami", "host": "ws1"},
    )
    limits = HuntLimits(evidence_max_items=3, evidence_max_value_length=10)

    # When the evidence is built with CommandLine as detection field
    evidence = build_evidence(events, limits, ["commandline"], ["_RAW"])

    # Then detection fields come first, the most frequent value first, one per field in turn
    assert [(e.field, e.count) for e in evidence] == [
        ("CommandLine", 2),
        ("host", 2),
        ("CommandLine", 1),
    ]
    assert evidence[0].value_preview == "powershell"
    assert evidence[0].value_hash == sha256_hex("powershell -enc AAAA" * 3)
    assert all(e.field != "_raw" for e in evidence)


def test_build_evidence_excludes_the_sub_fields_of_an_excluded_field():
    # Given bookkeeping fields nested under an excluded parent
    events = _events(
        {
            "metadata.base_labels.log_types": "WINDOWS_SYSMON",
            "metadata.base_labels.allow_scoped_access": True,
            "metadata.base_labels_extra": "kept",
            "target.process.command_line": "powershell -enc AAAA",
        }
    )

    # When the evidence is built without the parent field
    evidence = build_evidence(events, HuntLimits(), (), ["metadata.BASE_LABELS"])

    # Then its sub-fields are left out, never a field that only shares its prefix
    assert [e.field for e in evidence] == [
        "metadata.base_labels_extra",
        "target.process.command_line",
    ]


def test_present_fields_reads_the_names_case_insensitively_in_order():
    # Given an event and field names in another case, one missing, one repeated
    event = HuntEvent(fields={"Host.Name": "ws1", "CommandLine": "x"})

    # When/Then the event names are returned in the order of the names asked for
    assert present_fields(
        event, ["commandline", "missing", "host.name", "HOST.NAME"]
    ) == [
        "CommandLine",
        "Host.Name",
    ]


def test_build_hit_evidence_describes_each_hit_on_its_own():
    # Given two hits of a detection on CommandLine, the later one first, and one without time
    early = datetime(2026, 10, 3, 1, tzinfo=timezone.utc)
    late = datetime(2026, 10, 3, 5, tzinfo=timezone.utc)
    command_line = "powershell -enc " + "A" * 40
    hits = [
        (
            HuntEvent(
                timestamp=late,
                fields={
                    "CommandLine": "cmd /c whoami",
                    "Host.Name": "ws2",
                    "user": ["bob", "carol"],
                    "event.id": "e2",
                },
                detection="detection-1",
            ),
            ["CommandLine"],
        ),
        (HuntEvent(fields={"CommandLine": "x", "empty": None}), ["empty"]),
        (
            HuntEvent(
                timestamp=early,
                fields={
                    "CommandLine": command_line,
                    "host.name": "ws1",
                    "user.name": "alice",
                    "process.executable": "C:\\Windows\\powershell.exe",
                    "event.id": "e1",
                },
            ),
            ["CommandLine"],
        ),
    ]

    # When the evidence of the hits is built
    evidence = build_hit_evidence(
        hits, HuntLimits(evidence_max_items=10, evidence_max_value_length=16)
    )

    # Then each hit tells what matched, where, by whom and when, the earliest first
    first, second, third = evidence
    assert (first.event_id, first.timestamp, first.host, first.user) == (
        "e1",
        early,
        "ws1",
        "alice",
    )
    assert first.process == "C:\\Windows\\power"
    assert [(f.field, f.value_preview) for f in first.matched] == [
        ("CommandLine", "powershell -enc ")
    ]
    assert first.matched[0].value_hash == sha256_hex(command_line)
    assert (second.event_id, second.host, second.user) == ("e2", "ws2", "bob")
    assert second.detection == "detection-1"
    assert second.process is None
    # And a hit without time comes last, a matched field without value is left out
    assert third.timestamp is None
    assert third.matched == []


def test_build_hit_evidence_is_capped_by_the_evidence_limit():
    # Given three hits
    hits = [(HuntEvent(fields={"a": str(index)}), ["a"]) for index in range(3)]

    # When/Then at most evidence_max_items hits are kept, none when disabled
    assert len(build_hit_evidence(hits, HuntLimits(evidence_max_items=2))) == 2
    assert build_hit_evidence(hits, HuntLimits(evidence_max_items=0)) == []


def test_hit_fields_can_name_the_fields_of_a_platform():
    # Given a platform naming its hosts and event ids its own way
    fields = HitFields(event_id=("metadata.id",), host=("principal.hostname",))
    event = HuntEvent(
        fields={"metadata.id": "AAAA", "principal.hostname": "ws1", "host": "other"}
    )

    # When/Then the hit is described with the fields of the platform
    (hit,) = build_hit_evidence([(event, [])], HuntLimits(), fields)
    assert (hit.event_id, hit.host) == ("AAAA", "ws1")


def test_build_evidence_stops_when_values_are_exhausted_or_disabled():
    # Given few values
    events = _events({"a": "x"}, {"a": "x", "b": "y"})

    # When/Then the sample stops when no value is left, or is empty when disabled
    assert len(build_evidence(events, HuntLimits(evidence_max_items=10))) == 2
    assert build_evidence(events, HuntLimits(evidence_max_items=0)) == []


def test_count_distinct_entities():
    # Given events hitting hosts, users and peers
    events = _events(
        {"host.name": "WS1", "user.name": "alice", "CommandLine": "x"},
        {"Host.Name": "ws1", "user.name": "bob"},
        {"source.ip": ["8.8.8.8", "1.1.1.1"]},
    )

    # When/Then distinct values of entity fields are counted case-insensitively
    assert count_distinct_entities(events) == 5
    assert count_distinct_entities(events, ["CommandLine"]) == 1


def test_event_time_bounds():
    # Given a window and events with and without timestamps
    window = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")
    first = datetime(2026, 10, 3, 1, tzinfo=timezone.utc)
    last = datetime(2026, 10, 3, 5, tzinfo=timezone.utc)
    events = [
        HuntEvent(timestamp=last),
        HuntEvent(timestamp=None),
        HuntEvent(timestamp=first),
    ]

    # When/Then the bounds are the event times, or the window without times
    assert event_time_bounds(events, window) == (first, last)
    assert event_time_bounds([HuntEvent()], window) == (window.start, window.end)


# The vectors OpenCTI asserts as well (opencti-graphql tests/01-unit/modules/hunt):
# both sides must compute the same key for the same reported hit
HIT_KEY_VECTORS = {
    "detection": "3b02b63d8af62713440dd85ed25dd3f88e81e03c977896d7cfe34d2943c1fd56",
    "event": "377ad8ff94d918dc181777c7885fe87b097ce4d00ce135abbdd484463d07fe0c",
    "fields": "fad50c3a235a2707741dadfd8948e0eead646c7e2f5d997093a6cc306e79e418",
    "empty": "d3cfa790c1b204d5670ff28bab8eb2e65a0ed4df3f129240fca7fd570560e132",
}


def test_hit_key_matches_the_vectors_shared_with_opencti():
    # Given a hit grouped into a detection, a hit with an event id, a hit known by
    # its fields only (non-UTC time with sub-seconds, accents, quotes, upper-case
    # hash, fields out of order) and a hit with empty identifiers
    fields_hit = HuntHitEvidence(
        timestamp=datetime(
            2026, 10, 5, 23, 59, 59, 750000, tzinfo=timezone(timedelta(hours=2))
        ),
        host="WKS-01",
        user="j\u00e9r\u00f4me",
        process="powershell.exe",
        matched=[
            HuntHitField(
                field="process.command_line", value_hash="AB" * 32, value_preview="x"
            ),
            HuntHitField(
                field="destination.ip", value_hash="cd" * 32, value_preview='"q"'
            ),
        ],
    )

    # When/Then each key is the shared vector
    assert hit_key(HuntHitEvidence(detection="de_8f2c", event_id="e1")) == (
        HIT_KEY_VECTORS["detection"]
    )
    assert hit_key(HuntHitEvidence(event_id='evt "42"')) == HIT_KEY_VECTORS["event"]
    assert hit_key(fields_hit) == HIT_KEY_VECTORS["fields"]
    assert hit_key(HuntHitEvidence(detection="", event_id="")) == (
        HIT_KEY_VECTORS["empty"]
    )


def test_hit_key_ignores_what_does_not_identify_the_hit():
    # Given the same event reported with other previews, sub-seconds or field order
    base = HuntHitEvidence(
        timestamp=datetime(2026, 10, 3, 2, 0, 0, tzinfo=timezone.utc),
        host="ws1",
        matched=[
            HuntHitField(field="a", value_hash="11" * 32, value_preview="one"),
            HuntHitField(field="b", value_hash="22" * 32, value_preview="two"),
        ],
    )
    same = HuntHitEvidence(
        timestamp=datetime(2026, 10, 3, 2, 0, 0, 900000, tzinfo=timezone.utc),
        host="ws1",
        matched=[
            HuntHitField(field="b", value_hash="22" * 32, value_preview=None),
            HuntHitField(field="a", value_hash="11" * 32, value_preview="o"),
        ],
    )
    other_host = base.model_copy(update={"host": "ws2"})

    # When/Then only identifying values change the key
    assert hit_key(base) == hit_key(same)
    assert hit_key(base) != hit_key(other_host)
    # And a detection or an event id identifies a hit whatever its other values
    assert hit_key(base.model_copy(update={"event_id": "e1"})) == hit_key(
        other_host.model_copy(update={"event_id": "e1"})
    )


def test_build_hit_keys_counts_a_detection_once():
    # Given two events of one detection, an event with an id and one without
    limits = HuntLimits(evidence_max_value_length=16)
    stamp = datetime(2026, 10, 3, 2, tzinfo=timezone.utc)
    events = [
        HuntEvent(timestamp=stamp, fields={"event.id": "a"}, detection="det-1"),
        HuntEvent(timestamp=stamp, fields={"event.id": "b"}, detection="det-1"),
        HuntEvent(timestamp=stamp, fields={"event.id": "c"}),
        HuntEvent(timestamp=stamp, fields={"host": "ws1", "CommandLine": "x"}),
    ]

    # When the keys of the hits are built
    keys = build_hit_keys(
        [(event, present_fields(event, ["CommandLine"])) for event in events], limits
    )

    # Then the detection is one hit, and each key is the key of its sampled hit
    sample = build_hit_evidence(
        [(event, present_fields(event, ["CommandLine"])) for event in events], limits
    )
    assert len(keys) == 3
    assert set(keys) == {hit_key(hit) for hit in sample}
