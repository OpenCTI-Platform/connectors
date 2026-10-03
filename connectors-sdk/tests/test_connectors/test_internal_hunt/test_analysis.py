# pragma: no cover
# type: ignore
"""Tests of the hunt result post-processing helpers."""

import time
from datetime import datetime, timezone

import pytest
from connectors_sdk.connectors.internal_hunt import (
    BenignMatcher,
    HuntEvent,
    HuntLimits,
    HuntResult,
    HuntTimeoutError,
    HuntTimeWindow,
    RunDeadline,
    build_evidence,
    count_distinct_entities,
    event_time_bounds,
    flatten_fields,
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


def test_suppress_benign_keeps_the_total_of_a_truncated_result_without_benign_events():
    # Given a truncated result whose returned events are all relevant
    result = HuntResult(
        events=_events({"u": "alice"}, {"u": "bob"}), total_hits=50, truncated=True
    )

    # When/Then nothing is suppressed and the platform total stands
    assert suppress_benign(result, ["svc"], _deadline()) is result
    assert result.hits_count == 50


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
