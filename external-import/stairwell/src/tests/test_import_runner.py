import json
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from connector.import_runner import ImportRunner, StairwellImportError
from connector.stairwell import StairwellClient
from stix2patterns.v21.pattern import Pattern
from stix2patterns.validator import run_validator


def _client(pages):
    """pages is a list of (status, body_dict) tuples returned in order."""
    c = StairwellClient.__new__(StairwellClient)
    c._base_url = "https://app.stairwell.com"
    c._timeout = 30
    c._session = None
    iterator = iter(pages)
    c.list_objects_metadata = MagicMock(side_effect=lambda **_: next(iterator))
    return c


def _helper():
    helper = MagicMock()
    helper.get_state = MagicMock(return_value=None)
    helper.set_state = MagicMock()
    helper.send_stix2_bundle = MagicMock()
    helper.log_info = MagicMock()
    helper.log_warning = MagicMock()
    helper.log_error = MagicMock()
    return helper


def _runner(helper, client, **overrides):
    defaults = dict(
        first_run_window=timedelta(days=1),
        max_indicators=100,
        page_size=10,
        min_bucket="HIGH",
        scope_environment=True,
        wrapper="grouping",
        tlp="green",
        indicator_validity_days=90,
    )
    defaults.update(overrides)
    return ImportRunner(helper=helper, client=client, **defaults)


def _file_obj(sha256, bucket="PROBABILITY_HIGH", with_net=False):
    obj = {
        "sha256": sha256,
        "sha1": "a" * 40,
        "md5": "b" * 32,
        "stairwellFirstSeenTime": "2026-05-06T00:00:00Z",
        "malEval": {"probabilityBucket": bucket},
    }
    if with_net:
        obj["networkIndicators"] = {
            "ipAddresses": ["1.2.3.4"],
            "hostnames": ["c2.example.com"],
            "urls": ["http://c2.example.com/x"],
        }
    return obj


def test_happy_path_emits_grouping_with_indicators():
    pages = [
        (
            200,
            {
                "objectMetadatas": [
                    _file_obj("a" * 64, with_net=True),
                    _file_obj("b" * 64),
                ],
                "nextPageToken": "",
            },
        )
    ]
    client = _client(pages)
    helper = _helper()
    runner = _runner(helper, client)

    msg = runner.run()
    assert "2 indicators emitted" in msg

    helper.send_stix2_bundle.assert_called_once()
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    types = [o["type"] for o in payload["objects"]]

    assert "grouping" in types
    # Only files become Indicators; network values are related observables.
    assert types.count("indicator") == 2
    assert types.count("file") == 2
    assert types.count("ipv4-addr") == 1
    assert types.count("domain-name") == 1
    assert types.count("url") == 1
    rels = [o for o in payload["objects"] if o["type"] == "relationship"]
    assert (
        sorted(r["relationship_type"] for r in rels)
        == ["based-on"] * 2 + ["related-to"] * 3
    )

    # Wrapper Grouping has all the new objects in its object_refs.
    grouping = next(o for o in payload["objects"] if o["type"] == "grouping")
    assert "Stairwell daily MalEval feed" in grouping["name"]
    assert grouping["context"] == "malware-analysis"


def test_report_wrapper_when_configured():
    pages = [(200, {"objectMetadatas": [_file_obj("c" * 64)], "nextPageToken": ""})]
    client = _client(pages)
    helper = _helper()
    runner = _runner(helper, client, wrapper="report")
    runner.run()
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    types = [o["type"] for o in payload["objects"]]
    assert "report" in types
    assert "grouping" not in types
    report = next(o for o in payload["objects"] if o["type"] == "report")
    assert report["report_types"] == ["threat-report"]


def test_indicator_validity_window_set():
    pages = [(200, {"objectMetadatas": [_file_obj("d" * 64)], "nextPageToken": ""})]
    client = _client(pages)
    helper = _helper()
    runner = _runner(helper, client, indicator_validity_days=30)
    runner.run()
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    indicator = next(
        o
        for o in payload["objects"]
        if o["type"] == "indicator" and o["pattern"].startswith("[file:")
    )
    assert "valid_from" in indicator
    assert "valid_until" in indicator
    assert indicator["confidence"] == 75  # PROBABILITY_HIGH


def _stateful_helper(initial=None):
    helper = _helper()
    store = {"state": initial}
    helper.get_state = MagicMock(side_effect=lambda: store["state"])
    helper.set_state = MagicMock(side_effect=lambda st: store.update(state=st))
    return helper, store


def _page(prefix, n, next_token):
    objs = [_file_obj(f"{prefix}{i:063x}") for i in range(n)]
    return (200, {"objectMetadatas": objs, "nextPageToken": next_token})


def _file_indicator_count(helper, call=-1):
    payload = json.loads(helper.send_stix2_bundle.call_args_list[call][0][0])
    return len(
        [
            o
            for o in payload["objects"]
            if o["type"] == "indicator" and o["pattern"].startswith("[file:")
        ]
    )


def test_truncation_stops_at_page_boundary_and_emits_note():
    pages = [_page("a", 2, "p2"), _page("b", 2, "p3"), _page("c", 2, "")]
    client = _client(pages)
    helper, _ = _stateful_helper()
    runner = _runner(helper, client, max_indicators=3)
    msg = runner.run()
    assert "truncated=True" in msg
    # The cap is checked between pages, so page 2 finishes (4 >= 3).
    assert client.list_objects_metadata.call_count == 2
    assert _file_indicator_count(helper) == 4
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    notes = [o for o in payload["objects"] if o["type"] == "note"]
    assert any(n["abstract"] == "Stairwell Import Truncation" for n in notes)


def test_truncated_run_resumes_from_cursor_without_losing_objects():
    pages = [_page("a", 2, "p2"), _page("b", 2, "p3"), _page("c", 2, "")]
    client = _client(pages)
    helper, store = _stateful_helper({"last_run": "2026-05-04T00:00:00.000Z"})
    runner = _runner(helper, client, max_indicators=2)

    runner.run()
    # Watermark held; cursor saved for the next page of the same window.
    assert store["state"]["last_run"] == "2026-05-04T00:00:00.000Z"
    pending = store["state"]["pending"]
    assert pending["page_token"] == "p2"
    assert pending["cutoff"] == "2026-05-04T00:00:00.000Z"
    window_end = pending["window_end"]

    runner.run()
    second = client.list_objects_metadata.call_args_list[1].kwargs
    assert second["page_token"] == "p2"
    assert "2026-05-04T00:00:00.000Z" in second["cel_filter"]
    assert store["state"]["pending"]["page_token"] == "p3"

    runner.run()
    third = client.list_objects_metadata.call_args_list[2].kwargs
    assert third["page_token"] == "p3"
    # Window drained: watermark advances to the end of the first run's window.
    assert "pending" not in store["state"]
    assert store["state"]["last_run"] == window_end

    assert [_file_indicator_count(helper, i) for i in range(3)] == [2, 2, 2]


def test_pagination_failure_does_not_advance_state_or_send():
    pages = [_page("a", 2, "p2"), (503, None)]
    client = _client(pages)
    helper, store = _stateful_helper({"last_run": "2026-05-04T00:00:00.000Z"})
    runner = _runner(helper, client)
    with pytest.raises(StairwellImportError):
        runner.run()
    helper.send_stix2_bundle.assert_not_called()
    assert store["state"] == {"last_run": "2026-05-04T00:00:00.000Z"}


def test_first_page_failure_does_not_advance_state():
    client = _client([(500, None)])
    helper, store = _stateful_helper(None)
    runner = _runner(helper, client)
    with pytest.raises(StairwellImportError):
        runner.run()
    helper.set_state.assert_not_called()


def test_rejected_resume_cursor_restarts_window_from_first_page():
    state = {
        "last_run": "2026-05-04T00:00:00.000Z",
        "pending": {
            "cutoff": "2026-05-04T00:00:00.000Z",
            "window_end": "2026-05-05T00:00:00.000Z",
            "page_token": "expired",
        },
    }
    client = _client([(400, None), _page("a", 1, "")])
    helper, store = _stateful_helper(state)
    runner = _runner(helper, client)
    with pytest.raises(StairwellImportError):
        runner.run()
    assert store["state"]["pending"]["page_token"] is None
    assert store["state"]["pending"]["cutoff"] == "2026-05-04T00:00:00.000Z"

    runner.run()
    retry = client.list_objects_metadata.call_args_list[1].kwargs
    assert retry["page_token"] is None
    assert "2026-05-04T00:00:00.000Z" in retry["cel_filter"]
    assert store["state"] == {"last_run": "2026-05-05T00:00:00.000Z"}


def test_transient_failure_on_resume_keeps_cursor():
    state = {
        "last_run": "2026-05-04T00:00:00.000Z",
        "pending": {
            "cutoff": "2026-05-04T00:00:00.000Z",
            "window_end": "2026-05-05T00:00:00.000Z",
            "page_token": "p2",
        },
    }
    client = _client([(503, None)])
    helper, store = _stateful_helper(state)
    runner = _runner(helper, client)
    with pytest.raises(StairwellImportError):
        runner.run()
    assert store["state"] == state


def test_network_values_are_related_observables_not_indicators():
    url = "http://c2.example.com/a'b?q=1&r=2"
    obj = _file_obj("f" * 64)
    obj["networkIndicators"] = {
        "ipAddresses": ["1.2.3.4", "2001:db8::1"],
        "hostnames": ["C2.Example.com"],
        "urls": [url],
    }
    client = _client([(200, {"objectMetadatas": [obj], "nextPageToken": ""})])
    helper = _helper()
    msg = _runner(helper, client).run()
    assert "1 indicators emitted" in msg
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    by_id = {o["id"]: o for o in payload["objects"]}

    indicators = [o for o in payload["objects"] if o["type"] == "indicator"]
    assert [i["pattern"] for i in indicators] == [
        f"[file:hashes.'SHA-256' = '{'f' * 64}']"
    ]

    file_id = next(o["id"] for o in payload["objects"] if o["type"] == "file")
    related = {
        by_id[r["target_ref"]]["value"]: by_id[r["target_ref"]]
        for r in payload["objects"]
        if r["type"] == "relationship"
        and r["relationship_type"] == "related-to"
        and r["source_ref"] == file_id
    }
    assert set(related) == {"1.2.3.4", "2001:db8::1", "c2.example.com", url}
    assert related["2001:db8::1"]["type"] == "ipv6-addr"
    refs = related[url]["external_references"]
    assert refs[0]["url"] == (
        "https://app.stairwell.com/search?search-query="
        "http%3A%2F%2Fc2.example.com%2Fa%27b%3Fq%3D1%26r%3D2"
    )
    # Every observable sits in the run's Grouping.
    grouping = next(o for o in payload["objects"] if o["type"] == "grouping")
    assert {o["id"] for o in related.values()} <= set(grouping["object_refs"])


def test_network_value_shared_by_two_files_is_one_observable_two_links():
    a, b = _file_obj("a" * 64), _file_obj("b" * 64)
    for obj in (a, b):
        obj["networkIndicators"] = {"hostnames": ["c2.example.com"]}
    client = _client([(200, {"objectMetadatas": [a, b], "nextPageToken": ""})])
    helper = _helper()
    _runner(helper, client).run()
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    assert [o["type"] for o in payload["objects"]].count("domain-name") == 1
    links = [
        o
        for o in payload["objects"]
        if o["type"] == "relationship" and o["relationship_type"] == "related-to"
    ]
    assert len({r["source_ref"] for r in links}) == 2


def test_state_persisted_after_run():
    pages = [(200, {"objectMetadatas": [_file_obj("e" * 64)], "nextPageToken": ""})]
    client = _client(pages)
    helper = _helper()
    runner = _runner(helper, client)
    runner.run()
    helper.set_state.assert_called_once()
    state_arg = helper.set_state.call_args[0][0]
    assert "last_run" in state_arg


def test_state_used_as_cutoff_on_subsequent_run():
    pages = [(200, {"objectMetadatas": [], "nextPageToken": ""})]
    client = _client(pages)
    helper = _helper()
    helper.get_state.return_value = {"last_run": "2026-05-04T00:00:00.000Z"}
    runner = _runner(helper, client)
    runner.run()
    # The CEL filter passed should reference the state cutoff, not now-1d.
    call = client.list_objects_metadata.call_args
    cel = call.kwargs["cel_filter"]
    assert "2026-05-04T00:00:00.000Z" in cel


def test_pagination_continues_until_no_token():
    pages = [
        (200, {"objectMetadatas": [_file_obj("a" * 64)], "nextPageToken": "p2"}),
        (200, {"objectMetadatas": [_file_obj("b" * 64)], "nextPageToken": ""}),
    ]
    client = _client(pages)
    helper = _helper()
    runner = _runner(helper, client)
    runner.run()
    assert client.list_objects_metadata.call_count == 2


def test_client_side_bucket_filter_drops_below_min():
    objs = [
        _file_obj("a" * 64, bucket="PROBABILITY_LOW"),
        _file_obj("b" * 64, bucket="PROBABILITY_MEDIUM"),
        _file_obj("c" * 64, bucket="PROBABILITY_HIGH"),
        _file_obj("d" * 64, bucket="PROBABILITY_VERY_HIGH"),
    ]
    pages = [(200, {"objectMetadatas": objs, "nextPageToken": ""})]
    client = _client(pages)
    helper = _helper()
    runner = _runner(helper, client, min_bucket="HIGH")
    msg = runner.run()
    # 2 emitted (HIGH + VERY_HIGH), 2 filtered out
    assert "2 indicators emitted" in msg
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    file_indicators = [
        o
        for o in payload["objects"]
        if o["type"] == "indicator" and o["pattern"].startswith("[file:")
    ]
    assert len(file_indicators) == 2


def test_empty_result_does_not_emit_bundle():
    pages = [(200, {"objectMetadatas": [], "nextPageToken": ""})]
    client = _client(pages)
    helper = _helper()
    runner = _runner(helper, client)
    msg = runner.run()
    assert "No indicators emitted" in msg
    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_called_once()


@pytest.mark.parametrize(
    "bad_hash",
    [
        "a" * 60 + "'] OR [ipv4-addr:value = '10.0.0.1",
        "a" * 63,
        "g" * 64,
        "",
    ],
)
def test_object_with_invalid_sha256_is_skipped_not_sent(bad_hash):
    good = "B" * 64
    client = _client(
        [
            (
                200,
                {
                    "objectMetadatas": [_file_obj(bad_hash), _file_obj(good)],
                    "nextPageToken": "",
                },
            )
        ]
    )
    helper = _helper()
    msg = _runner(helper, client).run()
    assert "1 indicators emitted" in msg
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    patterns = [o["pattern"] for o in payload["objects"] if o["type"] == "indicator"]
    assert patterns == [f"[file:hashes.'SHA-256' = '{good.lower()}']"]
    assert run_validator(patterns[0]) == []
    assert list(Pattern(patterns[0]).inspect().comparisons) == ["file"]
