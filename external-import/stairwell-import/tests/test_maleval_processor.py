from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, ConnectorState
from connector.data_processors import MalEvalFilesProcessor
from connectors_sdk import ConfigValidationError
from connectors_sdk.exceptions.error import DataRetrievalError
from stix2patterns.v21.pattern import Pattern
from stix2patterns.validator import run_validator


class FakeLogger:
    def __init__(self):
        self.warnings = []

    def info(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        self.warnings.append(args)

    def error(self, *args, **kwargs):
        pass


@pytest.fixture
def env(monkeypatch):
    for key, value in {
        "OPENCTI_URL": "http://opencti:8080",
        "OPENCTI_TOKEN": "token",
        "CONNECTOR_ID": "22222222-2222-4222-8222-222222222222",
        "CONNECTOR_SCOPE": "stairwell",
        "STAIRWELL_API_TOKEN": "sw-token",
        "STAIRWELL_IMPORT_MAX_INDICATORS": "100",
        "STAIRWELL_IMPORT_PAGE_SIZE": "10",
    }.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


def _processor(pages, state=None):
    """A processor wired as the SDK wires it, with the API client mocked.

    `pages` is the list of (status, body) the API returns, in order.
    """
    processor = MalEvalFilesProcessor()
    processor.settings = ConnectorSettings()
    processor.state = state or ConnectorState()
    processor.logger = FakeLogger()
    processor.post_init()
    processor.client.list_objects_metadata = MagicMock(side_effect=list(pages))
    return processor


def _run(processor):
    """One connector run: what BaseDataProcessor.process does, minus sending."""
    return processor.transform(processor.collect())


def _file_obj(sha256, bucket="PROBABILITY_HIGH", net=None, **extra):
    # Each file has its own SHA-1/MD5, as real files do: a File's STIX ID
    # derives from one hash (MD5 first), so shared fake hashes would collide.
    digest = (str(sha256) * 2)[:40] if sha256 else ""
    obj = {
        "sha256": sha256,
        "sha1": digest if len(digest) == 40 else "a" * 40,
        "md5": digest[:32] if len(digest) == 40 else "b" * 32,
        "stairwellFirstSeenTime": "2026-05-06T00:00:00Z",
        "malEval": {"probabilityBucket": bucket} if bucket else {},
    }
    if net is not None:
        obj["networkIndicators"] = net
    obj.update(extra)
    return obj


def _page(prefix, n, next_token):
    objs = [_file_obj(f"{prefix}{i:063x}") for i in range(n)]
    return (200, {"objectMetadatas": objs, "nextPageToken": next_token})


def _one_page(*objs):
    return [(200, {"objectMetadatas": list(objs), "nextPageToken": ""})]


def _of_type(objects, stix_type):
    return [o for o in objects if o["type"] == stix_type]


def _file_patterns(objects):
    return [
        o["pattern"]
        for o in _of_type(objects, "indicator")
        if o["pattern"].startswith("[file:")
    ]


NET = {
    "ipAddresses": ["1.2.3.4"],
    "hostnames": ["c2.example.com"],
    "urls": ["http://c2.example.com/x"],
}


def test_happy_path_emits_grouping_with_indicators(env):
    objects = _run(
        _processor(_one_page(_file_obj("a" * 64, net=NET), _file_obj("b" * 64)))
    )
    assert len(_of_type(objects, "indicator")) == 2
    assert len(_of_type(objects, "file")) == 2
    for t in ("ipv4-addr", "domain-name", "url"):
        assert len(_of_type(objects, t)) == 1
    rels = sorted(r["relationship_type"] for r in _of_type(objects, "relationship"))
    assert rels == ["based-on"] * 2 + ["related-to"] * 3
    grouping = _of_type(objects, "grouping")[0]
    assert grouping["name"].startswith("Stairwell MalEval import — ")
    assert grouping["context"] == "malware-analysis"
    assert {
        o["id"]
        for o in objects
        if o["type"] not in ("identity", "grouping", "marking-definition")
    } <= set(grouping["object_refs"])


def test_report_wrapper_when_configured(env):
    env.setenv("STAIRWELL_IMPORT_WRAPPER", "report")
    objects = _run(_processor(_one_page(_file_obj("c" * 64))))
    assert not _of_type(objects, "grouping")
    assert _of_type(objects, "report")[0]["report_types"] == ["threat-report"]


def test_wrapper_setting_rejects_unknown_values(env):
    env.setenv("STAIRWELL_IMPORT_WRAPPER", "grouppping")
    with pytest.raises(ConfigValidationError) as err:
        ConnectorSettings()
    assert "import_wrapper" in str(err.value.__cause__)


def test_each_run_gets_its_own_wrapper(env):
    state = ConnectorState()
    first = _run(_processor(_one_page(_file_obj("c" * 64)), state))
    second = _run(_processor(_one_page(_file_obj("d" * 64)), state))
    assert _of_type(first, "grouping")[0]["id"] != _of_type(second, "grouping")[0]["id"]


def test_indicator_validity_window_and_confidence(env):
    env.setenv("STAIRWELL_IMPORT_INDICATOR_VALIDITY_DAYS", "30")
    objects = _run(_processor(_one_page(_file_obj("d" * 64))))
    indicator = _of_type(objects, "indicator")[0]
    assert indicator["valid_from"] == "2026-05-06T00:00:00.000Z"
    assert indicator["valid_until"] == "2026-06-05T00:00:00.000Z"
    assert indicator["confidence"] == 75  # PROBABILITY_HIGH


def test_source_timestamps_are_normalised_to_utc(env):
    obj = _file_obj("e" * 64, stairwellFirstSeenTime="2026-05-06T01:00:00+01:00")
    objects = _run(_processor(_one_page(obj)))
    assert _of_type(objects, "indicator")[0]["valid_from"] == "2026-05-06T00:00:00.000Z"


def test_truncation_stops_at_page_boundary_and_saves_cursor(env):
    env.setenv("STAIRWELL_IMPORT_MAX_INDICATORS", "3")
    processor = _processor(
        [_page("a", 2, "p2"), _page("b", 2, "p3"), _page("c", 2, "")]
    )
    objects = _run(processor)
    # The cap is checked between pages, so page 2 finishes (4 >= 3).
    assert processor.client.list_objects_metadata.call_count == 2
    assert len(_file_patterns(objects)) == 4
    assert any(
        n["abstract"] == "Stairwell Import Truncation"
        for n in _of_type(objects, "note")
    )
    assert processor.state.pending_page_token == "p3"
    assert processor.state.watermark is None


def test_capped_window_drains_across_runs_without_losing_objects(env):
    env.setenv("STAIRWELL_IMPORT_MAX_INDICATORS", "2")
    watermark = datetime(2026, 5, 4, tzinfo=timezone.utc)
    state = ConnectorState(watermark=watermark)
    pages = [_page("a", 2, "p2"), _page("b", 2, "p3"), _page("c", 2, "")]

    first = _processor(pages[:1], state)
    counts = [len(_file_patterns(_run(first)))]
    assert state.watermark == watermark
    assert state.pending_cutoff == watermark
    assert state.pending_page_token == "p2"
    window_end = state.pending_window_end

    second = _processor(pages[1:2], state)
    counts.append(len(_file_patterns(_run(second))))
    call = second.client.list_objects_metadata.call_args.kwargs
    assert call["page_token"] == "p2"
    assert "2026-05-04T00:00:00.000Z" in call["cel_filter"]
    assert state.pending_page_token == "p3"

    third = _processor(pages[2:], state)
    counts.append(len(_file_patterns(_run(third))))
    assert third.client.list_objects_metadata.call_args.kwargs["page_token"] == "p3"
    # Window drained: the watermark advances to the first run's window end.
    assert state.watermark == window_end
    assert state.pending_cutoff is None and state.pending_page_token is None
    assert counts == [2, 2, 2]


@pytest.mark.parametrize(
    "pages",
    [
        [_page("a", 2, "p2"), (503, None)],
        [(500, None)],
        [(200, {"objectMetadatas": "nope", "nextPageToken": ""})],
    ],
)
def test_fetch_failure_raises_without_moving_checkpoints(env, pages):
    state = ConnectorState(watermark=datetime(2026, 5, 4, tzinfo=timezone.utc))
    before = state.model_dump()
    processor = _processor(pages, state)
    with pytest.raises(DataRetrievalError, match="watermark was not advanced"):
        processor.collect()
    assert state.model_dump() == before


def _pending_state(token):
    return ConnectorState(
        watermark=datetime(2026, 5, 4, tzinfo=timezone.utc),
        pending_cutoff=datetime(2026, 5, 4, tzinfo=timezone.utc),
        pending_window_end=datetime(2026, 5, 5, tzinfo=timezone.utc),
        pending_page_token=token,
    )


def test_rejected_resume_token_restarts_window_within_the_run(env):
    state = _pending_state("expired")
    processor = _processor([(400, None), _page("a", 1, "")], state)
    assert len(_file_patterns(_run(processor))) == 1
    retry = processor.client.list_objects_metadata.call_args_list[1].kwargs
    assert retry["page_token"] is None
    assert "2026-05-04T00:00:00.000Z" in retry["cel_filter"]
    assert state.watermark == datetime(2026, 5, 5, tzinfo=timezone.utc)
    assert state.pending_page_token is None
    assert processor.logger.warnings


@pytest.mark.parametrize("status", [429, 503, 0])
def test_transient_failure_on_resume_keeps_cursor(env, status):
    state = _pending_state("p2")
    before = state.model_dump()
    processor = _processor([(status, None)], state)
    with pytest.raises(DataRetrievalError):
        processor.collect()
    assert state.model_dump() == before


def test_network_values_are_related_observables_not_indicators(env):
    url = "http://c2.example.com/a'b?q=1&r=2"
    net = {
        "ipAddresses": ["1.2.3.4", "2001:DB8::1", "1.2.3.4:80", "not-an-ip"],
        "hostnames": ["C2.Example.com"],
        "urls": [url],
    }
    objects = _run(_processor(_one_page(_file_obj("f" * 64, net=net))))
    by_id = {o["id"]: o for o in objects}
    assert _file_patterns(objects) == [f"[file:hashes.'SHA-256' = '{'f' * 64}']"]
    assert len(_of_type(objects, "indicator")) == 1
    file_id = _of_type(objects, "file")[0]["id"]
    related = {
        by_id[r["target_ref"]]["value"]: by_id[r["target_ref"]]
        for r in _of_type(objects, "relationship")
        if r["relationship_type"] == "related-to" and r["source_ref"] == file_id
    }
    # Invalid IPs are dropped; IPv6 is normalised.
    assert set(related) == {"1.2.3.4", "2001:db8::1", "c2.example.com", url}
    assert related["2001:db8::1"]["type"] == "ipv6-addr"
    assert related[url]["external_references"][0]["url"] == (
        "https://app.stairwell.com/search?search-query="
        "http%3A%2F%2Fc2.example.com%2Fa%27b%3Fq%3D1%26r%3D2"
    )


def test_network_value_shared_by_two_files_is_one_observable_two_links(env):
    net = {"hostnames": ["c2.example.com"]}
    objects = _run(
        _processor(
            _one_page(_file_obj("a" * 64, net=net), _file_obj("b" * 64, net=net))
        )
    )
    assert len(_of_type(objects, "domain-name")) == 1
    links = [
        r
        for r in _of_type(objects, "relationship")
        if r["relationship_type"] == "related-to"
    ]
    assert len({r["source_ref"] for r in links}) == 2


def test_new_window_starts_at_the_watermark(env):
    state = ConnectorState(watermark=datetime(2026, 5, 4, tzinfo=timezone.utc))
    processor = _processor(_one_page(), state)
    _run(processor)
    cel = processor.client.list_objects_metadata.call_args.kwargs["cel_filter"]
    assert "2026-05-04T00:00:00.000Z" in cel


def test_pagination_continues_until_no_token(env):
    processor = _processor([_page("a", 1, "p2"), _page("b", 1, "")])
    assert len(_file_patterns(_run(processor))) == 2
    assert processor.client.list_objects_metadata.call_count == 2


@pytest.mark.parametrize("bucket", [None, "PROBABILITY_UNKNOWN", "PROBABILITY_LOW"])
def test_objects_without_a_qualifying_bucket_are_filtered(env, bucket):
    objects = _run(
        _processor(_one_page(_file_obj("a" * 64, bucket=bucket), _file_obj("b" * 64)))
    )
    assert _file_patterns(objects) == [f"[file:hashes.'SHA-256' = '{'b' * 64}']"]


def test_client_side_bucket_filter_respects_min_bucket(env):
    objs = [
        _file_obj("a" * 64, bucket="PROBABILITY_LOW"),
        _file_obj("b" * 64, bucket="PROBABILITY_MEDIUM"),
        _file_obj("c" * 64, bucket="PROBABILITY_HIGH"),
        _file_obj("d" * 64, bucket="PROBABILITY_VERY_HIGH"),
    ]
    assert len(_file_patterns(_run(_processor(_one_page(*objs))))) == 2


def test_empty_result_sends_nothing_but_advances_the_watermark(env):
    processor = _processor(_one_page())
    assert _run(processor) == []
    assert processor.state.watermark is not None


@pytest.mark.parametrize(
    "bad_hash",
    ["a" * 60 + "'] OR [ipv4-addr:value = '10.0.0.1", "a" * 63, "g" * 64, ""],
)
def test_object_with_invalid_sha256_is_skipped_not_sent(env, bad_hash):
    processor = _processor(_one_page(_file_obj(bad_hash), _file_obj("B" * 64)))
    patterns = _file_patterns(_run(processor))
    assert patterns == [f"[file:hashes.'SHA-256' = '{'b' * 64}']"]
    assert run_validator(patterns[0]) == []
    assert list(Pattern(patterns[0]).inspect().comparisons) == ["file"]
    assert processor.logger.warnings


def test_malformed_optional_hashes_are_left_out(env):
    obj = _file_obj("c" * 64, sha1="x" * 40, md5="D" * 32)
    file_sco = _of_type(_run(_processor(_one_page(obj))), "file")[0]
    assert file_sco["hashes"] == {"SHA-256": "c" * 64, "MD5": "d" * 32}


def _loaded(raw):
    """A ConnectorState populated the way BaseConnectorState.load() does it."""
    state = ConnectorState()
    for key, value in raw.items():
        setattr(state, key, value)
    return state


def test_pre_sdk_state_is_migrated_not_dropped(env):
    state = _loaded(
        {
            "last_run": "2026-04-01T00:00:00.000Z",
            "pending": {
                "cutoff": "2026-03-01T00:00:00.000Z",
                "window_end": "2026-04-01T00:00:00.000Z",
                "page_token": "p7",
            },
        }
    )
    processor = _processor(_one_page(), state)
    processor.collect()
    call = processor.client.list_objects_metadata.call_args.kwargs
    assert call["page_token"] == "p7"
    assert "2026-03-01T00:00:00.000Z" in call["cel_filter"]
    assert state.watermark == datetime(2026, 4, 1, tzinfo=timezone.utc)
    assert "pending" not in state.to_json()


def test_pre_sdk_watermark_without_pending_window(env):
    state = _loaded({"last_run": "2026-04-01T00:00:00.000Z"})
    processor = _processor(_one_page(), state)
    processor.collect()
    assert "2026-04-01T00:00:00.000Z" in (
        processor.client.list_objects_metadata.call_args.kwargs["cel_filter"]
    )


def test_current_state_is_not_reinterpreted(env):
    # A first window that was capped: no watermark yet, but the SDK's own
    # last_run is set. That last_run must not become the watermark.
    state = _loaded(
        {
            "last_run": "2026-05-06T00:00:00+00:00",
            "watermark": None,
            "pending_cutoff": "2026-05-04T00:00:00+00:00",
            "pending_window_end": "2026-05-05T00:00:00+00:00",
            "pending_page_token": "p2",
        }
    )
    processor = _processor(_one_page(), state)
    processor.collect()
    assert state.watermark is None
    assert processor.client.list_objects_metadata.call_args.kwargs["page_token"] == "p2"


@pytest.mark.parametrize("tlp", ["green", "clear", "amber+strict"])
def test_every_reference_in_the_result_resolves_within_it(env, tlp):
    env.setenv("STAIRWELL_IMPORT_TLP", tlp)
    net = {"ipAddresses": ["1.2.3.4"], "hostnames": ["c2.example.com"]}
    objects = _run(_processor(_one_page(_file_obj("a" * 64, net=net))))
    ids = {o["id"] for o in objects}
    markings = [o for o in objects if o["type"] == "marking-definition"]
    assert len(markings) == 1
    for obj in objects:
        refs = list(obj.get("object_marking_refs") or [])
        refs += [
            obj[k] for k in ("created_by_ref", "source_ref", "target_ref") if k in obj
        ]
        refs += list(obj.get("object_refs") or [])
        missing = [r for r in refs if r not in ids]
        assert not missing, (obj["type"], missing)


def test_send_failure_leaves_checkpoints_unmoved(env):
    """The SDK sends after transform(); if that fails, nothing may advance."""
    state = ConnectorState()
    processor = _processor(_one_page(_file_obj("a" * 64)), state)
    processor.work_manager = MagicMock()
    processor.work_manager.__enter__ = MagicMock(return_value=processor.work_manager)
    processor.work_manager.__exit__ = MagicMock(return_value=False)
    processor.work_manager.send.side_effect = RuntimeError("queue down")
    before = state.model_dump()
    with pytest.raises(RuntimeError, match="queue down"):
        processor.process()
    assert state.model_dump() == before
    processor.work_manager.send.assert_called_once()


def test_successful_process_moves_checkpoints(env):
    state = ConnectorState()
    processor = _processor(_one_page(_file_obj("a" * 64)), state)
    processor.work_manager = MagicMock()
    processor.work_manager.__enter__ = MagicMock(return_value=processor.work_manager)
    processor.work_manager.__exit__ = MagicMock(return_value=False)
    processor.process()
    assert state.watermark is not None


def test_failed_run_on_legacy_state_keeps_the_legacy_cursor(env):
    """A rollback must not leave the state looking already migrated."""
    raw = {
        "last_run": "2026-04-01T00:00:00.000Z",
        "pending": {
            "cutoff": "2026-03-01T00:00:00.000Z",
            "window_end": "2026-04-01T00:00:00.000Z",
            "page_token": "p7",
        },
    }
    state = _loaded(raw)
    failing = _processor(_one_page(_file_obj("a" * 64)), state)
    failing.work_manager = MagicMock()
    failing.work_manager.__enter__ = MagicMock(return_value=failing.work_manager)
    failing.work_manager.__exit__ = MagicMock(return_value=False)
    failing.work_manager.send.side_effect = RuntimeError("queue down")
    with pytest.raises(RuntimeError):
        failing.process()
    # Next run: the SDK's load() re-applies the stored (still legacy) keys.
    for key, value in raw.items():
        setattr(state, key, value)
    retry = _processor(_one_page(), state)
    retry.collect()
    assert retry.client.list_objects_metadata.call_args.kwargs["page_token"] == "p7"


def _clocked(processor, *times):
    """Make processor._now() return each of `times` in turn (one per run)."""
    processor._now = MagicMock(side_effect=list(times))
    return processor


def _cel(processor, call=-1):
    return processor.client.list_objects_metadata.call_args_list[call].kwargs[
        "cel_filter"
    ]


def test_failed_first_run_retry_keeps_the_first_window(env):
    """A first run that fails must not let a later retry skip its backfill."""
    may6 = datetime(2026, 5, 6, tzinfo=timezone.utc)
    may7 = datetime(2026, 5, 7, tzinfo=timezone.utc)
    may8 = datetime(2026, 5, 8, tzinfo=timezone.utc)
    state = ConnectorState()
    # One processor instance across runs, as the SDK keeps it.
    processor = _processor(_one_page(_file_obj("a" * 64)) * 3, state)
    _clocked(processor, may6, may7, may8)
    processor.work_manager = MagicMock()
    processor.work_manager.__enter__ = MagicMock(return_value=processor.work_manager)
    processor.work_manager.__exit__ = MagicMock(return_value=False)

    processor.work_manager.send.side_effect = RuntimeError("queue down")
    with pytest.raises(RuntimeError):
        processor.process()
    processor.work_manager.send.side_effect = None
    processor.process()  # the retry, a day later
    retry = _cel(processor)
    assert '>= "2026-05-05T00:00:00.000Z"' in retry
    assert '< "2026-05-06T00:00:00.000Z"' in retry
    assert state.watermark == may6

    processor.process()  # the next scheduled run
    nxt = _cel(processor)
    assert '>= "2026-05-06T00:00:00.000Z"' in nxt
    assert '< "2026-05-08T00:00:00.000Z"' in nxt


def test_every_page_of_a_resumed_window_keeps_its_upper_bound(env):
    env.setenv("STAIRWELL_IMPORT_MAX_INDICATORS", "1")
    state = ConnectorState()
    pages = [_page("a", 1, "p2"), _page("b", 1, "")]
    first = _clocked(
        _processor(pages[:1], state), datetime(2026, 5, 6, tzinfo=timezone.utc)
    )
    _run(first)
    end = '< "2026-05-06T00:00:00.000Z"'
    assert end in _cel(first)
    second = _clocked(
        _processor(pages[1:], state), datetime(2026, 5, 9, tzinfo=timezone.utc)
    )
    _run(second)
    assert end in _cel(second)
    assert state.watermark == datetime(2026, 5, 6, tzinfo=timezone.utc)


def test_legacy_cursor_without_window_end_resumes_up_to_now(env):
    """Old-format state may lack `window_end`; the window then runs to now."""
    state = _loaded(
        {
            "last_run": "2026-04-01T00:00:00.000Z",
            "pending": {"cutoff": "2026-03-01T00:00:00.000Z", "page_token": "p7"},
        }
    )
    processor = _clocked(
        _processor(_one_page(), state), datetime(2026, 5, 9, 12, tzinfo=timezone.utc)
    )
    processor.collect()
    call = processor.client.list_objects_metadata.call_args.kwargs
    assert call["page_token"] == "p7"
    assert '>= "2026-03-01T00:00:00.000Z"' in call["cel_filter"]
    assert '< "2026-05-09T12:00:00.000Z"' in call["cel_filter"]
