import json
from datetime import timedelta
from unittest.mock import MagicMock

from connector.import_runner import ImportRunner
from connector.stairwell import StairwellClient


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
    assert types.count("indicator") == 5  # 2 file + 1 ip + 1 domain + 1 url
    assert types.count("file") == 2
    assert types.count("ipv4-addr") == 1
    assert types.count("domain-name") == 1
    assert types.count("url") == 1
    # based-on relationships: 5 indicators → 5 SCOs
    rels = [o for o in payload["objects"] if o["type"] == "relationship"]
    assert all(r["relationship_type"] == "based-on" for r in rels)
    assert len(rels) == 5

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


def test_truncation_emits_truncation_note():
    objs = [_file_obj(f"{i:064x}") for i in range(5)]
    pages = [(200, {"objectMetadatas": objs, "nextPageToken": ""})]
    client = _client(pages)
    helper = _helper()
    runner = _runner(helper, client, max_indicators=2)
    msg = runner.run()
    assert "truncated=True" in msg
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    notes = [o for o in payload["objects"] if o["type"] == "note"]
    assert any(n["abstract"] == "Stairwell Import Truncation" for n in notes)
    indicators = [
        o
        for o in payload["objects"]
        if o["type"] == "indicator" and o["pattern"].startswith("[file:")
    ]
    assert len(indicators) == 2  # cap respected


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
