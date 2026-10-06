# pylint: disable=protected-access

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests
from connector.api_client import (
    PostBatch,
    RansomLookAPIClient,
    RansomLookAPIError,
    RansomLookCapabilityUnavailable,
    RansomLookCycleBudgetExhausted,
    RansomLookPostWindowTooLarge,
)

FIXTURES = Path(__file__).parent / "fixtures" / "api"


@pytest.fixture(autouse=True)
def skip_retry_backoff(monkeypatch):
    monkeypatch.setattr("connector.api_client.time.sleep", lambda _seconds: None)


def fixture(name):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def streaming_response(payload, *, status=200, headers=None, chunks=None):
    """Build a bounded streaming response double."""
    response = MagicMock(spec=requests.Response)
    response.status_code = status
    response.headers = headers or {}
    body = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
    response.iter_content.return_value = chunks if chunks is not None else [body]
    return response


def test_posts_accepts_wrapped_response():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(
        return_value={
            "posts": [
                {
                    "group_name": "akira",
                    "post_title": "Example Corp",
                    "discovered": "2026-01-01T00:00:00Z",
                }
            ]
        }
    )
    result = client.get_posts(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    assert result[0]["group_name"] == "akira"


def test_group_discards_binary_payload_shape_errors():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(return_value=[{"meta": "description"}, "invalid"])
    with pytest.raises(RansomLookAPIError, match="group posts"):
        client.get_group("akira")


def test_api_key_and_successful_request():
    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api/", api_key="secret"
    )
    response = streaming_response({"ok": True})
    client.session.get = MagicMock(return_value=response)

    assert client.session.headers["Authorization"] == "secret"
    assert client._get("/health", {"check": 1}) == {"ok": True}
    response.raise_for_status.assert_called_once()
    response.close.assert_called_once()
    client.session.get.assert_called_once_with(
        "https://example.test/api/health",
        params={"check": 1},
        timeout=(10, 60),
        stream=True,
    )


def test_request_404_is_allowed():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    response = streaming_response([], status=404)
    client.session.get = MagicMock(return_value=response)
    assert client._get("missing", allow_404=True) == []
    response.close.assert_called_once()


def test_transport_errors_are_logged_and_wrapped():
    helper = MagicMock()
    client = RansomLookAPIClient(helper, "https://example.test/api")
    client.session.get = MagicMock(side_effect=requests.ConnectionError("offline"))

    with pytest.raises(RansomLookAPIError, match="Unable to query"):
        client._get("posts")
    helper.connector_logger.error.assert_called_once()


def test_invalid_json_is_rejected_logged_and_closed():
    helper = MagicMock()
    client = RansomLookAPIClient(helper, "https://example.test/api")
    response = streaming_response(b"not json")
    client.session.get = MagicMock(return_value=response)

    with pytest.raises(RansomLookAPIError, match="invalid JSON"):
        client._get("posts")
    helper.connector_logger.error.assert_called_once()
    response.close.assert_called_once()


def test_optional_request_can_defer_contextual_error_logging():
    helper = MagicMock()
    client = RansomLookAPIClient(helper, "https://example.test/api")
    response = streaming_response(b"not json")
    client.session.get = MagicMock(return_value=response)

    with pytest.raises(RansomLookAPIError, match="invalid JSON"):
        client._get("optional", log_errors=False)
    helper.connector_logger.error.assert_not_called()


def test_pathologically_nested_json_is_rejected():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    with patch(
        "connector.api_client.json.loads", side_effect=RecursionError("too deep")
    ):
        with pytest.raises(RansomLookAPIError, match="invalid JSON"):
            client._decode_json(streaming_response({}))


@pytest.mark.parametrize(
    ("headers", "chunks", "message"),
    [
        ({"Content-Length": "invalid"}, [], "invalid Content-Length"),
        ({"Content-Length": "-1"}, [], "invalid Content-Length"),
        ({"Content-Length": str(2 * 1024 * 1024)}, [], "size limit"),
        ({}, [b"a" * (1024 * 1024 + 1)], "size limit"),
    ],
)
def test_response_size_and_header_limits(headers, chunks, message):
    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_response_size_mb=1
    )
    response = streaming_response({}, headers=headers, chunks=chunks)
    with pytest.raises(RansomLookAPIError, match=message):
        client._decode_json(response)


def test_decode_retains_bounded_capture_fields_for_evidence_layer():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    response = streaming_response(
        {
            "screen": "large",
            "nested": {"source": "html", "kept": True},
            "items": [{"screen": "large"}, "kept"],
        },
        chunks=[
            b"",
            b'{"screen":"large","nested":{"source":"html","kept":true},'
            b'"items":[{"screen":"large"},"kept"]}',
        ],
    )
    assert client._decode_json(response) == {
        "screen": "large",
        "nested": {"source": "html", "kept": True},
        "items": [{"screen": "large"}, "kept"],
    }


@pytest.mark.parametrize("payload", ["invalid", ["invalid"]])
def test_posts_rejects_invalid_payloads(payload):
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(return_value=payload)
    with pytest.raises(RansomLookAPIError, match="Unexpected response"):
        client.get_posts(
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 2, tzinfo=timezone.utc),
        )


def test_posts_chunks_deduplicates_and_validates_window():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    valid = {
        "group_name": "akira",
        "post_title": "Example Corp",
        "discovered": "2026-01-01T00:00:00Z",
    }
    invalid = {"group_name": "akira"}
    client._get = MagicMock(side_effect=[[valid, invalid], [valid]])

    result = client.get_posts(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 9, tzinfo=timezone.utc),
    )
    assert result == [valid, invalid]
    assert client._get.call_count == 2
    with pytest.raises(RansomLookAPIError, match="start is after"):
        client.get_posts(
            datetime(2026, 1, 2, tzinfo=timezone.utc),
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_group_normalizes_invalid_members_and_filters_posts():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(
        return_value=[
            "bad metadata",
            [
                {
                    "ok": True,
                    "screen": "large",
                    "nested": {"source": "html"},
                    "items": [{"screen": "large"}, "kept"],
                },
                "bad",
            ],
        ]
    )
    with pytest.raises(RansomLookAPIError, match="group endpoint"):
        client.get_group("space group")
    client._get.assert_called_with(
        "group/space%20group", allow_404=True, log_errors=False
    )

    client._get.return_value = {"not": "a list"}
    with pytest.raises(RansomLookAPIError, match="group endpoint"):
        client.get_group("x")


def test_group_notes_normalizes_response():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(return_value=[{"id": "one"}])
    assert client.get_group_notes("space group") == [{"id": "one"}]
    client._get.assert_called_with(
        "notes/group/space%20group",
        log_errors=False,
        optional_capability="notes",
    )
    client._get.return_value = {"invalid": True}
    with pytest.raises(RansomLookAPIError, match="notes endpoint"):
        client.get_group_notes("x")


@pytest.mark.parametrize(
    "payload", [{"description": "claim"}, [{"description": "claim"}], []]
)
def test_post_normalizes_supported_response(payload):
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(return_value=payload)
    expected = {} if payload == [] else ({"description": "claim"})
    assert client.get_post("space group", "victim/name") == expected
    client._get.assert_called_once_with(
        "post/space%20group/victim%2Fname", allow_404=True, log_errors=False
    )


@pytest.mark.parametrize("payload", [["invalid"], "invalid", [{}, {}]])
def test_post_rejects_malformed_response(payload):
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(return_value=payload)
    with pytest.raises(RansomLookAPIError, match="post endpoint"):
        client.get_post("g", "p")


def test_sanitized_fixtures_cover_all_consumed_contracts():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(
        side_effect=[
            fixture("posts"),
            fixture("group"),
            fixture("post"),
            fixture("actors"),
            fixture("actor"),
            fixture("notes"),
            fixture("note"),
            fixture("crypto"),
            fixture("torrents"),
            fixture("leaks"),
            fixture("leak"),
        ]
    )

    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert client.get_posts(start, start)[0]["post_title"] == "Example Victim"
    group, history = client.get_group("example-operation")
    assert group["locations"][0]["screen"]
    assert history[0]["post_title"] == "Example Victim"
    assert client.get_post("example-operation", "Example Victim")["source"]
    assert client.get_actors()[0]["name"] == "example-person"
    assert client.get_actor("example-person")["relations"]["groups"]
    assert client.get_group_notes("example-operation")[0]["id"] == "example-note"
    assert client.get_note("example-note")["format"] == "txt"
    assert client.get_group_crypto("example-operation")["total"] == 1
    assert client.get_torrents("example-operation")[0]["infohash"]
    assert client.get_leaks()[0]["id"] == 1
    assert client.get_leak(1)["domain"] == "example.invalid"


def test_optional_auth_and_absent_capabilities_are_distinct_and_not_logged():
    helper = MagicMock()
    client = RansomLookAPIClient(helper, "https://example.test/api")
    response = streaming_response({}, status=403)
    client.session.get = MagicMock(return_value=response)
    with pytest.raises(RansomLookCapabilityUnavailable) as exc:
        client.get_actors()
    assert exc.value.capability == "actors"
    assert exc.value.status_code == 403
    helper.connector_logger.error.assert_not_called()

    with pytest.raises(RansomLookCapabilityUnavailable) as exc:
        client.get_group_analyses("example-operation")
    assert exc.value.capability == "analyses"
    assert exc.value.status_code is None


@pytest.mark.parametrize("field", ["screen", "source"])
def test_capture_carriers_require_scalar_strings(field):
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(return_value={field: {"nested": "payload"}})
    with pytest.raises(RansomLookAPIError, match=field):
        client.get_post("g", "p")


def test_group_locations_are_validated_and_available_separately():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(return_value=fixture("group"))
    locations = client.get_group_locations("example-operation")
    assert locations[0]["private"] is True
    assert locations[0]["available"] is False

    client._get.return_value = [{"locations": ["bad"]}, []]
    with pytest.raises(RansomLookAPIError, match="locations field"):
        client.get_group("bad")


def test_record_limits_apply_to_collections_and_pagination():
    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_records=2, max_pages=2
    )
    client._get = MagicMock(return_value=[{}, {}, {}])
    with pytest.raises(RansomLookAPIError, match="record limit"):
        client.get_actors()

    client._get.return_value = [{"id": 1}, {"id": 2}, {"id": 3}]
    with pytest.raises(RansomLookCapabilityUnavailable) as unavailable:
        client.get_leaks()
    assert unavailable.value.capability == "leaks"

    page_one = {"total": 4, "results": [{"id": 1}, {"id": 2}]}
    page_two = {"total": 4, "results": [{"id": 3}, {"id": 4}]}
    client._get = MagicMock(side_effect=[page_one, page_two])
    assert client.get_torrents() == [{"id": 1}, {"id": 2}]
    assert client._get.call_count == 1


def test_malformed_optional_shapes_fail_predictably():
    client = RansomLookAPIClient(MagicMock(), "https://example.test/api")
    client._get = MagicMock(return_value={"by_chain": []})
    with pytest.raises(RansomLookAPIError, match="by_chain"):
        client.get_group_crypto("g")

    client._get.return_value = {"total": "many", "results": []}
    with pytest.raises(RansomLookAPIError, match="total field"):
        client.get_torrents()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_response_size_mb": 0},
        {"max_records": 0},
        {"max_pages": 0},
    ],
)
def test_client_rejects_unbounded_configuration(kwargs):
    with pytest.raises(ValueError):
        RansomLookAPIClient(MagicMock(), "https://example.test/api", **kwargs)


def test_remaining_bounds_and_optional_transport_paths():
    helper = MagicMock()
    client = RansomLookAPIClient(helper, "https://example.test/api", max_records=1)
    client.session.get = MagicMock(side_effect=requests.ConnectionError("offline"))
    with pytest.raises(RansomLookAPIError, match="Unable to query"):
        client._get("optional", log_errors=False)
    helper.connector_logger.error.assert_not_called()

    with pytest.raises(RansomLookAPIError, match="capture exceeds"):
        client._evidence_record(
            {"screen": "x" * (client.max_response_bytes + 1)}, "post"
        )

    client._get = MagicMock(return_value=[])
    assert client.get_group("missing") == ({}, [])

    client._get.return_value = [{"locations": [{}, {}]}, []]
    with pytest.raises(RansomLookAPIError, match="locations exceed"):
        client.get_group("many")


def test_cross_window_wallet_and_torrent_aggregate_limits():
    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_records=3, max_pages=2
    )
    post = {
        "group_name": "g",
        "post_title": "p",
        "discovered": "2026-01-01T00:00:00Z",
    }
    client._get = MagicMock(
        side_effect=[[post, {**post, "post_title": "p2"}], [post, post]]
    )
    batch = client.get_posts(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 9, tzinfo=timezone.utc),
    )
    assert [post["post_title"] for post in batch.posts] == ["p", "p2"]
    assert batch.deferred_windows == []

    client._get = MagicMock(
        return_value={"by_chain": {"bitcoin": [{}, {}], "ethereum": [{}, {}]}}
    )
    with pytest.raises(RansomLookAPIError, match="crypto response exceeds"):
        client.get_group_crypto("g")

    client._get = MagicMock(
        side_effect=[
            {"total": 4, "results": [{"id": 1}, {"id": 2}]},
            {"total": 4, "results": [{"id": 3}, {"id": 4}]},
        ]
    )
    assert client.get_torrents() == [{"id": 1}, {"id": 2}, {"id": 3}]

    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_records=5, max_pages=1
    )
    client._get = MagicMock(return_value={"total": 10, "results": [{"id": 1}]})
    assert client.get_torrents() == [{"id": 1}]


def test_physical_retries_consume_the_shared_request_budget():
    client = RansomLookAPIClient(
        MagicMock(),
        "https://example.test/api",
        max_requests_per_run=2,
        max_run_duration_seconds=60,
    )
    client.session.get = MagicMock(side_effect=requests.ConnectionError("offline"))

    with pytest.raises(RansomLookCycleBudgetExhausted, match="attempt"):
        client._get("posts")

    assert client.session.get.call_count == 2
    assert client.request_attempts == 2


def test_remaining_run_time_bounds_timeout_and_streaming():
    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_run_duration_seconds=60
    )
    response = streaming_response([])
    client.session.get = MagicMock(return_value=response)
    client.run_deadline = client.run_started + 0.5

    assert client._get("posts") == []
    connect_timeout, read_timeout = client.session.get.call_args.kwargs["timeout"]
    assert 0 < connect_timeout <= 0.5
    assert 0 < read_timeout <= 0.5

    expiring = streaming_response([])

    def chunks(*_args, **_kwargs):
        yield b"["
        client.run_deadline = 0
        yield b"]"

    expiring.iter_content.side_effect = chunks
    client.session.get.return_value = expiring
    client.begin_run()
    with pytest.raises(RansomLookCycleBudgetExhausted, match="duration"):
        client._get("posts")


def test_oversized_post_ranges_subdivide_without_losing_later_posts():
    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_records=2, max_pages=10
    )
    first = {
        "group_name": "g",
        "post_title": "first",
        "discovered": "2026-01-01T00:00:00Z",
    }
    later = {**first, "post_title": "later", "discovered": "2026-01-03T00:00:00Z"}
    client._get = MagicMock(
        side_effect=[
            RansomLookPostWindowTooLarge("record limit"),
            [first],
            [later],
        ]
    )

    batch = client.get_posts(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
    )

    assert [post["post_title"] for post in batch.posts] == ["first", "later"]
    assert batch.deferred_windows == []
    assert client._get.call_count == 3


def test_single_oversized_day_is_deferred_while_later_day_continues():
    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_records=2, max_pages=2
    )
    client._POST_WINDOW_DAYS = 1
    later = {
        "group_name": "g",
        "post_title": "later",
        "discovered": "2026-01-02T00:00:00Z",
    }
    client._get = MagicMock(
        side_effect=[RansomLookPostWindowTooLarge("record limit"), [later]]
    )

    batch = client.get_posts(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    assert batch.posts == [later]
    assert [(item.start, item.end) for item in batch.deferred_windows] == [
        ("2026-01-01", "2026-01-01")
    ]


def test_post_batch_sequence_and_equality_contract():
    post = {"id": "one"}
    batch = PostBatch([post], [])
    assert list(batch) == [post]
    assert len(batch) == 1
    assert batch[0] == post
    assert batch == [post]
    assert batch == PostBatch([post], [])
    assert batch != PostBatch([], [])
    assert batch != object()


@pytest.mark.parametrize(
    "values",
    [
        {"max_requests_per_run": 0},
        {"max_run_duration_seconds": 0},
    ],
)
def test_client_rejects_invalid_cycle_budgets(values):
    with pytest.raises(ValueError):
        RansomLookAPIClient(MagicMock(), "https://example.test/api", **values)


def test_retry_after_and_deadline_exhaustion_are_bounded():
    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_run_duration_seconds=60
    )
    transient = streaming_response([], status=503, headers={"Retry-After": "bad"})
    transient.raise_for_status.side_effect = requests.HTTPError("busy")
    client.session.get = MagicMock(return_value=transient)
    client.run_deadline = client.run_started + 0.5
    with pytest.raises(RansomLookCycleBudgetExhausted, match="retry delay"):
        client._get("posts")


def test_post_subdivision_and_collection_caps_defer_without_unbounded_growth():
    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_records=1, max_pages=1
    )
    client._get = MagicMock(side_effect=RansomLookPostWindowTooLarge("record limit"))
    batch = client.get_posts(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    assert len(batch.deferred_windows) == 2
    assert all(
        item.reason == "post subdivision budget exhausted"
        for item in batch.deferred_windows
    )

    client = RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_records=1, max_pages=1
    )
    existing = {
        "group_name": "g",
        "post_title": "one",
        "discovered": "2026-01-01T00:00:00Z",
    }
    client._get = MagicMock(return_value=[existing, {**existing, "post_title": "two"}])
    with pytest.raises(RansomLookPostWindowTooLarge):
        client._dict_list(client._get("posts"), "posts")
