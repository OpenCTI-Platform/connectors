import logging

import pytest
import requests
from conftest import TS, FakeResponse, FakeTaxiiServer, stix_id
from luminar_connector.luminar_manager import (
    LuminarAPIError,
    LuminarManager,
    StaleCursorError,
    _StdLogger,
)

ANCHOR = "2026-01-01T00:00:00.000000Z"


def obj(stix_type, number, **extra):
    return {
        "type": stix_type,
        "id": stix_id(stix_type, number),
        "created": TS,
        "modified": TS,
        **extra,
    }


def pages_of(count, per_page=2):
    return [
        [obj("malware", page * 10 + i, name=f"m{page}-{i}") for i in range(per_page)]
        for page in range(count)
    ]


# ----- construction and helpers -------------------------------------------- #


def test_init_validation():
    with pytest.raises(ValueError, match="client_id"):
        LuminarManager("", "secret", "account", "https://x")
    with pytest.raises(ValueError, match="pages_per_batch"):
        LuminarManager("id", "secret", "account", "https://x", pages_per_batch=0)
    with pytest.raises(ValueError, match="limit"):
        LuminarManager("id", "secret", "account", "https://x", limit=True)
    with pytest.raises(ValueError):
        LuminarManager("id", "secret", "account", "https://x", added_after="  ")
    with pytest.raises(ValueError, match="LUMINAR_DATE_FORMAT"):
        LuminarManager("id", "secret", "account", "https://x", added_after="2026-01-01")


def test_init_normalizes_inputs_and_defaults_logger(caplog):
    manager = LuminarManager(
        " id ", " secret ", " account ", "https://x.test/ ", added_after=f" {ANCHOR} "
    )
    assert manager.base_url == "https://x.test"
    assert (manager.client_id, manager.client_secret, manager.account_id) == (
        "id",
        "secret",
        "account",
    )
    assert manager.added_after == ANCHOR
    assert manager.session.headers["User-Agent"] == "OpenCTI-Luminar-Connector"
    assert isinstance(manager.logger, _StdLogger)
    with caplog.at_level(logging.DEBUG):
        for level in ("debug", "info", "warning", "error"):
            getattr(manager.logger, level)(f"{level} message", {"k": "v"})
        manager.logger.info("no meta")
    assert "warning message {'k': 'v'}" in caplog.text and "no meta" in caplog.text


def test_set_bearer_token(make_manager, taxii_server):
    manager = make_manager(taxii_server)
    manager.set_bearer_token("abc")
    assert manager.session.headers["Authorization"] == "Bearer abc"
    with pytest.raises(ValueError):
        manager.set_bearer_token("")


def test_helpers(make_manager, taxii_server):
    manager = make_manager(taxii_server)
    assert manager._sanitize_params_for_log("raw") == "raw"
    assert (
        manager._sanitize_params_for_log({"next": "x" * 100})["next"] == "…" + "x" * 42
    )
    assert manager._sanitize_params_for_log({"next": "short"})["next"] == "short"

    assert (
        manager._format_api_error(
            FakeResponse(410, {"description": " gone ", "title": "t"})
        )
        == "HTTP 410: gone"
    )
    assert (
        manager._format_api_error(FakeResponse(400, {"title": "bad"}))
        == "HTTP 400: bad"
    )
    assert (
        manager._format_api_error(FakeResponse(503, reason="Unavailable"))
        == "HTTP 503: Unavailable"
    )
    assert (
        manager._format_api_error(FakeResponse(500, raw=b"<html>", reason=""))
        == "HTTP 500: Unknown error"
    )
    assert manager.last_api_error == "HTTP 500: Unknown error"

    assert (
        manager._subtract_one_second("2026-01-01T00:00:01.500000Z")
        == "2026-01-01T00:00:00.500000Z"
    )
    assert manager._subtract_one_second("") == ""
    assert manager._subtract_one_second("garbage") == "garbage"

    assert manager.create_lookup_dict([{"id": "a"}, {"no": "id"}]) == {"a": {"id": "a"}}
    refs = manager.extract_relationship_refs(
        [
            "not-a-dict",
            {
                "source_ref": stix_id("malware", 1),
                "target_ref": "bad-ref",
                "object_refs": [stix_id("tool", 1), 5, ""],
            },
        ]
    )
    assert refs == {stix_id("malware", 1), stix_id("tool", 1)}


# ----- retry primitives ---------------------------------------------------- #


def test_execute_with_retry(make_manager, taxii_server, network_error):
    manager = make_manager(taxii_server)

    responses = iter([FakeResponse(503), FakeResponse(200, {})])
    assert manager.execute_with_retry(lambda: next(responses)).status_code == 200

    assert manager.execute_with_retry(lambda: FakeResponse(429)).status_code == 429

    calls = iter([network_error, FakeResponse(200, {})])

    def flaky():
        item = next(calls)
        if isinstance(item, Exception):
            raise item
        return item

    assert manager.execute_with_retry(flaky).status_code == 200

    def always_fails():
        raise network_error

    with pytest.raises(requests.RequestException):
        manager.execute_with_retry(always_fails)

    later_failure = iter([FakeResponse(503), network_error, network_error])

    def response_then_errors():
        item = next(later_failure)
        if isinstance(item, Exception):
            raise item
        return item

    assert manager.execute_with_retry(response_then_errors).status_code == 503

    with pytest.raises(RuntimeError):
        manager.execute_with_retry(lambda: FakeResponse(200), retries=0)


def test_get_with_network_retry(make_manager, network_error):
    server = FakeTaxiiServer(pages=pages_of(1))
    manager = make_manager(server)
    server.scripted = {0: network_error}
    assert manager._get_with_network_retry("https://x/objects/", {}).status_code == 200

    server.scripted = {2: network_error, 3: network_error}
    with pytest.raises(requests.RequestException):
        manager._get_with_network_retry("https://x/objects/", {})

    with pytest.raises(RuntimeError):
        manager._get_with_network_retry("https://x/objects/", {}, retries=0)


# ----- authentication and collections -------------------------------------- #


@pytest.mark.parametrize(
    "response, error",
    [
        (
            FakeResponse(401, {"description": "bad credentials"}),
            "HTTP 401: bad credentials",
        ),
        (FakeResponse(200, ["list"]), "unexpected token payload type list"),
        (FakeResponse(200, {"token_type": "bearer"}), "contained no access_token"),
        (FakeResponse(200, raw=b"not json"), "Invalid response from Luminar"),
    ],
)
def test_access_token_failures(make_manager, taxii_server, response, error):
    manager = make_manager(taxii_server)
    taxii_server.token_responses = [response]
    assert manager.access_token() is None
    assert error in manager.last_api_error
    assert manager._refresh_token() is True  # next call uses the default token


def test_access_token_network_error(make_manager, taxii_server, network_error):
    manager = make_manager(taxii_server)
    taxii_server.token_responses = [network_error] * 3
    assert manager.access_token() is None
    assert manager.last_api_error.startswith("Network error")


def test_get_taxi_collections(make_manager, taxii_server):
    taxii_server.collections = [{"alias": "iocs", "id": "c1"}, "bad", {"alias": "x"}]
    manager = make_manager(taxii_server)
    taxii_server.collection_responses = [FakeResponse(401)]
    assert manager.get_taxi_collections() == {"iocs": "c1"}
    assert manager.session.headers["Authorization"] == "Bearer test-token"


@pytest.mark.parametrize(
    "responses, error",
    [
        ([FakeResponse(403, {"title": "forbidden"})], "HTTP 403: forbidden"),
        ([FakeResponse(200, ["x"])], "unexpected collections payload type list"),
        (
            [FakeResponse(200, {"collections": {"a": 1}})],
            "unexpected 'collections' type dict",
        ),
        ([FakeResponse(200, raw=b"{")], "Invalid response from Luminar"),
        ([requests.ConnectionError("down")] * 3, "Network error"),
    ],
)
def test_get_taxi_collections_failures(make_manager, taxii_server, responses, error):
    manager = make_manager(taxii_server)
    taxii_server.collection_responses = list(responses)
    assert manager.get_taxi_collections() == {}
    assert error in manager.last_api_error


# ----- match[id] hydration -------------------------------------------------- #


def test_get_objects_by_match_id(make_manager):
    store = {
        o["id"]: o
        for o in (
            obj("malware", 1, name="a"),
            obj("malware", 2, name="b"),
            obj("malware", 3, name="c"),
        )
    }
    server = FakeTaxiiServer(store=store)
    manager = make_manager(server)

    assert manager.get_objects_by_match_id("c", []) == []
    found = manager.get_objects_by_match_id("c", list(store), batch_size=2)
    assert {o["id"] for o in found} == set(store)
    assert len(server.match_calls) == 2

    server.match_responses = [FakeResponse(401)]
    assert len(manager.get_objects_by_match_id("c", [stix_id("malware", 1)])) == 1
    assert manager.last_hydration_failed is False


@pytest.mark.parametrize(
    "responses",
    [
        [FakeResponse(404)],
        [FakeResponse(200, ["not-a-dict"])],
        [FakeResponse(200, raw=b"not json")],
        [requests.ConnectionError("down")] * 3,
    ],
)
def test_get_objects_by_match_id_failures_are_flagged(make_manager, responses):
    server = FakeTaxiiServer(store={stix_id("malware", 1): obj("malware", 1, name="a")})
    manager = make_manager(server)
    server.match_responses = list(responses)
    assert manager.get_objects_by_match_id("c", [stix_id("malware", 1)]) == []
    assert manager.last_hydration_failed is True


# ----- single page fetch ---------------------------------------------------- #


def test_fetch_page_success_and_validation(make_manager):
    server = FakeTaxiiServer(pages=pages_of(2))
    manager = make_manager(server)
    objs, next_token, last, first = manager.fetch_page(
        "c", {"limit": 5, "added_after": ANCHOR}
    )
    assert len(objs) == 2 and next_token == "1"
    assert (first, last) == (
        "2026-01-01T00:00:00.000000Z",
        "2026-01-01T00:00:00.500000Z",
    )
    with pytest.raises(ValueError):
        manager.fetch_page("", {})
    with pytest.raises(ValueError):
        manager.fetch_page("c", "params")


def test_fetch_page_unexpected_payloads(make_manager):
    server = FakeTaxiiServer()
    manager = make_manager(server)
    server.scripted = {
        0: FakeResponse(200, {"objects": "bad", "next": 7}),
        1: FakeResponse(200, ["x"]),
        2: FakeResponse(200, raw=b"{"),
    }
    objs, next_token, _, _ = manager.fetch_page("c", {"added_after": ANCHOR})
    assert objs == [] and next_token == "7"
    with pytest.raises(LuminarAPIError, match="unexpected page payload type list"):
        manager.fetch_page("c", {"added_after": ANCHOR})
    with pytest.raises(LuminarAPIError, match="Invalid response"):
        manager.fetch_page("c", {"added_after": ANCHOR})


def test_fetch_page_http_and_network_errors(make_manager, network_error):
    server = FakeTaxiiServer(pages=pages_of(1))
    manager = make_manager(server)
    server.scripted = {
        0: FakeResponse(401),
        2: FakeResponse(404, {"title": "nope"}),
        3: network_error,
        4: network_error,
        5: network_error,
    }
    assert (
        len(manager.fetch_page("c", {"added_after": ANCHOR})[0]) == 2
    )  # 401 -> refresh -> retry
    with pytest.raises(LuminarAPIError, match="HTTP 404: nope"):
        manager.fetch_page("c", {"added_after": ANCHOR})
    with pytest.raises(LuminarAPIError, match="Network error"):
        manager.fetch_page("c", {"added_after": ANCHOR})


def test_fetch_page_with_cursor(make_manager, network_error):
    server = FakeTaxiiServer(pages=pages_of(2))
    manager = make_manager(server)
    cursored = {"added_after": ANCHOR, "next": "1"}

    server.scripted = {0: FakeResponse(410, {"title": "Expired pagination token"})}
    with pytest.raises(StaleCursorError, match="Expired"):
        manager.fetch_page("c", cursored)

    server.scripted = {1: FakeResponse(401), 2: FakeResponse(410)}
    with pytest.raises(StaleCursorError, match="after token refresh"):
        manager.fetch_page("c", cursored)

    server.scripted = {3: FakeResponse(401)}
    assert len(manager.fetch_page("c", cursored)[0]) == 2

    server.scripted = {5: FakeResponse(500)}
    assert (
        len(manager.fetch_page("c", cursored)[0]) == 2
    )  # retried via execute_with_retry

    server.scripted = {7: network_error, 8: network_error}
    with pytest.raises(LuminarAPIError, match="Network error"):
        manager.fetch_page("c", cursored)


# ----- page batching -------------------------------------------------------- #


def test_iter_page_batches_batches_and_trailing_partial(make_manager):
    server = FakeTaxiiServer(pages=pages_of(5))
    manager = make_manager(server, pages_per_batch=2)
    batches = list(manager.iter_page_batches("c", ANCHOR))
    assert [len(b) for b, _ in batches] == [4, 4, 2]
    assert [cp for _, cp in batches] == [
        "2026-01-01T00:00:01.500000Z",
        "2026-01-01T00:00:03.500000Z",
        "2026-01-01T00:00:04.500000Z",
    ]
    with pytest.raises(ValueError):
        list(manager.iter_page_batches("c", ""))


def test_iter_page_batches_recovers_from_stale_cursor(make_manager):
    server = FakeTaxiiServer(pages=pages_of(3))
    manager = make_manager(server, pages_per_batch=10)
    server.scripted = {1: FakeResponse(410)}
    ((batch, checkpoint),) = list(manager.iter_page_batches("c", ANCHOR))
    rebuild = server.object_calls[2]
    assert (
        "next" not in rebuild
        and rebuild["added_after"] == "2025-12-31T23:59:59.500000Z"
    )
    assert checkpoint == "2026-01-01T00:00:02.500000Z"
    assert len(batch) == 8  # page 0 re-read after the rebuild; deduplicated downstream


def test_iter_page_batches_stale_before_any_checkpoint(make_manager):
    server = FakeTaxiiServer(pages=pages_of(2))
    manager = make_manager(server, pages_per_batch=10)
    server.scripted = {
        0: FakeResponse(200, {"objects": [], "next": "1"}),
        1: FakeResponse(410),
    }
    list(manager.iter_page_batches("c", ANCHOR))
    assert server.object_calls[2]["added_after"] == ANCHOR


def test_iter_page_batches_aborts_when_stale_recovery_stalls(make_manager):
    server = FakeTaxiiServer(pages=pages_of(2))
    manager = make_manager(server, pages_per_batch=10)
    server.scripted = {call: FakeResponse(410) for call in range(1, 30, 2)}
    iterator = manager.iter_page_batches("c", ANCHOR)
    batch, _ = next(iterator)  # partial batch handed back before the abort
    assert batch
    with pytest.raises(LuminarAPIError, match="no progress"):
        next(iterator)


def test_iter_page_batches_yields_partial_batch_on_api_error(make_manager):
    server = FakeTaxiiServer(pages=pages_of(3))
    manager = make_manager(server, pages_per_batch=10)
    server.scripted = {1: FakeResponse(404)}
    iterator = manager.iter_page_batches("c", ANCHOR)
    batch, checkpoint = next(iterator)
    assert len(batch) == 2 and checkpoint == "2026-01-01T00:00:00.500000Z"
    with pytest.raises(LuminarAPIError):
        next(iterator)


def test_iter_page_batches_falls_back_to_first_added_header(make_manager):
    server = FakeTaxiiServer()
    manager = make_manager(server)
    server.scripted = {
        0: FakeResponse(
            200,
            {"objects": [obj("malware", 1, name="x")]},
            {"X-TAXII-Date-Added-First": "2026-02-02T00:00:00.000000Z"},
        )
    }
    ((_, checkpoint),) = list(manager.iter_page_batches("c", ANCHOR))
    assert checkpoint == "2026-02-02T00:00:00.000000Z"


# ----- reference hydration -------------------------------------------------- #


def test_resolve_and_augment_batch_two_levels(make_manager):
    identity = obj("identity", 1, name="Luminar")
    target = obj("malware", 2, name="far", created_by_ref=identity["id"])
    in_prev, in_next = obj("malware", 3, name="prev"), obj("malware", 4, name="next")
    rel = obj(
        "relationship",
        1,
        relationship_type="related-to",
        source_ref=in_prev["id"],
        target_ref=target["id"],
    )
    rel2 = obj(
        "relationship",
        2,
        relationship_type="related-to",
        source_ref=in_next["id"],
        target_ref=target["id"],
    )
    server = FakeTaxiiServer(store={o["id"]: o for o in (identity, target)})
    manager = make_manager(server)

    augmented = manager.resolve_and_augment_batch(
        "c", [rel, rel2], [in_prev], [in_next]
    )

    ids = {o["id"] for o in augmented}
    assert {target["id"], identity["id"], in_prev["id"], in_next["id"]} <= ids
    assert manager.last_hydration_failed is False
    assert target["id"] in manager.hydrated_objects

    server.match_calls.clear()
    again = manager.resolve_and_augment_batch("c", [rel], None, None)
    assert target["id"] in {o["id"] for o in again}
    assert all(
        target["id"] not in call for call in server.match_calls
    )  # served from cache


def test_resolve_and_augment_batch_cache_eviction_and_failure(
    make_manager, monkeypatch
):
    targets = [obj("malware", n, name=f"m{n}") for n in (1, 2)]
    rels = [
        obj(
            "relationship",
            n,
            relationship_type="related-to",
            source_ref=t["id"],
            target_ref=t["id"],
        )
        for n, t in enumerate(targets, 1)
    ]
    manager = make_manager(FakeTaxiiServer(store={t["id"]: t for t in targets}))
    manager.hydrated_objects_max_size = 1
    manager.resolve_and_augment_batch("c", rels, None, None)
    assert len(manager.hydrated_objects) == 1

    def boom(*_args, **_kwargs):
        raise RuntimeError("down")

    monkeypatch.setattr(manager, "get_objects_by_match_id", boom)
    manager.hydrated_objects.clear()
    augmented = manager.resolve_and_augment_batch("c", rels[:1], None, None)
    assert augmented == rels[:1]
    assert manager.last_hydration_failed is True


# ----- client-facing generator ---------------------------------------------- #


def test_get_objects_validation(make_manager, taxii_server):
    manager = make_manager(taxii_server)
    with pytest.raises(ValueError):
        next(manager.get_objects(" "))
    with pytest.raises(ValueError, match="Unknown feed_name"):
        next(manager.get_objects("unknown"))
    with pytest.raises(ValueError, match="LUMINAR_DATE_FORMAT"):
        next(manager.get_objects("iocs", added_after="2026-01-01"))
    manager.added_after = None
    with pytest.raises(ValueError, match="added_after is required"):
        next(manager.get_objects("iocs"))


def test_get_objects_authentication_and_discovery_failures(make_manager):
    server = FakeTaxiiServer()
    server.token_responses = [FakeResponse(401, {"description": "denied"})]
    with pytest.raises(LuminarAPIError, match="denied"):
        next(make_manager(server).get_objects("iocs"))

    empty = FakeTaxiiServer(collections=[])
    with pytest.raises(LuminarAPIError, match="No TAXII collections"):
        next(make_manager(empty).get_objects("iocs"))


def test_get_objects_small_dataset(make_manager):
    server = FakeTaxiiServer(pages=pages_of(2))
    manager = make_manager(server, pages_per_batch=1)
    (result,) = list(manager.get_objects("iocs"))
    assert len(result["results"]["data"]) == 4
    assert result["results"]["last_success"] == "2026-01-01T00:00:01.500000Z"
    assert result["results"]["hydration_complete"] is True and result["error"] is None


def test_get_objects_sliding_window_delivers_every_object_once(make_manager):
    pages = pages_of(6, per_page=1)
    far_back = pages[0][0]
    pages[5].append(
        obj(
            "relationship",
            1,
            relationship_type="related-to",
            source_ref=pages[5][0]["id"],
            target_ref=far_back["id"],
        )
    )
    server = FakeTaxiiServer(pages=pages)
    manager = make_manager(server, pages_per_batch=1)

    results = list(manager.get_objects("iocs", added_after=ANCHOR))

    assert [r["results"]["last_success"] for r in results] == [
        f"2026-01-01T00:00:0{i}.500000Z" for i in range(6)
    ]
    delivered = [o["id"] for r in results[:-1] for o in r["results"]["data"]]
    assert sorted(delivered) == sorted(p[0]["id"] for p in pages[:5])  # once each
    assert far_back["id"] in {
        o["id"] for o in results[-1]["results"]["data"]
    }  # hydrated
    assert all(r["error"] is None for r in results)


def test_get_objects_preload_failures(make_manager):
    server = FakeTaxiiServer(pages=pages_of(3, per_page=1))
    server.scripted = {1: FakeResponse(404, {"title": "gone"})}
    (result,) = list(make_manager(server, pages_per_batch=1).get_objects("iocs"))
    assert len(result["results"]["data"]) == 1 and result["error"] == "HTTP 404: gone"

    failing = FakeTaxiiServer(pages=pages_of(3))
    failing.scripted = {0: FakeResponse(404, {"title": "gone"})}
    (result,) = list(make_manager(failing).get_objects("iocs"))
    assert result["results"]["data"] == [] and result["error"] == "HTTP 404: gone"
    assert result["results"]["last_success"] is None


def test_iter_collection_batches_invalid_anchor(make_manager, taxii_server):
    (result,) = list(make_manager(taxii_server).iter_collection_batches("c", ""))
    assert result["error"].startswith("ValueError")


def test_get_objects_flushes_center_batch_on_steady_state_error(make_manager):
    server = FakeTaxiiServer(pages=pages_of(6, per_page=1))
    server.scripted = {4: FakeResponse(404, {"title": "gone"})}
    results = list(make_manager(server, pages_per_batch=1).get_objects("iocs"))
    assert [r["error"] for r in results] == [None, None, None, "HTTP 404: gone"]
    assert results[-1]["results"]["last_success"] == "2026-01-01T00:00:03.500000Z"


def test_get_objects_reports_error_when_tail_resolution_fails(
    make_manager, monkeypatch
):
    server = FakeTaxiiServer(pages=pages_of(6, per_page=1))
    server.scripted = {4: FakeResponse(404, {"title": "gone"})}
    manager = make_manager(server, pages_per_batch=1)
    original = manager.resolve_and_augment_batch
    calls = {"n": 0}

    def flaky_resolve(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 4:
            raise RuntimeError("resolve failed")
        return original(*args, **kwargs)

    monkeypatch.setattr(manager, "resolve_and_augment_batch", flaky_resolve)
    results = list(manager.get_objects("iocs"))
    assert (
        results[-1]["results"]["data"] == []
        and results[-1]["error"] == "HTTP 404: gone"
    )
