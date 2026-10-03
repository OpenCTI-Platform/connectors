import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from splunk import KV_STORE_INDICATOR_FIELDS, KVStore
from splunk_test_support import DATA_URL, SEARCH_URL, SPLUNK_URL


@pytest.fixture
def kvstore():
    return KVStore(
        SPLUNK_URL, "splunk-token", "Bearer", "search", "nobody", "opencti", True
    )


def query_params(request):
    return {
        name: values[0]
        for name, values in parse_qs(urlsplit(request.url).query).items()
    }


def form_fields(request):
    return {name: values[0] for name, values in parse_qs(request.text).items()}


def test_list_indicators_paginates_by_key(kvstore, requests_mock):
    requests_mock.get(
        DATA_URL,
        [
            {"json": [{"_key": "a", "type": "indicator"}, {"_key": "b"}]},
            {"json": [{"_key": "c"}]},
        ],
    )

    items = list(kvstore.list_indicators(page_size=2))

    assert [item["_key"] for item in items] == ["a", "b", "c"]
    first, second = (query_params(request) for request in requests_mock.request_history)
    assert json.loads(first["query"]) == {"type": "indicator"}
    assert json.loads(second["query"]) == {
        "$and": [{"type": "indicator"}, {"_key": {"$gt": "b"}}]
    }
    assert first["sort"] == "_key"
    assert first["limit"] == "2"
    assert first["fields"].split(",") == list(KV_STORE_INDICATOR_FIELDS)
    assert (
        requests_mock.request_history[0].headers["Authorization"]
        == "Bearer splunk-token"
    )


def test_list_indicators_stops_on_an_empty_page(kvstore, requests_mock):
    requests_mock.get(DATA_URL, json=[])

    assert list(kvstore.list_indicators()) == []
    assert requests_mock.call_count == 1


def test_list_indicators_raises_on_http_error(kvstore, requests_mock):
    requests_mock.get(DATA_URL, status_code=503, text="KV Store is initializing")

    with pytest.raises(requests.HTTPError):
        list(kvstore.list_indicators())


def test_list_indicators_raises_on_an_unexpected_payload(kvstore, requests_mock):
    requests_mock.get(DATA_URL, json={"messages": []})

    with pytest.raises(ValueError):
        list(kvstore.list_indicators())


def test_list_indicators_raises_when_a_full_page_has_no_key(kvstore, requests_mock):
    requests_mock.get(DATA_URL, json=[{"_key": "a"}, {"type": "indicator"}])

    with pytest.raises(ValueError):
        list(kvstore.list_indicators(page_size=2))


def test_run_saved_search_runs_a_bounded_oneshot_job(kvstore, requests_mock):
    requests_mock.post(SEARCH_URL, json={"results": [{"opencti_id": "a"}]})
    earliest = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)

    results = kvstore.run_saved_search('OpenCTI "matches"', earliest, 50)

    assert results == [{"opencti_id": "a"}]
    request = requests_mock.request_history[0]
    assert form_fields(request) == {
        "search": (
            '| savedsearch "OpenCTI \\"matches\\"" | sort 0 _time opencti_id value '
            "| head 50"
        ),
        "exec_mode": "oneshot",
        "output_mode": "json",
        "earliest_time": f"{earliest.timestamp():.3f}",
        "latest_time": "now",
        "count": "50",
    }
    assert request.headers["Authorization"] == "Bearer splunk-token"
    assert "application/json" not in request.headers.get("Content-Type", "")


def test_run_saved_search_skips_the_results_already_read(kvstore, requests_mock):
    requests_mock.post(SEARCH_URL, json={"results": []})
    earliest = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)

    kvstore.run_saved_search("matches", earliest, 50, offset=100)

    assert form_fields(requests_mock.request_history[0])["search"] == (
        '| savedsearch "matches" | sort 0 _time opencti_id value '
        "| streamstats count AS opencti_row | where opencti_row > 100 "
        "| fields - opencti_row | head 50"
    )


def test_run_saved_search_raises_on_http_error(kvstore, requests_mock):
    requests_mock.post(SEARCH_URL, status_code=400, text="Unknown saved search")

    with pytest.raises(requests.HTTPError):
        kvstore.run_saved_search("missing", datetime.now(UTC), 10)


def test_run_saved_search_raises_without_results(kvstore, requests_mock):
    requests_mock.post(SEARCH_URL, json={"messages": [{"type": "FATAL"}]})

    with pytest.raises(ValueError):
        kvstore.run_saved_search("broken", datetime.now(UTC), 10)
