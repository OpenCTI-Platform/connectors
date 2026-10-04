from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import requests
from conftest import ES_URL, esql_answer, hits_answer
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
)
from elastic_security_hunt.client import ElasticsearchClient, index_path

START = datetime(2026, 10, 3, tzinfo=timezone.utc)
END = datetime(2026, 10, 4, tzinfo=timezone.utc)
ESQL_URL = f"{ES_URL}/_query/async"
EQL_URL = f"{ES_URL}/logs-*/_eql/search"
SEARCH_URL = f"{ES_URL}/logs-*/_search"
TIME_RANGE = {
    "range": {
        "@timestamp": {
            "gte": "2026-10-03T00:00:00.000Z",
            "lte": "2026-10-04T00:00:00.000Z",
            "format": "strict_date_optional_time",
        }
    }
}


def _client(**overrides) -> ElasticsearchClient:
    values = {
        "base_url": ES_URL,
        "api_key": "a2V5OnNlY3JldA==",
        "username": None,
        "password": None,
        "verify_ssl": True,
        "ca_cert": None,
        "timestamp_field": "@timestamp",
        "logger": MagicMock(),
    }
    values.update(overrides)
    return ElasticsearchClient(**values)


def test_api_key_authentication(requests_mock):
    # Given a client with an API key
    requests_mock.post(SEARCH_URL, json=hits_answer([]))

    # When it searches
    _client().lucene(["logs-*"], "x", START, END, 10, RunDeadline(30))

    # Then the API key is sent
    request = requests_mock.last_request
    assert request.headers["Authorization"] == "ApiKey a2V5OnNlY3JldA=="
    assert request.verify is True


def test_basic_authentication_and_ca_bundle(requests_mock):
    # Given a client with a user, a password and a CA bundle
    requests_mock.post(SEARCH_URL, json=hits_answer([]))
    client = _client(
        api_key=None, username="hunter", password="pw", ca_cert="/certs/ca.pem"
    )

    # When it searches
    client.lucene(["logs-*"], "x", START, END, 10, RunDeadline(30))

    # Then basic authentication and the CA bundle are used
    request = requests_mock.last_request
    assert request.headers["Authorization"] == "Basic aHVudGVyOnB3"
    assert request.verify == "/certs/ca.pem"


def test_index_path_keeps_patterns_and_remote_clusters():
    # Given/When/Then index patterns and remote clusters stay readable
    assert index_path(["logs-*", "remote:logs-endpoint.*"]) == (
        "logs-*,remote:logs-endpoint.*"
    )
    assert index_path(["a b"]) == "a%20b"


def test_esql_completes_in_the_first_request(requests_mock):
    # Given an ES|QL query completing immediately
    requests_mock.post(
        ESQL_URL, json=esql_answer(["host.name", "@timestamp"], [["ws1", "t"]])
    )

    # When it runs
    result = _client().esql("from logs-*", START, END, 10, RunDeadline(120), "k")

    # Then it is capped, restricted to the window and not polled
    body = requests_mock.last_request.json()
    assert body["query"] == "from logs-*\n| limit 10"
    assert body["filter"] == TIME_RANGE
    assert body["keep_alive"] == "10m"
    assert body["wait_for_completion_timeout"] == "30s"
    assert result.rows == [{"host.name": "ws1", "@timestamp": "t"}]
    assert (result.total, result.partial) == (1, False)
    assert requests_mock.call_count == 1


def test_esql_is_polled_then_deleted(requests_mock):
    # Given an ES|QL query still running after the first request
    requests_mock.post(ESQL_URL, json={"id": "q/1", "is_running": True})
    requests_mock.get(
        f"{ESQL_URL}/q%2F1",
        [
            {"json": {"id": "q/1", "is_running": True}},
            {"json": {**esql_answer(["a"], [[1]]), "is_partial": True}},
        ],
    )
    delete = requests_mock.delete(f"{ESQL_URL}/q%2F1", json={"acknowledged": True})

    # When it runs
    result = _client().esql("from x", START, END, 10, RunDeadline(120), "k")

    # Then it is long-polled until done, then deleted
    assert result.rows == [{"a": 1}]
    assert result.partial is True
    assert delete.call_count == 1
    assert requests_mock.request_history[1].qs["wait_for_completion_timeout"] == ["30s"]


def test_esql_counts_when_the_cap_is_reached(requests_mock):
    # Given more matches than the cap
    requests_mock.post(
        ESQL_URL,
        [
            {"json": esql_answer(["a"], [[1], [2]])},
            {"json": esql_answer(["opencti_hit_count"], [[57]])},
        ],
    )

    # When it runs with a cap of two rows
    result = _client().esql("from x", START, END, 2, RunDeadline(30), "k")

    # Then the total comes from the count query
    queries = [request.json()["query"] for request in requests_mock.request_history]
    assert queries == [
        "from x\n| limit 2",
        "from x\n| stats opencti_hit_count = count(*)",
    ]
    assert (result.total, result.partial) == (57, False)


def test_esql_propagates_a_partial_count(requests_mock):
    # Given a full page whose count query is flagged partial by Elasticsearch
    requests_mock.post(
        ESQL_URL,
        [
            {"json": esql_answer(["a"], [[1]])},
            {"json": {**esql_answer(["opencti_hit_count"], [[1]]), "is_partial": True}},
        ],
    )

    # When/Then the partial count makes the result partial
    result = _client().esql("from x", START, END, 1, RunDeadline(30), "k")
    assert (result.total, result.partial) == (1, True)


@pytest.mark.parametrize(
    "count_answer",
    [
        pytest.param(esql_answer(["opencti_hit_count"], []), id="no_rows"),
        pytest.param(esql_answer(["opencti_hit_count"], [["x"]]), id="not_a_number"),
        pytest.param(esql_answer(["opencti_hit_count"], [[True]]), id="boolean"),
        pytest.param(esql_answer(["opencti_hit_count"], [[0]]), id="below_the_page"),
    ],
)
def test_esql_keeps_the_rows_when_the_count_is_unusable(requests_mock, count_answer):
    # Given a count query without a usable answer
    requests_mock.post(
        ESQL_URL, [{"json": esql_answer(["a"], [[1]])}, {"json": count_answer}]
    )

    # When/Then the total is the number of rows, a lower bound of a partial result
    result = _client().esql("from x", START, END, 1, RunDeadline(30), "k")
    assert (result.total, result.partial) == (1, True)


def test_esql_caps_at_the_result_window(requests_mock):
    # Given a run allowing more results than Elasticsearch returns
    requests_mock.post(ESQL_URL, json=esql_answer(["a"], []))

    # When/Then the limit is the result window
    _client().esql("from x", START, END, 50000, RunDeadline(30), "k")
    assert requests_mock.last_request.json()["query"].endswith("| limit 10000")


def test_esql_rejects_unexpected_answers(requests_mock):
    # Given an answer that is not a JSON object
    requests_mock.post(ESQL_URL, json=[1, 2])

    # When/Then the query fails
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        _client().esql("from x", START, END, 1, RunDeadline(30), "k")


def test_esql_reports_the_elasticsearch_error(requests_mock):
    # Given an invalid ES|QL query
    requests_mock.post(
        ESQL_URL,
        status_code=400,
        json={
            "error": {
                "root_cause": [{"reason": "Unknown column [foo]"}],
                "type": "verification_exception",
            }
        },
    )

    # When/Then the error carries the reason
    with pytest.raises(HuntExecutionError, match="Unknown column"):
        _client().esql("from x | where foo", START, END, 1, RunDeadline(30), "k")


def test_eql_reads_events_and_sequences(requests_mock):
    # Given an EQL answer with events and sequences
    requests_mock.post(
        EQL_URL,
        json={
            "is_running": False,
            "hits": {
                "total": {"value": 3, "relation": "eq"},
                "events": [{"_source": {"process": {"name": "a"}}}],
                "sequences": [
                    {"events": [{"_source": {"b": 1}}, {"_index": "x"}]},
                ],
            },
        },
    )

    # When the query runs
    result = _client().eql(
        ["logs-*"], "any where true", START, END, 5, RunDeadline(30), "k"
    )

    # Then the request is restricted to the window and the events are read
    request = requests_mock.last_request
    body = request.json()
    assert body["size"] == 5
    assert body["filter"] == TIME_RANGE
    assert body["timestamp_field"] == "@timestamp"
    assert request.qs["ignore_unavailable"] == ["true"]
    assert result.rows == [{"process": {"name": "a"}}, {"b": 1}, {}]
    assert (result.total, result.partial) == (3, False)


def test_eql_counts_sequence_events_and_flags_the_ones_cut(requests_mock):
    # Given two sequences of three events each, more events than the cap
    sequence = {"events": [{"_source": {"step": step}} for step in range(3)]}
    requests_mock.post(
        EQL_URL,
        json={
            "hits": {
                "total": {"value": 2, "relation": "eq"},
                "sequences": [sequence, sequence],
            }
        },
    )

    # When the query runs with a cap of four events
    result = _client().eql(["logs-*"], "q", START, END, 4, RunDeadline(30), "k")

    # Then every fetched event counts and the cut ones make the result partial
    assert len(result.rows) == 4
    assert (result.total, result.partial) == (6, True)


def test_eql_flags_lower_bound_totals(requests_mock):
    # Given an EQL total that is a lower bound
    requests_mock.post(
        EQL_URL,
        json={
            "hits": {
                "total": {"value": 10000, "relation": "gte"},
                "events": [{"_source": {"a": 1}}],
            }
        },
    )

    # When/Then the result is partial
    result = _client().eql(["logs-*"], "q", START, END, 5, RunDeadline(30), "k")
    assert (result.total, result.partial) == (10000, True)


def test_eql_without_a_total(requests_mock):
    # Given an EQL answer without a total
    requests_mock.post(EQL_URL, json={"hits": {"events": [{"_source": {"a": 1}}]}})

    # When/Then the total is the number of events
    result = _client().eql(["logs-*"], "q", START, END, 5, RunDeadline(30), "k")
    assert result.total == 1


def test_lucene_search_body(requests_mock):
    # Given matching documents
    requests_mock.post(SEARCH_URL, json=hits_answer([{"a": 1}], total=12))

    # When the Lucene query runs
    result = _client().lucene(["logs-*"], "a:1", START, END, 1, RunDeadline(30))

    # Then the query string is filtered by time, sorted and counted
    body = requests_mock.last_request.json()
    assert body["query"]["bool"]["must"] == [{"query_string": {"query": "a:1"}}]
    assert body["query"]["bool"]["filter"] == [TIME_RANGE]
    assert body["size"] == 1
    assert body["track_total_hits"] is True
    assert body["sort"] == [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
    assert (result.rows, result.total, result.partial) == ([{"a": 1}], 12, False)


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param({**hits_answer([]), "timed_out": True}, id="timed_out"),
        pytest.param(
            {**hits_answer([]), "_shards": {"total": 2, "failed": 1}},
            id="shard_failure",
        ),
    ],
)
def test_lucene_flags_partial_results(requests_mock, answer):
    # Given a search that timed out or lost shards
    requests_mock.post(SEARCH_URL, json=answer)

    # When/Then the result is partial
    assert _client().lucene(["logs-*"], "x", START, END, 1, RunDeadline(30)).partial


def test_lucene_rejects_unexpected_answers(requests_mock):
    # Given an answer that is not a JSON object
    requests_mock.post(SEARCH_URL, text="oops", headers={"Content-Type": "text/plain"})

    # When/Then the search fails
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        _client().lucene(["logs-*"], "x", START, END, 1, RunDeadline(30))


def test_lucene_timeout_maps_to_hunt_timeout(requests_mock):
    # Given a cluster that does not answer in time
    requests_mock.post(SEARCH_URL, exc=requests.exceptions.ReadTimeout)

    # When/Then the run times out
    with pytest.raises(HuntTimeoutError):
        _client().lucene(["logs-*"], "x", START, END, 1, RunDeadline(30))


def test_no_request_once_the_deadline_has_expired(requests_mock):
    # Given an expired deadline
    # When/Then no search is submitted
    with pytest.raises(HuntTimeoutError):
        _client().esql("from x", START, END, 1, RunDeadline(0), "k")
    assert requests_mock.call_count == 0


def test_polling_stops_at_the_deadline_and_deletes_the_search(requests_mock):
    # Given a search that never completes and a clock passing the deadline
    now = [0.0]
    deadline = RunDeadline(30, clock=lambda: now[0])

    def _still_running(request, context):
        now[0] += 20
        return {"id": "q1", "is_running": True}

    requests_mock.post(ESQL_URL, json=_still_running)
    requests_mock.get(f"{ESQL_URL}/q1", json=_still_running)
    delete = requests_mock.delete(f"{ESQL_URL}/q1", json={})

    # When/Then the run times out and the search is deleted
    with pytest.raises(HuntTimeoutError):
        _client().esql("from x", START, END, 1, deadline, "k")
    assert delete.call_count == 1


def test_cancel_deletes_the_running_search_once(requests_mock):
    # Given a search registered as running for a run
    client = _client()
    delete = requests_mock.delete(f"{ESQL_URL}/q1", json={})
    calls = []

    def _poll(request, context):
        if not calls:
            calls.append(1)
            client.cancel("k")
        return esql_answer(["a"], [])

    requests_mock.post(ESQL_URL, json={"id": "q1", "is_running": True})
    requests_mock.get(f"{ESQL_URL}/q1", json=_poll)

    # When the run is cancelled while polling
    client.esql("from x", START, END, 1, RunDeadline(30), "k")

    # Then the search is deleted by the cancellation only
    assert delete.call_count == 1
    client.cancel("k")
    assert delete.call_count == 1


def test_failed_deletion_is_logged(requests_mock):
    # Given a cluster refusing the deletion
    logger = MagicMock()
    requests_mock.post(ESQL_URL, json={"id": "q1", "is_running": True})
    requests_mock.get(f"{ESQL_URL}/q1", json=esql_answer(["a"], []))
    requests_mock.delete(f"{ESQL_URL}/q1", status_code=403, json={})

    # When the query completes
    _client(logger=logger).esql("from x", START, END, 1, RunDeadline(30), "k")

    # Then the cleanup failure is logged as a warning
    message, details = logger.warning.call_args.args
    assert "The async search deletion failed" in message
    assert details == {"search": "/_query/async/q1"}
