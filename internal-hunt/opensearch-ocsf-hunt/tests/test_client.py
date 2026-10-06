import base64
from datetime import datetime, timedelta, timezone

import pytest
import requests
from conftest import OS_URL, PPL_URL, SEARCH_URL, count_answer, hits_answer, ppl_answer
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
)
from opensearch_ocsf_hunt.client import (
    OpenSearchClient,
    epoch_ms,
    index_path,
    iso_time,
    ppl_rows,
    with_where,
)

START = datetime(2026, 10, 3, tzinfo=timezone.utc)
END = datetime(2026, 10, 4, tzinfo=timezone.utc)
START_MS = 1790985600000
END_MS = 1791072000000


def _client(
    username="hunter",
    password="secret",
    verify_ssl=True,
    ca_cert=None,
    timestamp_format="epoch_millis",
) -> OpenSearchClient:
    return OpenSearchClient(
        base_url=OS_URL,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        ca_cert=ca_cert,
        timestamp_field="time",
        timestamp_format=timestamp_format,
    )


def test_time_helpers():
    # Given/When/Then times are sent as epoch milliseconds or ISO 8601 UTC
    assert (epoch_ms(START), epoch_ms(END)) == (START_MS, END_MS)
    paris = timezone(timedelta(hours=2))
    assert iso_time(datetime(2026, 10, 3, 2, 0, 0, 5000, paris)) == (
        "2026-10-03T00:00:00.005Z"
    )


def test_basic_authentication_header(requests_mock):
    # Given a client with credentials
    requests_mock.post(PPL_URL, json=ppl_answer([], []))

    # When a query is sent
    _client().ppl("source=ocsf-*", START, END, 10, RunDeadline(30))

    # Then it carries the basic authentication header
    expected = base64.b64encode(b"hunter:secret").decode()
    assert requests_mock.last_request.headers["Authorization"] == f"Basic {expected}"


def test_no_authentication_without_credentials():
    # Given/When/Then a client without credentials sends no authorization header
    assert _client(username=None, password=None).session_headers == {}


@pytest.mark.parametrize(
    "verify_ssl, ca_cert, expected",
    [
        pytest.param(True, "/certs/ca.pem", "/certs/ca.pem", id="ca_bundle"),
        pytest.param(True, None, True, id="verify"),
        pytest.param(False, "/certs/ca.pem", False, id="no_verify"),
    ],
)
def test_certificate_verification(requests_mock, verify_ssl, ca_cert, expected):
    # Given a client with a verification setting
    requests_mock.post(PPL_URL, json=ppl_answer([], []))

    # When a query is sent
    _client(verify_ssl=verify_ssl, ca_cert=ca_cert).ppl(
        "source=x", START, END, 10, RunDeadline(30)
    )

    # Then the certificate is verified as configured
    assert requests_mock.last_request.verify == expected


def test_ppl_restricts_caps_and_counts(requests_mock):
    # Given a PPL answer filling the cap, and its count
    requests_mock.post(
        PPL_URL,
        [
            {"json": ppl_answer(["time", "device.hostname"], [[START_MS, "ws1"]])},
            {"json": count_answer(42)},
        ],
    )

    # When a query with a pipeline runs
    result = _client().ppl(
        "source=ocsf-* | where class_uid=1007 | fields time;",
        START,
        END,
        1,
        RunDeadline(30),
    )

    # Then the window is inserted after the source, the rows capped and counted
    queries = [request.json()["query"] for request in requests_mock.request_history]
    window = f"`time` >= {START_MS} and `time` <= {END_MS}"
    base = f"source=ocsf-* | where {window} | where class_uid=1007 | fields time"
    assert queries == [
        f"{base} | head 1",
        f"{base} | stats count() as opencti_hit_count",
    ]
    assert result.rows == [{"time": START_MS, "device.hostname": "ws1"}]
    assert (result.total, result.partial) == (42, False)


def test_ppl_does_not_count_a_page_below_the_cap(requests_mock):
    # Given fewer rows than the cap: they are all the matches
    requests_mock.post(PPL_URL, json=ppl_answer(["a"], [[1], [2]]))

    # When the query runs
    result = _client().ppl("source=x", START, END, 50, RunDeadline(30))

    # Then no count query is sent and the total is the number of rows
    assert requests_mock.call_count == 1
    assert result.total == 2


def test_ppl_date_window_and_platform_cap(requests_mock):
    # Given a date timestamp field
    requests_mock.post(PPL_URL, json=ppl_answer([], []))

    # When a query runs with a cap above the OpenSearch result window
    result = _client(timestamp_format="date").ppl(
        "source=ocsf-*", START, END, 50000, RunDeadline(30)
    )

    # Then the window uses timestamps, the cap is bounded and nothing is counted
    assert requests_mock.call_count == 1
    assert requests_mock.last_request.json()["query"] == (
        "source=ocsf-* | where `time` >= timestamp('2026-10-03 00:00:00') "
        "and `time` <= timestamp('2026-10-04 00:00:00') | head 10000"
    )
    assert (result.rows, result.total) == ([], 0)


@pytest.mark.parametrize(
    "count",
    [
        pytest.param(ppl_answer(["opencti_hit_count"], []), id="no_row"),
        pytest.param(ppl_answer(["opencti_hit_count"], [["many"]]), id="not_a_number"),
        pytest.param(ppl_answer(["opencti_hit_count"], [[True]]), id="boolean"),
        pytest.param(count_answer(0), id="lower"),
    ],
)
def test_ppl_keeps_the_row_count_without_a_usable_count(requests_mock, count):
    # Given a full page and an unusable or lower count
    requests_mock.post(
        PPL_URL, [{"json": ppl_answer(["a"], [[1], [2]])}, {"json": count}]
    )

    # When/Then the total is the number of rows, a lower bound of a partial result
    result = _client().ppl("source=x", START, END, 2, RunDeadline(30))
    assert (result.total, result.partial) == (2, True)


def test_ppl_reports_a_count_equal_to_the_page_as_complete(requests_mock):
    # Given a full page whose count confirms there is nothing more
    requests_mock.post(
        PPL_URL, [{"json": ppl_answer(["a"], [[1], [2]])}, {"json": count_answer(2)}]
    )

    # When/Then the result is complete
    result = _client().ppl("source=x", START, END, 2, RunDeadline(30))
    assert (result.total, result.partial) == (2, False)


def test_ppl_reports_the_error_details(requests_mock):
    # Given a PPL query on an unknown field
    requests_mock.post(
        PPL_URL,
        status_code=400,
        json={
            "error": {
                "reason": "Invalid Query",
                "details": "can't resolve Symbol(namespace=FIELD_NAME, name=bad)",
                "type": "SemanticCheckException",
            },
            "status": 400,
        },
    )

    # When/Then the reason and the details are reported
    with pytest.raises(HuntExecutionError) as err:
        _client().ppl("source=x | where bad=1", START, END, 10, RunDeadline(30))
    assert str(err.value) == (
        "The PPL query failed (HTTP 400 on POST /_plugins/_ppl): Invalid Query"
        " - can't resolve Symbol(namespace=FIELD_NAME, name=bad)"
    )


@pytest.mark.parametrize(
    "response",
    [
        pytest.param({"exc": requests.exceptions.ConnectionError}, id="network"),
        pytest.param({"status_code": 401, "text": "Unauthorized"}, id="text_body"),
        pytest.param(
            {"status_code": 403, "json": {"error": "no permissions"}}, id="error_text"
        ),
        pytest.param(
            {"status_code": 400, "json": {"error": {"reason": "bad"}}}, id="no_details"
        ),
    ],
)
def test_ppl_keeps_generic_errors(requests_mock, response):
    # Given a failure without PPL error details
    requests_mock.post(PPL_URL, **response)

    # When/Then the generic hunt error is raised (access denied for a refused account)
    with pytest.raises(HuntExecutionError, match="The PPL query (failed|was refused)"):
        _client().ppl("source=x", START, END, 10, RunDeadline(30))


def test_ppl_rejects_unexpected_answers(requests_mock):
    # Given an answer that is not an object
    requests_mock.post(PPL_URL, json=[1, 2])

    # When/Then the answer is rejected
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        _client().ppl("source=x", START, END, 10, RunDeadline(30))


def test_ppl_times_out(requests_mock):
    # Given a cluster that does not answer in time
    requests_mock.post(PPL_URL, exc=requests.exceptions.ReadTimeout)

    # When/Then the run times out
    with pytest.raises(HuntTimeoutError):
        _client().ppl("source=x", START, END, 10, RunDeadline(30))


def test_ppl_never_starts_without_time_left(requests_mock):
    # Given/When/Then an expired deadline sends no query
    with pytest.raises(HuntTimeoutError):
        _client().ppl("source=x", START, END, 10, RunDeadline(0))
    assert requests_mock.call_count == 0


def test_lucene_search_body(requests_mock):
    # Given matching documents
    requests_mock.post(
        SEARCH_URL, json=hits_answer([{"time": START_MS, "a": {"b": 1}}], total=7)
    )

    # When a Lucene query runs
    result = _client().lucene(
        ["ocsf-*"], "class_uid:1007", START, END, 5, RunDeadline(30)
    )

    # Then the window filters the search, sorted by time, with the exact total
    request = requests_mock.last_request
    assert request.qs == {"ignore_unavailable": ["true"], "allow_no_indices": ["true"]}
    assert request.json() == {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": "class_uid:1007"}}],
                "filter": [{"range": {"time": {"gte": START_MS, "lte": END_MS}}}],
            }
        },
        "size": 5,
        "track_total_hits": True,
        "sort": [{"time": {"order": "desc", "unmapped_type": "long"}}],
    }
    assert result.rows == [{"time": START_MS, "a": {"b": 1}}]
    assert (result.total, result.partial) == (7, False)


def test_lucene_date_window(requests_mock):
    # Given a date timestamp field
    requests_mock.post(SEARCH_URL, json=hits_answer([]))

    # When a Lucene query runs with a cap above the OpenSearch result window
    _client(timestamp_format="date").lucene(
        ["ocsf-*"], "*", START, END, 50000, RunDeadline(30)
    )

    # Then the window is an ISO range and the size is bounded
    body = requests_mock.last_request.json()
    assert body["query"]["bool"]["filter"] == [
        {
            "range": {
                "time": {
                    "gte": "2026-10-03T00:00:00.000Z",
                    "lte": "2026-10-04T00:00:00.000Z",
                    "format": "strict_date_optional_time",
                }
            }
        }
    ]
    assert body["size"] == 10000
    assert body["sort"] == [{"time": {"order": "desc", "unmapped_type": "date"}}]


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(hits_answer([{"a": 1}], timed_out=True), id="timed_out"),
        pytest.param(hits_answer([{"a": 1}], failed_shards=1), id="failed_shard"),
    ],
)
def test_lucene_flags_partial_results(requests_mock, answer):
    # Given a search that timed out or lost a shard
    requests_mock.post(SEARCH_URL, json=answer)

    # When/Then the results are partial
    result = _client().lucene(["ocsf-*"], "a:1", START, END, 5, RunDeadline(30))
    assert result.partial is True


def test_lucene_without_total(requests_mock):
    # Given an answer without a total and a hit without source
    requests_mock.post(SEARCH_URL, json={"hits": {"hits": [{"_id": "1"}]}})

    # When/Then the total is the number of documents, each row keeping the
    # document id that keys its hit across runs
    result = _client().lucene(["ocsf-*"], "a:1", START, END, 5, RunDeadline(30))
    assert (result.rows, result.total, result.partial) == ([{"_id": "1"}], 1, False)


def test_lucene_keeps_the_document_id_with_the_source(requests_mock):
    # Given a hit with its source and its document id
    requests_mock.post(
        SEARCH_URL,
        json={"hits": {"hits": [{"_id": "doc-7", "_source": {"a": 1}}]}},
    )

    # When/Then the row holds the source and the id
    result = _client().lucene(["ocsf-*"], "a:1", START, END, 5, RunDeadline(30))
    assert result.rows == [{"a": 1, "_id": "doc-7"}]


def test_lucene_keeps_apart_documents_of_two_indices_with_the_same_id(requests_mock):
    # Given two documents with the same id in two indices of the pattern
    requests_mock.post(
        SEARCH_URL,
        json={
            "hits": {
                "hits": [
                    {"_index": "ocsf-1", "_id": "doc-7", "_source": {"a": 1}},
                    {"_index": "ocsf-2", "_id": "doc-7", "_source": {"a": 2}},
                ]
            }
        },
    )

    # When/Then each row is identified by its index and its id
    result = _client().lucene(["ocsf-*"], "a:*", START, END, 5, RunDeadline(30))
    assert [row["_id"] for row in result.rows] == ["ocsf-1/doc-7", "ocsf-2/doc-7"]


def test_lucene_full_page_without_total_is_partial(requests_mock):
    # Given a full page answered without a total
    requests_mock.post(SEARCH_URL, json={"hits": {"hits": [{"_id": "1"}]}})

    # When/Then the page size is a lower bound of a partial result
    result = _client().lucene(["ocsf-*"], "a:1", START, END, 1, RunDeadline(30))
    assert (result.total, result.partial) == (1, True)


def test_lucene_lower_bound_total_is_partial(requests_mock):
    # Given a total that OpenSearch reports as a lower bound
    answer = hits_answer([{"a": 1}], total=10000)
    answer["hits"]["total"]["relation"] = "gte"
    requests_mock.post(SEARCH_URL, json=answer)

    # When/Then the result is partial
    result = _client().lucene(["ocsf-*"], "a:1", START, END, 5, RunDeadline(30))
    assert (result.total, result.partial) == (10000, True)


def test_lucene_rejects_unexpected_answers(requests_mock):
    # Given an answer that is not an object
    requests_mock.post(SEARCH_URL, json="nope")

    # When/Then the answer is rejected
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        _client().lucene(["ocsf-*"], "a:1", START, END, 5, RunDeadline(30))


def test_lucene_reports_the_search_error(requests_mock):
    # Given a malformed query string
    requests_mock.post(
        SEARCH_URL,
        status_code=400,
        json={"error": {"root_cause": [{"reason": "Failed to parse query [a:(]"}]}},
    )

    # When/Then the OpenSearch reason is reported
    with pytest.raises(HuntExecutionError, match="Failed to parse query"):
        _client().lucene(["ocsf-*"], "a:(", START, END, 5, RunDeadline(30))


@pytest.mark.parametrize(
    "query, expected",
    [
        pytest.param("source=x", "source=x | where c", id="source_only"),
        pytest.param("source=x | head 5;", "source=x | where c | head 5", id="pipe"),
        pytest.param(
            "source=x | where a='p|q' | fields a",
            "source=x | where c | where a='p|q' | fields a",
            id="quoted_pipe",
        ),
        pytest.param(
            'search source=`a|b` "x|y" | head 1',
            'search source=`a|b` "x|y" | where c | head 1',
            id="backticks",
        ),
    ],
)
def test_with_where(query, expected):
    # Given/When/Then the condition follows the first command, outside quotes
    assert with_where(query, "c") == expected


def test_ppl_rows_and_index_path():
    # Given/When/Then PPL rows are mapped to their columns and indices quoted
    answer = {"schema": [{"name": "a"}, {"name": "b"}], "datarows": [[1, 2]]}
    assert ppl_rows(answer) == [{"a": 1, "b": 2}]
    assert ppl_rows({}) == []
    assert index_path(["ocsf-*", "remote:logs 1"]) == "ocsf-*,remote:logs%201"
