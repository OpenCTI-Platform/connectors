"""Tests for the Rösti API client (no network access)."""

import datetime as dt
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from conftest import load_fixture
from connectors_sdk.client.exceptions import ApiRateLimitError
from rosti_client import RostiClient
from rosti_client.api_client import quota_exceeded


class RecordingClient(RostiClient):
    """RostiClient whose HTTP GETs are answered from a dict of canned responses."""

    def __init__(self, responses):
        super().__init__(api_key="secret")
        self.responses = responses
        self.requests = []

    def _get(self, path, *, params=None, **kwargs):
        self.requests.append((path, dict(params or {})))
        answer = self.responses[path]
        if isinstance(answer, list):  # successive pages
            return answer.pop(0)
        return answer


def test_headers_carry_api_key_and_user_agent():
    client = RostiClient(api_key="secret")
    assert client.session_headers["X-API-Key"] == "secret"
    assert client.session_headers["User-Agent"].startswith("opencti-connector-rosti/")
    assert client._session.headers["X-API-Key"] == "secret"


def test_report_list_query_and_cursor_pagination():
    page = lambda ids, more, cursor=None: {  # noqa: E731
        "data": [
            {
                "id": i,
                "title": i,
                "date": "2026-10-01",
                "url": "u",
                "authors": None,
                "tags": [],
                "count": {"iocs": 0, "yara_rules": 0, "mitre_ids": 0},
                "checksum": "c",
            }
            for i in ids
        ],
        "meta": {
            "paginated": True,
            "count": len(ids),
            "has_more": more,
            "limit": 100,
            "total": 3,
            "next_cursor": cursor,
        },
    }
    client = RecordingClient(
        {"/reports": [page(["A", "B"], True, "cur1"), page(["C"], False)]}
    )

    since = dt.datetime(
        2026, 10, 1, 12, 0, 5, tzinfo=dt.timezone(dt.timedelta(hours=2))
    )
    pages = list(client.iter_updated_reports(since))

    assert [[r.id for r in p] for p in pages] == [["A", "B"], ["C"]]
    first_params = client.requests[0][1]
    assert first_params == {
        "timestamp": "2026-10-01T10:00:05Z",
        "sort": "last_updated",
        "limit": 100,
    }
    assert client.requests[1][1]["cursor"] == "cur1"


def test_get_report_requests_mitre_cve_and_notes():
    client = RecordingClient(
        {"/reports/r1xSdqAy": load_fixture("report_r1xSdqAy.json")}
    )
    report = client.get_report("r1xSdqAy")
    assert report.cve[0].id == "CVE-2026-104286"
    assert client.requests[0][1] == {
        "mitre_ids": "true",
        "cve": "true",
        "notes": "true",
    }


def test_report_iocs_use_max_page_size():
    client = RecordingClient(
        {"/reports/r1xSdqAy/iocs": load_fixture("report_r1xSdqAy_iocs.json")}
    )
    iocs = client.get_report_iocs("r1xSdqAy")
    assert len(iocs) == 16
    assert client.requests[0][1] == {"limit": 1000}


def test_yara_rules_endpoint():
    client = RecordingClient(
        {"/reports/r1/yara-rules": load_fixture("yara_rules.json")}
    )
    rules = client.get_report_yara_rules("r1")
    assert [r.name for r in rules] == ["PavokwiLoader_1", "RMMCRAT_1"]


# ---------------------------------------------------------------------------
# Retries and quota, against a local HTTP server (real requests/urllib3)
# ---------------------------------------------------------------------------

QUOTA_BODY = {
    "type": "https://iana.org/assignments/http-problem-types#quota-exceeded",
    "title": "Daily quota exceeded",
    "status": 429,
    "detail": "Your free plan allows 1000 requests per day.",
    "reset": "2026-10-08T00:00:00Z",
}


@pytest.fixture
def api_server():
    """Local server answering with a queue of (status, headers, body) responses."""
    answers = []
    requests_seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802
            requests_seen.append(self.path)
            status, headers, body = answers.pop(0) if len(answers) > 1 else answers[0]
            data = json.dumps(body).encode()
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/v2", answers, requests_seen
    server.shutdown()


def test_short_retry_after_is_waited_for_and_retried(api_server):
    url, answers, seen = api_server
    answers += [
        (429, {"Retry-After": "1"}, {"title": "slow down"}),
        (200, {"Content-Type": "application/json"}, {"status": "ok"}),
    ]
    client = RostiClient(api_key="k", base_url=url, backoff_factor=0)
    start = time.monotonic()
    assert client._get("/status") == {"status": "ok"}
    assert time.monotonic() - start >= 1
    assert len(seen) == 2


def test_quota_exceeded_raises_with_problem_details(api_server):
    url, answers, seen = api_server
    answers.append((429, {"Content-Type": "application/problem+json"}, QUOTA_BODY))
    client = RostiClient(api_key="k", base_url=url, max_retries=2, backoff_factor=0)
    with pytest.raises(ApiRateLimitError) as error:
        client._get("/reports")
    assert quota_exceeded(error.value) == QUOTA_BODY
    assert error.value.retry_after is None
    assert len(seen) == 3  # first request + 2 retries


def test_other_errors_are_not_quota():
    assert (
        quota_exceeded(ApiRateLimitError("x", response_body={"title": "slow"})) is None
    )
    assert quota_exceeded(ValueError("x")) is None


# ---------------------------------------------------------------------------
# IOC groups (entity_ref)
# ---------------------------------------------------------------------------


def _ioc(ioc_id, entity_ref):
    return {
        "id": ioc_id,
        "type": "md5",
        "value": "0" * 32,
        "date": "2026-10-06",
        "report": "r1",
        "entity_ref": entity_ref,
    }


def _ioc_page(items, cursor=None):
    return {
        "data": items,
        "meta": {"has_more": cursor is not None, "next_cursor": cursor},
    }


def test_example_response_is_grouped_by_entity_ref():
    client = RecordingClient(
        {"/reports/oGmTvDQn/iocs": load_fixture("report_oGmTvDQn_iocs.json")}
    )
    groups = client.get_report_ioc_groups("oGmTvDQn")
    assert [[ioc.id for ioc in group] for group in groups] == [
        ["an5PrgvWWJQBBWqZPyPP9q"],
        ["WBzU2hwsq5c5bd4Ge8TcG3", "NL2oEmM2KxGE7AqjurBhC7"],
    ]
    assert groups[1][0].entity_ref == "rx7SAFIjtIiHz3CAlvsph"


def test_group_at_the_end_of_a_page_waits_for_the_next_page():
    client = RecordingClient(
        {
            "/reports/r1/iocs": [
                _ioc_page([_ioc("A", None), _ioc("B", "x")], "c1"),
                _ioc_page([_ioc("C", "x"), _ioc("D", "y")], "c2"),
                _ioc_page([_ioc("E", "y")]),
            ]
        }
    )
    groups = client.iter_report_ioc_groups("r1", page_size=2)

    assert [i.id for i in next(groups)] == ["A"]
    assert len(client.requests) == 1
    # B ends page 1: it is only released together with C from page 2
    assert [i.id for i in next(groups)] == ["B", "C"]
    assert len(client.requests) == 2
    assert [i.id for i in next(groups)] == ["D", "E"]
    assert len(client.requests) == 3
    assert next(groups, None) is None
    assert client.requests[1][1] == {"limit": 2, "cursor": "c1"}


def test_iocs_without_entity_ref_are_never_grouped():
    client = RecordingClient(
        {"/reports/r1/iocs": _ioc_page([_ioc("A", None), _ioc("B", None)])}
    )
    assert [len(g) for g in client.get_report_ioc_groups("r1")] == [1, 1]
    assert [i.id for i in client.get_report_iocs("r1")] == ["A", "B"]
