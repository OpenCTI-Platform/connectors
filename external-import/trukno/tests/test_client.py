import json
from datetime import date

import pytest
from conftest import FIXTURES
from trukno_connector.client import TruKnoClient


class DummySession:
    def __init__(self, responses):
        self._responses = responses
        self.requests = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.requests.append(
            {
                "url": url,
                "headers": headers,
                "params": params,
                "timeout": timeout,
            }
        )
        return self._responses.pop(0)


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class ErrorResponse:
    def raise_for_status(self):
        raise RuntimeError("boom")

    def json(self):
        return {"ignored": True}


class EmptyResponse:
    status_code = 400
    content = b""

    def raise_for_status(self):
        raise RuntimeError("empty error")

    def json(self):
        raise ValueError("empty response")


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_list_updated_breaches_returns_ids_and_request_details():
    session = DummySession(
        [
            DummyResponse(_load_fixture("breach_list.json")),
            DummyResponse(
                {
                    "results": [
                        {"_id": "malware-only", "date": "2026-04-20T11:00:00Z"}
                    ],
                    "metadata": {"totalPages": 1},
                }
            ),
        ]
    )
    client = TruKnoClient("https://api.trukno.com/v2", "secret", session=session)
    client._today = lambda: date(2026, 4, 20)

    items = client.list_updated_breaches("2026-04-20T00:00:00Z")

    assert [item.id for item in items] == ["b1", "malware-only"]
    assert [request["params"]["hasTTPs"] for request in session.requests] == [
        "true",
        "false",
    ]
    assert session.requests[0] == {
        "url": "https://api.trukno.com/v2/breaches/list",
        "headers": {
            "Authorization": "Bearer secret",
            "Accept": "application/json",
        },
        "params": {
            "limit": 100,
            "page": 1,
            "sortBy": "updatedate",
            "start_date": "2026-04-20",
            "end_date": "2026-04-21",
            "hasTTPs": "true",
        },
        "timeout": 60,
    }


def test_get_breach_details_returns_payload_and_request_details():
    session = DummySession([DummyResponse(_load_fixture("breach_detail.json"))])
    client = TruKnoClient("https://api.trukno.com/v2", "secret", session=session)

    payload = client.get_breach_details("b1")

    assert payload["_id"] == "b1"
    assert session.requests == [
        {
            "url": "https://api.trukno.com/v2/breaches/b1",
            "headers": {
                "Authorization": "Bearer secret",
                "Accept": "application/json",
            },
            "params": None,
            "timeout": 60,
        }
    ]


def test_raise_for_status_errors_propagate_from_list_calls():
    session = DummySession([ErrorResponse()])
    client = TruKnoClient("https://api.trukno.com/v2", "secret", session=session)

    with pytest.raises(RuntimeError, match="boom"):
        client.list_updated_breaches("2026-04-20T00:00:00Z")


def test_bearer_prefix_is_not_duplicated_in_auth_header():
    session = DummySession(
        [
            DummyResponse(_load_fixture("breach_list.json")),
            DummyResponse({"results": [], "metadata": {"totalPages": 1}}),
        ]
    )
    client = TruKnoClient("https://api.trukno.com/v2", "Bearer secret", session=session)
    client._today = lambda: date(2026, 4, 20)

    client.list_updated_breaches("2026-04-20T00:00:00Z")

    assert session.requests[0]["headers"] == {
        "Authorization": "Bearer secret",
        "Accept": "application/json",
    }


def test_list_updated_breaches_reads_all_pages_and_filters_checkpoint_item():
    first_page = {
        "results": [
            {"_id": "checkpoint", "date": "2026-04-20T00:00:00Z"},
            {"_id": "newer", "date": "2026-04-20T12:00:00Z"},
        ],
        "metadata": {"page": 1, "totalPages": 2},
    }
    second_page = {
        "results": [
            {"_id": "newest", "date": "2026-04-21T08:00:00Z"},
        ],
        "metadata": {"page": 2, "totalPages": 2},
    }
    empty_page = {"results": [], "metadata": {"totalPages": 1}}
    session = DummySession(
        [
            DummyResponse(first_page),
            DummyResponse(second_page),
            DummyResponse(empty_page),
        ]
    )
    client = TruKnoClient("https://api.trukno.com/v2", "secret", session=session)
    client._today = lambda: date(2026, 4, 20)

    items = client.list_updated_breaches("2026-04-20T00:00:00Z")

    assert [(item.id, item.updated_at) for item in items] == [
        ("newer", "2026-04-20T12:00:00Z"),
        ("newest", "2026-04-21T08:00:00Z"),
    ]
    assert [request["params"]["page"] for request in session.requests] == [1, 2, 1]


def test_list_updated_breaches_splits_the_range_into_daily_windows():
    first_day = {
        "results": [{"_id": "first", "date": "2026-04-20T12:00:00Z"}],
        "metadata": {"page": 1, "totalPages": 1},
    }
    second_day = {
        "results": [{"_id": "second", "date": "2026-04-21T08:00:00Z"}],
        "metadata": {"page": 1, "totalPages": 1},
    }
    empty_day = {"results": [], "metadata": {"totalPages": 1}}
    session = DummySession(
        [
            DummyResponse(first_day),
            DummyResponse(empty_day),
            DummyResponse(second_day),
            DummyResponse(empty_day),
        ]
    )
    client = TruKnoClient("https://api.trukno.com/v2", "secret", session=session)
    client._today = lambda: date(2026, 4, 21)

    items = client.list_updated_breaches("2026-04-20T00:00:00Z")

    assert [item.id for item in items] == ["first", "second"]
    assert [
        (request["params"]["start_date"], request["params"]["end_date"])
        for request in session.requests
    ] == [
        ("2026-04-20", "2026-04-21"),
        ("2026-04-20", "2026-04-21"),
        ("2026-04-21", "2026-04-22"),
        ("2026-04-21", "2026-04-22"),
    ]


def test_list_updated_breaches_retries_rate_limited_requests():
    session = DummySession(
        [
            DummyResponse({}, status_code=429),
            DummyResponse(_load_fixture("breach_list.json")),
            DummyResponse({"results": [], "metadata": {"totalPages": 1}}),
        ]
    )
    sleep_calls = []
    client = TruKnoClient(
        "https://api.trukno.com/v2",
        "secret",
        session=session,
        sleep=sleep_calls.append,
    )
    client._today = lambda: date(2026, 4, 20)

    items = client.list_updated_breaches("2026-04-20T00:00:00Z")

    assert [item.id for item in items] == ["b1"]
    assert sleep_calls == [1]


def test_list_updated_breaches_accepts_empty_false_partition_response():
    session = DummySession(
        [
            DummyResponse(_load_fixture("breach_list.json")),
            DummyResponse([], status_code=400),
        ]
    )
    client = TruKnoClient("https://api.trukno.com/v2", "secret", session=session)
    client._today = lambda: date(2026, 4, 20)

    items = client.list_updated_breaches("2026-04-20T00:00:00Z")

    assert [item.id for item in items] == ["b1"]


def test_list_updated_breaches_accepts_empty_false_partition_body():
    session = DummySession(
        [
            DummyResponse(_load_fixture("breach_list.json")),
            EmptyResponse(),
        ]
    )
    client = TruKnoClient("https://api.trukno.com/v2", "secret", session=session)
    client._today = lambda: date(2026, 4, 20)

    items = client.list_updated_breaches("2026-04-20T00:00:00Z")

    assert [item.id for item in items] == ["b1"]
