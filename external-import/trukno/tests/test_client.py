import json

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
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class ErrorResponse:
    def raise_for_status(self):
        raise RuntimeError("boom")

    def json(self):
        return {"ignored": True}


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_list_updated_breaches_returns_ids_and_request_details():
    session = DummySession([DummyResponse(_load_fixture("breach_list.json"))])
    client = TruKnoClient("https://api.trukno.com/v2", "secret", session=session)

    items = client.list_updated_breaches("2026-04-20T00:00:00Z")

    assert [item.id for item in items] == ["b1"]
    assert session.requests == [
        {
            "url": "https://api.trukno.com/v2/breaches",
            "headers": {"x-api-key": "secret"},
            "params": {"updated_after": "2026-04-20T00:00:00Z"},
            "timeout": 60,
        }
    ]


def test_get_breach_details_returns_payload_and_request_details():
    session = DummySession([DummyResponse(_load_fixture("breach_detail.json"))])
    client = TruKnoClient("https://api.trukno.com/v2", "secret", session=session)

    payload = client.get_breach_details("b1")

    assert payload["id"] == "b1"
    assert session.requests == [
        {
            "url": "https://api.trukno.com/v2/breaches/b1",
            "headers": {"x-api-key": "secret"},
            "params": None,
            "timeout": 60,
        }
    ]


def test_raise_for_status_errors_propagate_from_list_calls():
    session = DummySession([ErrorResponse()])
    client = TruKnoClient("https://api.trukno.com/v2", "secret", session=session)

    with pytest.raises(RuntimeError, match="boom"):
        client.list_updated_breaches("2026-04-20T00:00:00Z")
