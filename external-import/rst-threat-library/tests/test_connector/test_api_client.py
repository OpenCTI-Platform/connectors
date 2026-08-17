from unittest.mock import MagicMock

import pytest
import requests
from rst_threat_library_client.api_client import ThreatLibraryClient


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self.reason = "Error"
        self.url = "http://test.com/threat-objects/malware"
        self._payload = payload or {"data": []}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}", response=self)

    def json(self):
        return self._payload


def test_get_json_retries_transient_http_errors(monkeypatch):
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    client = ThreatLibraryClient(
        helper,
        base_url="http://test.com/v1",
        api_key="secret",
        retry=2,
    )

    responses = [
        _FakeResponse(500),
        _FakeResponse(200, {"data": [{"standard_id": "malware--1", "name": "x"}]}),
    ]
    client._session.get = MagicMock(side_effect=responses)
    monkeypatch.setattr(
        "rst_threat_library_client.api_client.time.sleep", lambda _: None
    )

    payload = client._get_json(
        "http://test.com/v1/threat-objects/malware", {"limit": 1}
    )

    assert payload["data"][0]["standard_id"] == "malware--1"
    assert client._session.get.call_count == 2


def test_get_json_raises_after_retry_budget_exhausted(monkeypatch):
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    client = ThreatLibraryClient(
        helper,
        base_url="http://test.com/v1",
        api_key="secret",
        retry=1,
    )
    client._session.get = MagicMock(return_value=_FakeResponse(500))
    monkeypatch.setattr(
        "rst_threat_library_client.api_client.time.sleep", lambda _: None
    )

    with pytest.raises(requests.HTTPError):
        client._get_json("http://test.com/v1/threat-objects/malware", {"limit": 1})

    assert client._session.get.call_count == 2


def test_get_json_does_not_retry_permanent_4xx(monkeypatch):
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    client = ThreatLibraryClient(
        helper,
        base_url="http://test.com/v1",
        api_key="secret",
        retry=2,
    )
    client._session.get = MagicMock(return_value=_FakeResponse(401))
    sleep = MagicMock()
    monkeypatch.setattr("rst_threat_library_client.api_client.time.sleep", sleep)

    with pytest.raises(requests.HTTPError):
        client._get_json("http://test.com/v1/threat-objects/malware", {"limit": 1})

    assert client._session.get.call_count == 1
    sleep.assert_not_called()


def test_get_json_retries_429(monkeypatch):
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    client = ThreatLibraryClient(
        helper,
        base_url="http://test.com/v1",
        api_key="secret",
        retry=2,
    )
    responses = [
        _FakeResponse(429),
        _FakeResponse(200, {"data": [{"standard_id": "malware--1", "name": "x"}]}),
    ]
    client._session.get = MagicMock(side_effect=responses)
    monkeypatch.setattr(
        "rst_threat_library_client.api_client.time.sleep", lambda _: None
    )

    payload = client._get_json(
        "http://test.com/v1/threat-objects/malware", {"limit": 1}
    )

    assert payload["data"][0]["standard_id"] == "malware--1"
    assert client._session.get.call_count == 2


def _client(*, order_mode: str = "desc") -> ThreatLibraryClient:
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return ThreatLibraryClient(
        helper,
        base_url="http://test.com/v1",
        api_key="secret",
        order_mode=order_mode,
    )


def test_iter_new_items_desc_includes_objects_with_cursor_timestamp():
    client = _client(order_mode="desc")
    client._iter_pages = MagicMock(
        return_value=iter(
            [
                {"standard_id": "malware--new", "modified": "2024-02-01T00:00:00.000Z"},
                {"standard_id": "malware--same", "modified": "2024-01-01T00:00:00.000Z"},
                {"standard_id": "malware--old", "modified": "2023-12-01T00:00:00.000Z"},
            ]
        )
    )

    got = list(client.iter_new_items("malware", "2024-01-01T00:00:00.000Z"))

    assert [item["standard_id"] for item in got] == [
        "malware--new",
        "malware--same",
    ]


def test_iter_new_items_desc_skips_known_ids_at_cursor_timestamp():
    client = _client(order_mode="desc")
    client._iter_pages = MagicMock(
        return_value=iter(
            [
                {"standard_id": "malware--new", "modified": "2024-02-01T00:00:00.000Z"},
                {"standard_id": "malware--same", "modified": "2024-01-01T00:00:00.000Z"},
                {"standard_id": "malware--old", "modified": "2023-12-01T00:00:00.000Z"},
            ]
        )
    )

    got = list(
        client.iter_new_items(
            "malware",
            "2024-01-01T00:00:00.000Z",
            cursor_ids=["malware--same"],
        )
    )

    assert [item["standard_id"] for item in got] == ["malware--new"]


def test_iter_new_items_desc_yields_nothing_when_only_known_cursor_items_remain():
    client = _client(order_mode="desc")
    client._iter_pages = MagicMock(
        return_value=iter(
            [
                {"standard_id": "malware--same", "modified": "2024-01-01T00:00:00.000Z"},
                {"standard_id": "malware--old", "modified": "2023-12-01T00:00:00.000Z"},
            ]
        )
    )

    got = list(
        client.iter_new_items(
            "malware",
            "2024-01-01T00:00:00.000Z",
            cursor_ids=["malware--same"],
        )
    )

    assert got == []


def test_iter_new_items_asc_includes_objects_with_cursor_timestamp():
    client = _client(order_mode="asc")
    client._iter_pages = MagicMock(
        return_value=iter(
            [
                {"standard_id": "malware--old", "modified": "2023-12-01T00:00:00.000Z"},
                {"standard_id": "malware--same", "modified": "2024-01-01T00:00:00.000Z"},
                {"standard_id": "malware--new", "modified": "2024-02-01T00:00:00.000Z"},
            ]
        )
    )

    got = list(client.iter_new_items("malware", "2024-01-01T00:00:00.000Z"))

    assert [item["standard_id"] for item in got] == [
        "malware--same",
        "malware--new",
    ]
