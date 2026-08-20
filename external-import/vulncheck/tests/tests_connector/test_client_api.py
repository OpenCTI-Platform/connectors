"""Tests for the VulnCheck API client (pagination + source availability)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests
from vulncheck_client import VulnCheckClient


def _client(helper):
    return VulnCheckClient(helper, base_url="https://api.vulncheck.com/v3", api_key="k")


def _response(data, next_cursor):
    return SimpleNamespace(
        data=data, meta=SimpleNamespace(next_cursor=next_cursor, total_documents=99)
    )


def test_iter_data_follows_cursor_and_forwards_kwargs(helper):
    client = _client(helper)
    pages = [_response([1, 2], "cur1"), _response([3], None)]
    calls = []

    def index_func(session, **kwargs):
        calls.append(kwargs)
        return pages[len(calls) - 1]

    items = [
        x for page in client.iter_data(index_func, "test", foo="bar") for x in page
    ]

    assert items == [1, 2, 3]
    # first call starts a cursor session; second passes the returned cursor
    assert calls[0]["start_cursor"] == "true"
    assert calls[1]["cursor"] == "cur1"
    # extra query params are forwarded on every page
    assert all(c["foo"] == "bar" for c in calls)


def test_iter_data_stops_when_no_data(helper):
    client = _client(helper)
    index_func = MagicMock(return_value=_response(None, None))
    assert list(client.iter_data(index_func, "test")) == []


def test_is_source_available_true_on_2xx(helper, monkeypatch):
    monkeypatch.setattr(
        requests, "head", lambda *a, **k: SimpleNamespace(status_code=200)
    )
    assert _client(helper).is_source_available("botnets", "/index/") is True


def test_is_source_available_false_on_4xx(helper, monkeypatch):
    monkeypatch.setattr(
        requests, "head", lambda *a, **k: SimpleNamespace(status_code=403)
    )
    assert _client(helper).is_source_available("botnets", "/index/") is False


def test_is_source_available_raises_on_network_error(helper, monkeypatch):
    def boom(*a, **k):
        raise requests.RequestException("network down")

    monkeypatch.setattr(requests, "head", boom)
    with pytest.raises(RuntimeError, match="error testing botnets"):
        _client(helper).is_source_available("botnets", "/index/")
