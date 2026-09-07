from unittest.mock import MagicMock

import pytest
import requests
from cloudflare_rules_list.client import CloudflareAPIError, CloudflareRulesListClient


@pytest.fixture
def client():
    c = CloudflareRulesListClient(account_id="acc-1", api_token="token-1", timeout=10)
    c._session = MagicMock()
    return c


def _response(json_body=None, raise_exc=None):
    resp = MagicMock()
    resp.json.return_value = json_body or {}
    if raise_exc is not None:
        resp.raise_for_status.side_effect = raise_exc
    return resp


def test_auth_header_is_set():
    c = CloudflareRulesListClient(account_id="acc-1", api_token="secret")
    assert c._session.headers["Authorization"] == "Bearer secret"


def test_default_base_url():
    c = CloudflareRulesListClient(account_id="acc-1", api_token="secret")
    assert c.base_url == CloudflareRulesListClient.BASE_URL


def test_base_url_override_strips_trailing_slash():
    c = CloudflareRulesListClient(
        account_id="acc-1",
        api_token="secret",
        base_url="https://gateway.example/client/v4/",
    )
    assert c.base_url == "https://gateway.example/client/v4"


def test_session_verify_is_true():
    c = CloudflareRulesListClient(account_id="acc-1", api_token="secret")
    assert c._session.verify is True


def test_make_request_uses_overridden_base_url():
    c = CloudflareRulesListClient(
        account_id="acc-1", api_token="secret", base_url="http://mock:9999/v4"
    )
    c._session = MagicMock()
    c._session.request.return_value = _response({"result": {}})
    c._make_request("GET", "/rules/lists/abc")
    assert (
        c._session.request.call_args.kwargs["url"]
        == "http://mock:9999/v4/accounts/acc-1/rules/lists/abc"
    )


def test_make_request_success(client):
    client._session.request.return_value = _response({"result": {"ok": True}})
    result = client._make_request("GET", "/rules/lists/abc")
    assert result == {"result": {"ok": True}}
    args, kwargs = client._session.request.call_args
    assert kwargs["url"].endswith("/accounts/acc-1/rules/lists/abc")


def test_make_request_raises_on_non_json_success(client):
    # 2xx response whose body is not JSON (e.g. an HTML challenge page) must be
    # wrapped as CloudflareAPIError, not surface a bare ValueError.
    resp = _response()
    resp.json.side_effect = ValueError("no json")
    resp.text = "<html>challenge</html>"
    client._session.request.return_value = resp
    with pytest.raises(CloudflareAPIError) as exc:
        client._make_request("GET", "/x")
    assert "Invalid JSON" in str(exc.value)


def test_make_request_uses_custom_timeout(client):
    client._session.request.return_value = _response({"result": {}})
    client._make_request("PUT", "/x", data=[], timeout=300)
    assert client._session.request.call_args.kwargs["timeout"] == 300


def test_make_request_raises_with_structured_errors(client):
    err = requests.exceptions.HTTPError("400")
    err.response = MagicMock()
    err.response.json.return_value = {"errors": [{"code": 10001, "message": "bad"}]}
    client._session.request.return_value = _response(raise_exc=err)

    with pytest.raises(CloudflareAPIError) as exc:
        client._make_request("GET", "/x")
    assert "10001" in str(exc.value)


def test_make_request_raises_with_text_body(client):
    err = requests.exceptions.HTTPError("500")
    err.response = MagicMock()
    err.response.json.side_effect = ValueError("not json")
    err.response.text = "Internal Server Error"
    client._session.request.return_value = _response(raise_exc=err)

    with pytest.raises(CloudflareAPIError) as exc:
        client._make_request("GET", "/x")
    assert "Internal Server Error" in str(exc.value)


def test_make_request_raises_without_response(client):
    err = requests.exceptions.ConnectionError("no network")
    client._session.request.return_value = _response(raise_exc=err)
    with pytest.raises(CloudflareAPIError) as exc:
        client._make_request("GET", "/x")
    assert "no network" in str(exc.value)


def test_list_lists(client):
    client._session.request.return_value = _response({"result": [{"id": "l1"}]})
    assert client.list_lists() == [{"id": "l1"}]


def test_get_list(client):
    client._session.request.return_value = _response({"result": {"id": "l1"}})
    assert client.get_list("l1") == {"id": "l1"}


def test_get_list_items_with_cursor(client):
    client._session.request.return_value = _response({"result": []})
    client.get_list_items("l1", cursor="CURSOR")
    assert "cursor=CURSOR" in client._session.request.call_args.kwargs["url"]


def test_get_all_list_items_follows_pagination(client):
    page1 = _response(
        {"result": [{"ip": "1.1.1.1"}], "result_info": {"cursors": {"after": "C2"}}}
    )
    page2 = _response({"result": [{"ip": "2.2.2.2"}], "result_info": {"cursors": {}}})
    client._session.request.side_effect = [page1, page2]

    items = client.get_all_list_items("l1")
    assert items == [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}]


def test_replace_list_items(client):
    client._session.request.return_value = _response({"result": {"operation_id": "op"}})
    result = client.replace_list_items("l1", [{"ip": "1.1.1.1"}])
    assert result == {"operation_id": "op"}
    assert client._session.request.call_args.kwargs["method"] == "PUT"


def test_get_bulk_operation(client):
    client._session.request.return_value = _response(
        {"result": {"status": "completed"}}
    )
    assert client.get_bulk_operation("op") == {"status": "completed"}


def test_wait_for_operation_completed(client, monkeypatch):
    monkeypatch.setattr("cloudflare_rules_list.client.time.monotonic", lambda: 0.0)
    client._session.request.return_value = _response(
        {"result": {"status": "completed"}}
    )
    assert client.wait_for_operation("op") == {"status": "completed"}


def test_wait_for_operation_failed(client, monkeypatch):
    monkeypatch.setattr("cloudflare_rules_list.client.time.monotonic", lambda: 0.0)
    client._session.request.return_value = _response(
        {"result": {"status": "failed", "error": "boom"}}
    )
    with pytest.raises(CloudflareAPIError) as exc:
        client.wait_for_operation("op")
    assert "boom" in str(exc.value)


def test_wait_for_operation_times_out(client, monkeypatch):
    times = iter([0.0, 0.0, 100.0])
    monkeypatch.setattr(
        "cloudflare_rules_list.client.time.monotonic", lambda: next(times)
    )
    monkeypatch.setattr("cloudflare_rules_list.client.time.sleep", lambda _: None)
    client._session.request.return_value = _response({"result": {"status": "pending"}})

    with pytest.raises(CloudflareAPIError) as exc:
        client.wait_for_operation("op", timeout=10)
    assert "timed out" in str(exc.value)


def test_wait_for_operation_polls_until_complete(client, monkeypatch):
    monkeypatch.setattr("cloudflare_rules_list.client.time.monotonic", lambda: 0.0)
    monkeypatch.setattr("cloudflare_rules_list.client.time.sleep", lambda _: None)
    client._session.request.side_effect = [
        _response({"result": {"status": "pending"}}),
        _response({"result": {"status": "completed"}}),
    ]
    assert client.wait_for_operation("op") == {"status": "completed"}
