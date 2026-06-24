from unittest.mock import MagicMock

import pytest
from splunk_connector.client import SplunkClient, SplunkClientError


def test_client_uses_bearer_token():
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )

    assert client.session.headers["Authorization"] == "Bearer secret-token"


def test_saved_search_pagination_filters_disabled(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )

    responses = [
        {
            "entry": [
                {"name": "enabled", "content": {"search": "index=main"}},
                {"name": "disabled", "content": {"search": "index=main", "disabled": "1"}},
            ]
        }
    ]
    monkeypatch.setattr(client, "_request", MagicMock(side_effect=responses))

    searches = client.get_saved_searches(include_disabled=False, count=500)

    assert [search["name"] for search in searches] == ["enabled"]


def test_request_raises_on_http_error(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    response = MagicMock(status_code=403, text="forbidden")
    monkeypatch.setattr(client.session, "request", MagicMock(return_value=response))

    with pytest.raises(SplunkClientError):
        client._request("GET", "/services/test")


def test_request_retries_transient_http_errors(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    first_response = MagicMock(status_code=429, text="rate limited", headers={})
    second_response = MagicMock(status_code=200, headers={})
    second_response.json.return_value = {"ok": True}
    request = MagicMock(side_effect=[first_response, second_response])
    sleep = MagicMock()
    monkeypatch.setattr(client.session, "request", request)
    monkeypatch.setattr("splunk_connector.client.time.sleep", sleep)

    assert client._request("GET", "/services/test") == {"ok": True}
    assert request.call_count == 2
    sleep.assert_called_once_with(1.0)


def test_request_honors_retry_after_header(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    first_response = MagicMock(
        status_code=503, text="unavailable", headers={"Retry-After": "2.5"}
    )
    second_response = MagicMock(status_code=200, headers={})
    second_response.json.return_value = {"ok": True}
    monkeypatch.setattr(
        client.session,
        "request",
        MagicMock(side_effect=[first_response, second_response]),
    )
    sleep = MagicMock()
    monkeypatch.setattr("splunk_connector.client.time.sleep", sleep)

    client._request("GET", "/services/test")

    sleep.assert_called_once_with(2.5)


def test_run_search_creates_job_waits_and_returns_results(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    request = MagicMock(return_value={"sid": "search-id"})
    wait = MagicMock()
    results = MagicMock(return_value=[{"event": "one"}])
    monkeypatch.setattr(client, "_request", request)
    monkeypatch.setattr(client, "_wait_for_search", wait)
    monkeypatch.setattr(client, "_get_search_results", results)

    rows = client.run_search(
        "index=main",
        earliest_time="-15m",
        latest_time="now",
        max_records=10,
    )

    assert rows == [{"event": "one"}]
    request.assert_called_once_with(
        "POST",
        "/services/search/jobs",
        data={
            "search": "search index=main",
            "output_mode": "json",
            "exec_mode": "normal",
            "earliest_time": "-15m",
            "latest_time": "now",
        },
    )
    wait.assert_called_once_with("search-id")
    results.assert_called_once_with("search-id", max_records=10)


def test_run_search_preserves_search_prefix(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    request = MagicMock(return_value={"sid": "search-id"})
    monkeypatch.setattr(client, "_request", request)
    monkeypatch.setattr(client, "_wait_for_search", MagicMock())
    monkeypatch.setattr(client, "_get_search_results", MagicMock(return_value=[]))

    client.run_search("search index=main")

    assert request.call_args.kwargs["data"]["search"] == "search index=main"


def test_run_search_raises_when_sid_missing(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    monkeypatch.setattr(client, "_request", MagicMock(return_value={}))

    with pytest.raises(SplunkClientError):
        client.run_search("index=main")


def test_wait_for_search_returns_when_done(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    monkeypatch.setattr(
        client,
        "_request",
        MagicMock(return_value={"entry": [{"content": {"isDone": "1"}}]}),
    )
    sleep = MagicMock()
    monkeypatch.setattr("splunk_connector.client.time.sleep", sleep)

    client._wait_for_search("search-id")

    sleep.assert_not_called()


def test_wait_for_search_times_out(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
        timeout_seconds=1,
    )
    monkeypatch.setattr(
        client,
        "_request",
        MagicMock(return_value={"entry": [{"content": {"isDone": "0"}}]}),
    )
    monkeypatch.setattr("splunk_connector.client.time.sleep", MagicMock())
    monkeypatch.setattr(
        "splunk_connector.client.time.time",
        MagicMock(side_effect=[100.0, 100.1, 101.2]),
    )

    with pytest.raises(SplunkClientError):
        client._wait_for_search("search-id")


def test_get_search_results_paginates_and_truncates(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    first_page = [{"event": str(index)} for index in range(500)]
    second_page = [{"event": "500"}]
    request = MagicMock(
        side_effect=[
            {"results": first_page},
            {"results": second_page},
        ]
    )
    monkeypatch.setattr(client, "_request", request)

    rows = client._get_search_results("search-id", max_records=501)

    assert rows == first_page + second_page
    assert request.call_args_list[0].kwargs["params"]["offset"] == 0
    assert request.call_args_list[1].kwargs["params"]["offset"] == 500


def test_get_search_results_respects_unlimited_max_records(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    monkeypatch.setattr(
        client,
        "_request",
        MagicMock(return_value={"results": [{"event": "one"}]}),
    )

    rows = client._get_search_results("search-id", max_records=0)

    assert rows == [{"event": "one"}]


def test_get_search_results_raises_on_malformed_results(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    monkeypatch.setattr(client, "_request", MagicMock(return_value={"results": {}}))

    with pytest.raises(SplunkClientError):
        client._get_search_results("search-id", max_records=10)


def test_get_paginated_collects_multiple_pages(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    monkeypatch.setattr(
        client,
        "_request",
        MagicMock(
            side_effect=[
                {"entry": [{"name": "one"}]},
                {"entry": []},
            ]
        ),
    )

    rows = client._get_paginated("/services/test", {"offset": 0}, count=1)

    assert rows == [{"name": "one"}]


def test_get_paginated_raises_on_malformed_entry(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    monkeypatch.setattr(client, "_request", MagicMock(return_value={"entry": {}}))

    with pytest.raises(SplunkClientError):
        client._get_paginated("/services/test", {"offset": 0}, count=1)


@pytest.mark.parametrize("key", ["results", "entry", "items", "data"])
def test_get_json_list_accepts_supported_list_keys(monkeypatch, key):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    monkeypatch.setattr(client, "_request", MagicMock(return_value={key: [{"id": key}]}))

    assert client._get_json_list("/services/test") == [{"id": key}]


def test_get_json_list_raises_when_no_list(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    monkeypatch.setattr(client, "_request", MagicMock(return_value={"messages": []}))

    with pytest.raises(SplunkClientError):
        client._get_json_list("/services/test")


def test_request_raises_on_non_json(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    response = MagicMock(status_code=200)
    response.json.side_effect = ValueError("not json")
    monkeypatch.setattr(client.session, "request", MagicMock(return_value=response))

    with pytest.raises(SplunkClientError):
        client._request("GET", "/services/test")


def test_request_raises_on_non_object_json(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    response = MagicMock(status_code=200)
    response.json.return_value = []
    monkeypatch.setattr(client.session, "request", MagicMock(return_value=response))

    with pytest.raises(SplunkClientError):
        client._request("GET", "/services/test")


def test_first_entry_content_handles_empty_and_malformed_entries():
    assert SplunkClient._first_entry_content({}) == {}
    assert SplunkClient._first_entry_content({"entry": []}) == {}
    assert SplunkClient._first_entry_content({"entry": [{"content": "bad"}]}) == {}
    assert SplunkClient._first_entry_content(
        {"entry": [{"content": {"isDone": True}}]}
    ) == {"isDone": True}


@pytest.mark.parametrize(
    "value, expected",
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        ("true", True),
        ("yes", True),
        ("y", True),
        ("false", False),
        (None, False),
    ],
)
def test_to_bool_variants(value, expected):
    assert SplunkClient._to_bool(value) is expected


def test_get_assets_identities_tags_records(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    monkeypatch.setattr(
        client,
        "_get_json_list",
        MagicMock(side_effect=[[{"host": "server01"}], [{"identity": "alice"}]]),
    )

    assert client.get_assets_identities() == [
        {"host": "server01", "record_type": "asset"},
        {"identity": "alice", "record_type": "identity"},
    ]


def test_get_findings_passes_optional_earliest_time(monkeypatch):
    client = SplunkClient(
        base_url="https://splunk.example.com:8089",
        token="secret-token",
    )
    get_json = MagicMock(return_value=[])
    monkeypatch.setattr(client, "_get_json_list", get_json)

    client.get_findings(earliest_time="-1h")

    get_json.assert_called_once_with(
        "/servicesNS/nobody/missioncontrol/public/v2/findings",
        params={"earliest_time": "-1h"},
    )
