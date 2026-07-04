from unittest.mock import MagicMock, patch

import pytest
import requests
from fortisandbox_client import FortiSandboxAPIError, FortisandboxClient


def _make_client() -> FortisandboxClient:
    client = FortisandboxClient(
        MagicMock(),
        api_base_url="https://fsa.example.com",
        username="api-user",
        password="api-pass",
    )
    client.session = MagicMock()
    return client


def _response(payload, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_login_sets_session_token():
    client = _make_client()
    client.session.post.return_value = _response({"session": "TOKEN"})

    token = client.login()
    assert token == "TOKEN"
    assert client.session_token == "TOKEN"


def test_login_without_token_raises():
    client = _make_client()
    client.session.post.return_value = _response({"result": {"status": {"code": -1}}})

    with pytest.raises(FortiSandboxAPIError):
        client.login()


def test_get_file_rating_returns_data():
    client = _make_client()
    client.session_token = "TOKEN"
    client.session.post.return_value = _response(
        {"result": {"data": {"rating": "Malicious", "sha256": "abc"}}}
    )

    data = client.get_file_rating("abc")
    assert data["rating"] == "Malicious"


def test_get_file_rating_logs_in_when_no_session():
    client = _make_client()
    client.session.post.side_effect = [
        _response({"session": "TOKEN"}),
        _response({"result": {"data": {"rating": "Clean"}}}),
    ]

    data = client.get_file_rating("abc")
    assert data["rating"] == "Clean"
    assert client.session_token == "TOKEN"


def test_extract_data_inline_rating():
    payload = {"result": {"rating": "Suspicious"}}
    assert FortisandboxClient._extract_data(payload) == {"rating": "Suspicious"}


def test_extract_data_result_list():
    payload = {"result": [{"data": {"rating": "Clean"}}]}
    assert FortisandboxClient._extract_data(payload) == {"rating": "Clean"}


def test_extract_data_unexpected_returns_none():
    assert FortisandboxClient._extract_data({"unexpected": 1}) is None


def test_extract_jobs_variants():
    assert FortisandboxClient._extract_jobs({"result": {"data": [{"jid": "1"}]}}) == [
        {"jid": "1"}
    ]
    assert FortisandboxClient._extract_jobs(
        {"result": {"data": {"jobs": [{"jid": "2"}]}}}
    ) == [{"jid": "2"}]
    assert FortisandboxClient._extract_jobs({"result": {}}) == []


def test_submit_file_returns_sid():
    client = _make_client()
    client.session_token = "TOKEN"
    client.session.post.return_value = _response({"result": {"sid": "sub-1"}})

    sid = client.submit_file("malware.exe", b"data")
    assert sid == "sub-1"


def test_get_submission_verdict_polls_jobs():
    client = _make_client()
    client.session_token = "TOKEN"
    client.session.post.side_effect = [
        _response({"result": {"data": [{"jid": "5"}]}}),
        _response({"result": {"data": {"rating": "Malicious"}}}),
    ]

    with patch("fortisandbox_client.api_client.time.sleep"):
        verdict = client.get_submission_verdict("sub-1")
    assert verdict["rating"] == "Malicious"


def test_call_raises_on_http_error():
    client = _make_client()
    client.session_token = "TOKEN"
    err_response = MagicMock()
    err_response.status_code = 500
    err_response.reason = "Server Error"
    bad = MagicMock()
    bad.raise_for_status.side_effect = requests.HTTPError(response=err_response)
    client.session.post.return_value = bad

    with pytest.raises(FortiSandboxAPIError):
        client.get_file_rating("abc")


def test_call_wraps_non_http_request_errors():
    # Connection/timeout/retry errors (not HTTPError) must also be wrapped as
    # FortiSandboxAPIError so callers see a single, consistent error type.
    client = _make_client()
    client.session_token = "TOKEN"
    client.session.post.side_effect = requests.ConnectionError("boom")

    with pytest.raises(FortiSandboxAPIError):
        client.get_file_rating("abc")


def test_get_submission_verdict_does_not_sleep_past_max_wait():
    # With the budget already spent, the poll loop must return without sleeping
    # one extra interval beyond max_wait.
    client = _make_client()
    client.session_token = "TOKEN"
    client.session.post.side_effect = [
        _response({"result": {"data": [{"jid": "5"}]}}),  # get-jobs-of-submission
        _response({"result": {"data": None}}),  # job: no rating yet
    ]

    with patch("fortisandbox_client.api_client.time.sleep") as sleep:
        verdict = client.get_submission_verdict("sub-1", max_wait=0, interval=30)

    assert verdict is None
    sleep.assert_not_called()


def test_get_submission_verdict_stops_at_max_wait_boundary():
    # When the accumulated wait reaches max_wait exactly, the loop must return
    # without sleeping again (the budget is already spent).
    client = _make_client()
    client.session_token = "TOKEN"
    client.session.post.side_effect = [
        _response({"result": {"data": [{"jid": "5"}]}}),  # get-jobs-of-submission
        _response({"result": {"data": None}}),  # job: no rating yet
    ]

    with patch("fortisandbox_client.api_client.time.sleep") as sleep:
        verdict = client.get_submission_verdict("sub-1", max_wait=30, interval=30)

    assert verdict is None
    sleep.assert_not_called()
