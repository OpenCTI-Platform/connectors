"""Tests of the Azure Resource Manager client: auth, pagination, retries."""

from unittest.mock import MagicMock

import pytest
import requests_mock as requests_mock_module
from connectors_sdk import ApiClientError, ApiServerError, ApiUnauthorizedError
from sentinel_client import SentinelAlertRulesClient

TENANT = "00000000-0000-4000-8000-0000000000aa"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
RULES_URL = (
    "https://management.azure.com/subscriptions/sub-1/resourceGroups/soc-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/soc-workspace"
    "/providers/Microsoft.SecurityInsights/alertRules"
)


def _client(sleep=None, **kwargs) -> SentinelAlertRulesClient:
    values = {
        "tenant_id": TENANT,
        "client_id": "app-id",
        "client_secret": "s3cr3t",
        "subscription_id": "sub-1",
        "resource_group": "soc-rg",
        "workspace_name": "soc-workspace",
        "api_version": "2025-07-01-preview",
        "logger": MagicMock(),
        "management_url": "https://management.azure.com/",
        "login_url": "https://login.microsoftonline.com/",
        "sleep": sleep or MagicMock(),
    }
    values.update(kwargs)
    return SentinelAlertRulesClient(**values)


@pytest.fixture
def http():
    with requests_mock_module.Mocker() as mocker:
        mocker.post(TOKEN_URL, json={"access_token": "token-1", "expires_in": 3599})
        yield mocker


def test_client_credentials_and_next_link(http):
    next_link = f"{RULES_URL}?api-version=2025-07-01-preview&$skipToken=abc"
    http.get(
        RULES_URL,
        [
            {"json": {"value": [{"name": "a"}], "nextLink": next_link}},
            {"json": {"value": [{"name": "b"}]}},
        ],
    )
    rules = list(_client().iter_alert_rules())
    assert [r["name"] for r in rules] == ["a", "b"]

    token_request = http.request_history[0]
    assert token_request.method == "POST"
    assert "grant_type=client_credentials" in token_request.text
    assert "scope=https%3A%2F%2Fmanagement.azure.com%2F.default" in token_request.text
    first, second = http.request_history[1:]
    assert first.method == "GET"
    assert first.headers["Authorization"] == "Bearer token-1"
    assert first.qs == {"api-version": ["2025-07-01-preview"]}
    assert second.qs["$skiptoken"] == ["abc"]
    # The token is reused until it expires.
    assert [r.method for r in http.request_history] == ["POST", "GET", "GET"]


def test_next_link_outside_resource_manager_is_refused(http):
    http.get(
        RULES_URL,
        json={"value": [], "nextLink": "https://evil.example.com/steal"},
    )
    with pytest.raises(ApiClientError, match="Refusing"):
        list(_client().iter_alert_rules())


def test_expired_token_is_renewed_once(http):
    http.post(
        TOKEN_URL,
        [
            {"json": {"access_token": "token-1", "expires_in": 3599}},
            {"json": {"access_token": "token-2", "expires_in": 3599}},
        ],
    )
    http.get(RULES_URL, [{"status_code": 401}, {"json": {"value": [{"name": "a"}]}}])
    assert len(list(_client().iter_alert_rules())) == 1
    assert http.request_history[-1].headers["Authorization"] == "Bearer token-2"


def test_invalid_credentials(http):
    http.post(TOKEN_URL, status_code=401, json={"error": "invalid_client"})
    with pytest.raises(ApiUnauthorizedError):
        list(_client().iter_alert_rules())


def test_token_response_without_token(http):
    http.post(TOKEN_URL, json={"error": "nope"})
    with pytest.raises(ApiUnauthorizedError):
        list(_client().iter_alert_rules())


def test_throttling_is_retried(http):
    sleep = MagicMock()
    http.get(
        RULES_URL,
        [
            {"status_code": 429, "headers": {"Retry-After": "12"}},
            {"json": {"value": [{"name": "a"}]}},
        ],
    )
    assert len(list(_client(sleep=sleep).iter_alert_rules())) == 1
    sleep.assert_called_once_with(12.0)


def test_server_errors_give_up_after_max_retries(http):
    sleep = MagicMock()
    http.get(RULES_URL, status_code=503)
    with pytest.raises(ApiServerError):
        list(_client(sleep=sleep, max_retries=1).iter_alert_rules())
    assert sleep.call_count == 1


def test_unexpected_payload(http):
    http.get(RULES_URL, json={"error": {"code": "BadRequest"}})
    with pytest.raises(ApiClientError, match="Unexpected response"):
        list(_client().iter_alert_rules())
