"""Tests of the Chronicle API client: auth, pagination, retries, errors."""

from unittest.mock import MagicMock

import pytest
import requests_mock as requests_mock_module
from conftest import FakeCredentials
from connectors_sdk import ApiClientError, ApiRateLimitError, ApiUnauthorizedError
from google.auth.exceptions import RefreshError, TransportError
from secops_client import GoogleSecOpsRulesClient
from secops_client import api_client as api_client_module
from secops_client import rule_id_from_name
from secops_client.api_client import regional_url

INSTANCE = (
    "https://europe-chronicle.googleapis.com/v1alpha/projects/soc-project"
    "/locations/europe/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6"
)
RULES = f"{INSTANCE}/rules"
DEPLOYMENTS = f"{INSTANCE}/rules/-/deployments"
RULE_NAME = (
    "projects/soc-project/locations/europe/instances/"
    "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/rules/ru_e6abfcb5"
)


def _client(credentials=None, sleep=None, **kwargs) -> GoogleSecOpsRulesClient:
    options = {
        "base_url": "https://chronicle.googleapis.com/",
        "region": "europe",
        "project_id": "soc-project",
        "instance_id": "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6",
        "api_version": "v1alpha",
        "credentials": credentials or FakeCredentials(),
        "logger": MagicMock(),
        "sleep": sleep or MagicMock(),
        "auth_request": MagicMock,
    }
    options.update(kwargs)
    return GoogleSecOpsRulesClient(**options)


@pytest.fixture
def http():
    with requests_mock_module.Mocker() as mocker:
        yield mocker


@pytest.mark.parametrize(
    "base_url,region,expected",
    [
        (
            "https://chronicle.googleapis.com",
            "us",
            "https://us-chronicle.googleapis.com",
        ),
        (
            "https://chronicle.googleapis.com/",
            "europe-west2",
            "https://europe-west2-chronicle.googleapis.com",
        ),
    ],
)
def test_regional_url(base_url, region, expected):
    assert regional_url(base_url, region) == expected


@pytest.mark.parametrize(
    "name,rule_id",
    [
        (RULE_NAME, "ru_e6abfcb5"),
        (f"{RULE_NAME}/deployment", "ru_e6abfcb5"),
        (f"{RULE_NAME}@v_1767323045_123456000", "ru_e6abfcb5"),
        ("ru_e6abfcb5", None),
        (None, None),
    ],
)
def test_rule_id_from_name(name, rule_id):
    assert rule_id_from_name(name) == rule_id


def test_rules_are_paged_with_their_full_view(http):
    http.get(
        RULES,
        [
            {
                "json": {
                    "rules": [{"name": "r1"}, {"name": "r2"}],
                    "nextPageToken": "p2",
                }
            },
            {"json": {"rules": [{"name": "r3"}, "not a rule"]}},
        ],
    )
    credentials = FakeCredentials("token-1")
    rules = list(_client(credentials, page_size=2).iter_rules())
    assert [r["name"] for r in rules] == ["r1", "r2", "r3"]
    first, second = http.request_history
    assert first.qs == {"view": ["full"], "pagesize": ["2"]}
    assert second.qs == {"view": ["full"], "pagesize": ["2"], "pagetoken": ["p2"]}
    assert first.headers["Authorization"] == "Bearer token-1"
    # The token is fetched once and reused while valid.
    assert credentials.refreshes == 1


def test_deployments_are_keyed_by_rule_id(http):
    http.get(
        DEPLOYMENTS,
        [
            {
                "json": {
                    "ruleDeployments": [
                        {"name": f"{RULE_NAME}/deployment", "enabled": True},
                        {"name": "no rule id", "enabled": True},
                    ],
                    "nextPageToken": "p2",
                }
            },
            {
                "json": {
                    "ruleDeployments": [
                        {"name": f"{RULE_NAME}2/deployment", "archived": True}
                    ]
                }
            },
        ],
    )
    deployments = _client().rule_deployments()
    assert deployments == {
        "ru_e6abfcb5": {"name": f"{RULE_NAME}/deployment", "enabled": True},
        "ru_e6abfcb52": {"name": f"{RULE_NAME}2/deployment", "archived": True},
    }
    assert "view" not in http.request_history[0].qs


def test_instance_without_rules(http):
    http.get(RULES, json={})
    assert list(_client().iter_rules()) == []


def test_repeated_page_token_stops_with_an_error(http):
    http.get(RULES, json={"rules": [{"name": "r1"}], "nextPageToken": "same"})
    with pytest.raises(ApiClientError, match="same page token twice"):
        list(_client().iter_rules())


def test_unexpected_payload(http):
    http.get(RULES, json={"rules": "nope"})
    with pytest.raises(ApiClientError, match="Unexpected response"):
        list(_client().iter_rules())


def test_non_json_payload(http):
    http.get(
        RULES, text="<html>proxy error</html>", headers={"Content-Type": "text/html"}
    )
    with pytest.raises(ApiClientError, match="Unexpected response"):
        list(_client().iter_rules())


def test_revoked_token_is_renewed_once(http):
    http.get(RULES, [{"status_code": 401}, {"json": {"rules": []}}])
    credentials = FakeCredentials("token-1", "token-2")
    list(_client(credentials).iter_rules())
    assert http.request_history[-1].headers["Authorization"] == "Bearer token-2"
    assert credentials.refreshes == 2


def test_rejected_token_twice_fails(http):
    http.get(RULES, status_code=401)
    with pytest.raises(ApiUnauthorizedError):
        list(_client(FakeCredentials("token-1", "token-2")).iter_rules())


def test_rejected_service_account(http):
    credentials = FakeCredentials(error=RefreshError("invalid_grant: Invalid JWT"))
    with pytest.raises(ApiUnauthorizedError, match="invalid_grant"):
        list(_client(credentials).iter_rules())
    assert http.request_history == []


def test_unreachable_token_endpoint(http):
    credentials = FakeCredentials(error=TransportError("connection reset"))
    with pytest.raises(ApiClientError, match="Could not get an access token"):
        list(_client(credentials).iter_rules())


def test_missing_token_after_refresh(http):
    credentials = FakeCredentials()
    credentials.refresh = lambda request: None
    with pytest.raises(ApiUnauthorizedError, match="no access token"):
        list(_client(credentials).iter_rules())


def test_rate_limit_honors_retry_after(http):
    sleep = MagicMock()
    http.get(
        RULES,
        [
            {"status_code": 429, "headers": {"Retry-After": "7"}},
            {"json": {"rules": [{"name": "r1"}]}},
        ],
    )
    assert len(list(_client(sleep=sleep).iter_rules())) == 1
    sleep.assert_called_once_with(7.0)


def test_rate_limit_gives_up(http):
    http.get(RULES, status_code=429)
    with pytest.raises(ApiRateLimitError):
        list(_client(max_retries=1).iter_rules())


def test_service_account_credentials(monkeypatch):
    calls = []

    def fake_from_info(info, scopes):
        calls.append((info, scopes))
        return "credentials"

    monkeypatch.setattr(
        api_client_module.service_account.Credentials,
        "from_service_account_info",
        fake_from_info,
    )
    assert (
        api_client_module.service_account_credentials(
            client_email="sa@p.iam.gserviceaccount.com",
            private_key="PEM",
            token_uri="https://oauth2.googleapis.com/token",
        )
        == "credentials"
    )
    ((info, scopes),) = calls
    assert info == {
        "type": "service_account",
        "client_email": "sa@p.iam.gserviceaccount.com",
        "private_key": "PEM",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    assert scopes == ["https://www.googleapis.com/auth/cloud-platform"]
