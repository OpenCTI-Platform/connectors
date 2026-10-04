"""Tests of the CrowdStrike client: OAuth2, pagination, rate limits, errors."""

import time
from unittest.mock import MagicMock

import pytest
import requests_mock as requests_mock_module
from connectors_sdk import (
    ApiClientError,
    ApiForbiddenError,
    ApiRateLimitError,
    ApiUnauthorizedError,
)
from crowdstrike_client import CrowdStrikeIoaClient

API = "https://api.eu-1.crowdstrike.com"
TOKEN = f"{API}/oauth2/token"
QUERY = f"{API}/ioarules/queries/rule-groups/v1"
ENTITIES = f"{API}/ioarules/entities/rule-groups/v1"
POLICIES = f"{API}/policy/combined/prevention/v1"


def _client(sleep=None, **kwargs) -> CrowdStrikeIoaClient:
    return CrowdStrikeIoaClient(
        API + "/",
        "falcon-client",
        "falcon-secret",
        logger=MagicMock(),
        sleep=sleep or MagicMock(),
        **kwargs,
    )


def _ids_page(ids, total):
    return {
        "meta": {"pagination": {"offset": 0, "limit": 2, "total": total}},
        "resources": ids,
        "errors": [],
    }


@pytest.fixture
def http():
    with requests_mock_module.Mocker() as mocker:
        mocker.post(
            TOKEN,
            status_code=201,
            json={"access_token": "token-1", "expires_in": 1799},
        )
        yield mocker


def test_rule_groups_are_paged_then_fetched(http):
    http.get(
        QUERY,
        [{"json": _ids_page(["g1", "g2"], 3)}, {"json": _ids_page(["g3"], 3)}],
    )
    http.get(
        ENTITIES,
        json={"resources": [{"id": "g1"}, {"id": "g2"}, {"id": "g3"}], "errors": []},
    )
    groups = list(_client(page_size=2).iter_rule_groups("platform:'windows'"))
    assert [g["id"] for g in groups] == ["g1", "g2", "g3"]

    token_request = http.request_history[0]
    assert token_request.method == "POST"
    assert "client_id=falcon-client" in token_request.text
    first_page, second_page, entities = http.request_history[1:]
    assert first_page.qs == {
        "offset": ["0"],
        "limit": ["2"],
        "filter": ["platform:'windows'"],
    }
    assert second_page.qs["offset"] == ["2"]
    assert entities.qs["ids"] == ["g1", "g2", "g3"]
    assert entities.headers["Authorization"] == "Bearer token-1"


def test_member_cid_is_sent_for_child_tenants(http):
    http.get(QUERY, json=_ids_page([], 0))
    assert list(_client(member_cid="child-cid").iter_rule_groups()) == []
    assert "member_cid=child-cid" in http.request_history[0].text


def test_empty_rule_group_page_before_the_total_fails_the_listing(http):
    http.get(
        QUERY,
        [{"json": _ids_page(["g1", "g2"], 5)}, {"json": _ids_page([], 5)}],
    )
    with pytest.raises(ApiClientError, match="rule groups at offset 2 of 5"):
        list(_client(page_size=2).iter_rule_groups())
    assert http.call_count == 3


def test_rate_limit_waits_until_the_announced_time(http, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1_000.0)
    sleep = MagicMock()
    http.get(
        QUERY,
        [
            {"status_code": 429, "headers": {"X-RateLimit-RetryAfter": "1009"}},
            {"json": _ids_page([], 0)},
        ],
    )
    list(_client(sleep=sleep).iter_rule_groups())
    sleep.assert_called_once_with(9.0)


def test_rate_limit_gives_up(http):
    http.get(QUERY, status_code=429, headers={"X-RateLimit-RetryAfter": "bad"})
    with pytest.raises(ApiRateLimitError):
        list(_client(max_retries=1).iter_rule_groups())


def test_revoked_token_is_renewed_once(http):
    http.post(
        TOKEN,
        [
            {
                "status_code": 201,
                "json": {"access_token": "token-1", "expires_in": 1799},
            },
            {
                "status_code": 201,
                "json": {"access_token": "token-2", "expires_in": 1799},
            },
        ],
    )
    http.get(QUERY, [{"status_code": 401}, {"json": _ids_page([], 0)}])
    list(_client().iter_rule_groups())
    assert http.request_history[-1].headers["Authorization"] == "Bearer token-2"


def test_bad_credentials(http):
    http.post(TOKEN, status_code=401, json={"errors": [{"code": 401}]})
    with pytest.raises(ApiUnauthorizedError):
        list(_client().iter_rule_groups())


def test_api_errors_in_the_payload(http):
    http.get(
        QUERY,
        json={"resources": [], "errors": [{"code": 500, "message": "boom"}]},
    )
    with pytest.raises(ApiClientError, match="CrowdStrike API errors"):
        list(_client().iter_rule_groups())


def test_unexpected_payload(http):
    http.get(QUERY, json={"resources": "nope"})
    with pytest.raises(ApiClientError, match="Unexpected response"):
        list(_client().iter_rule_groups())


def _policies_page(policies, total):
    return {
        "meta": {"pagination": {"offset": 0, "limit": 500, "total": total}},
        "resources": policies,
        "errors": [],
    }


def test_enforced_rule_groups_come_from_enabled_prevention_policies(http):
    http.get(
        POLICIES,
        [
            {
                "json": _policies_page(
                    [
                        {
                            "id": "p1",
                            "enabled": True,
                            "ioa_rule_groups": [{"id": "g1"}, {"id": "g2"}],
                        },
                        {
                            "id": "p2",
                            "enabled": False,
                            "ioa_rule_groups": [{"id": "g3"}],
                        },
                    ],
                    3,
                )
            },
            {
                "json": _policies_page(
                    [{"id": "p3", "enabled": True, "ioa_rule_groups": None}], 3
                )
            },
        ],
    )
    assert _client().enforced_rule_group_ids() == {"g1", "g2"}
    first_page, second_page = http.request_history[1:]
    assert first_page.qs == {"offset": ["0"], "limit": ["500"]}
    assert second_page.qs["offset"] == ["2"]


def test_empty_policy_page_before_the_total_fails_the_listing(http):
    http.get(
        POLICIES,
        [
            {"json": _policies_page([{"id": "p1", "enabled": True}], 4)},
            {"json": _policies_page([], 4)},
        ],
    )
    with pytest.raises(ApiClientError, match="prevention policies at offset 1 of 4"):
        _client().enforced_rule_group_ids()


def test_policy_pages_count_every_returned_entry(http):
    http.get(
        POLICIES,
        [
            {"json": _policies_page(["not-a-policy"], 2)},
            {
                "json": _policies_page(
                    [{"id": "p1", "enabled": True, "ioa_rule_groups": [{"id": "g1"}]}],
                    2,
                )
            },
        ],
    )
    assert _client().enforced_rule_group_ids() == {"g1"}
    assert http.request_history[-1].qs["offset"] == ["1"]


def test_prevention_policies_need_their_scope(http):
    http.get(POLICIES, status_code=403, json={"errors": [{"code": 403}]})
    with pytest.raises(ApiForbiddenError):
        _client().enforced_rule_group_ids()
