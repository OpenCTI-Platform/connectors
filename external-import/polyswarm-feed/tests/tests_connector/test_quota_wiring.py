"""Tests for the account quota reader in the feed connector and its client."""

from unittest.mock import MagicMock

import pytest
from conftest import make_sample_bundle, make_settings
from connector import PolySwarmFeedConnector
from connectors_sdk import ApiRateLimitError, ApiServerError
from polyswarm_client import PolySwarmAccountClient
from test_connector import FakeHelper, FakeTaxiiClient, page
from test_hunting_client import FAKE_KEY, _FakeApi
from test_quota import _account, _feature


def _quota_api(limit=500, remaining=0, **kwargs):
    api = MagicMock()
    api.account_features.return_value = _account(
        limit=limit, remaining=remaining, **kwargs
    )
    return api


def build(fake_logger, pages, quota_api, **overrides):
    settings = make_settings(**overrides)
    helper = FakeHelper(fake_logger)
    connector = PolySwarmFeedConnector(
        settings,
        helper,
        taxii_client=FakeTaxiiClient(pages),
        account_client=quota_api,
    )
    return connector, helper


def test_each_run_logs_the_plan_and_quota(fake_logger):
    api = _quota_api(
        limit=1000, remaining=640, features=[_feature("sandbox_request", 500, 300)]
    )
    connector, _ = build(
        fake_logger, {"trustgroup": [page(make_sample_bundle(1))]}, api
    )

    connector.process_message()

    quota_lines = [m for m in fake_logger.messages("info") if m.startswith("[QUOTA]")]
    assert len(quota_lines) == 1
    assert "plan Example Plan" in quota_lines[0]
    assert "daily API calls remaining 640 of 1000" in quota_lines[0]
    assert "sandbox_request: 300 of 500 remaining" in quota_lines[0]
    assert "000000000000" not in quota_lines[0]


def test_hourly_runs_each_read_the_quota_once(fake_logger):
    api = _quota_api()
    connector, _ = build(fake_logger, {}, api)
    clock = [1000.0]
    connector.quota._clock = lambda: clock[0]
    connector.process_message()
    connector.process_message()
    assert api.account_features.call_count == 1
    # The next scheduled run (PT1H) reads it again
    clock[0] += 3600
    connector.process_message()
    assert api.account_features.call_count == 2


def test_warns_below_the_threshold_and_not_when_turned_off(fake_logger):
    connector, _ = build(fake_logger, {}, _quota_api(limit=1000, remaining=40))
    connector.process_message()
    assert any("below 100" in m for m in fake_logger.messages("warning"))


def test_warnings_off_with_zero(fake_logger):
    connector, _ = build(
        fake_logger, {}, _quota_api(limit=1000, remaining=40), quota_warn_below=0
    )
    connector.process_message()
    assert not any("below" in m for m in fake_logger.messages("warning"))


def test_unreadable_quota_never_stops_the_import(fake_logger):
    api = MagicMock()
    api.account_features.side_effect = ApiServerError("boom", status_code=500)
    pages = {"trustgroup": [page(make_sample_bundle(1), last="T1")]}
    connector, helper = build(fake_logger, pages, api)

    connector.process_message()

    assert len(helper.bundles) == 1
    assert helper.stored_state["collections"]["trustgroup"]["added_after"] == "T1"
    assert any(
        "Could not read the account plan and quota" in m
        for m in fake_logger.messages("warning")
    )


def test_quota_failure_shows_remaining_quota_in_work_message_and_log(fake_logger):
    api = _quota_api(limit=500, remaining=0)
    pages = {
        "trustgroup": [
            page(make_sample_bundle(1), more=True, next_token="n1", last="T1"),
            # A rejected next token is retried once from added_after
            ApiRateLimitError("Rate limited (429) on GET /v3/stix/trustgroup/x"),
            ApiRateLimitError("Rate limited (429) on GET /v3/stix/trustgroup/x"),
        ]
    }
    connector, helper = build(fake_logger, pages, api)

    connector.process_message()

    failed = helper.processed()[0]
    assert failed[-1] == {"in_error": True}
    assert "quota exhausted or rate limited (HTTP 429)" in failed[1]
    assert "daily API calls remaining 0 of 500" in failed[1]
    assert "usage window ends 2026-12-01T00:00:00+00:00" in failed[1]
    logged = [meta for lvl, _, meta in fake_logger.records if lvl == "error"]
    assert "daily API calls remaining 0 of 500" in logged[0]["error"]
    # Progress up to the last sent page is kept
    assert helper.stored_state["collections"]["trustgroup"]["next_token"] == "n1"


def test_quota_failure_with_unreadable_quota_says_so(fake_logger):
    api = MagicMock()
    api.account_features.side_effect = ConnectionError("down")
    pages = {"trustgroup": [ApiRateLimitError("Rate limited (429)")]}
    connector, helper = build(fake_logger, pages, api)

    connector.process_message()

    errors = [meta["error"] for lvl, _, meta in fake_logger.records if lvl == "error"]
    assert "remaining quota could not be read" in errors[0]


def test_other_failures_are_reported_unchanged(fake_logger):
    api = _quota_api()
    pages = {
        "trustgroup": [
            page(make_sample_bundle(1), more=True, next_token="n1", last="T1"),
            ApiServerError("boom", status_code=500),
            ApiServerError("boom", status_code=500),
        ]
    }
    connector, helper = build(fake_logger, pages, api)

    connector.process_message()

    assert helper.processed()[0][1] == "PolySwarm feed trustgroup failed: boom"


# -- Account client ---------------------------------------------------------


@pytest.fixture
def server():
    fake = _FakeApi()
    yield fake
    fake.close()


def _result(**extra):
    body = {
        "account_number": "000000000000",
        "user_account_number": "000000000001",
        "account_plan_name": "Example Plan",
        "plan_period_start": "2026-01-01T00:00:00+00:00",
        "plan_period_end": "2027-01-01T00:00:00+00:00",
        "window_start": "2026-11-01T00:00:00+00:00",
        "window_end": "2026-12-01T00:00:00+00:00",
        "daily_api_limit": 0,
        "daily_api_remaining": 0,
        "has_stream_access": True,
        "is_trial": False,
        "is_trial_expired": False,
        "features": [
            {
                "base_uses": 0,
                "name": "Sandbox Artifacts",
                "remaining_uses": 0,
                "tag": "sandbox_request",
                "value": True,
                "overage": 0,
                "backing_feature": None,
            }
        ],
    }
    body.update(extra)
    return {"result": body}


def test_account_client_reads_the_plan_with_the_raw_key(server):
    server.reply(200, _result())
    client = PolySwarmAccountClient(server.url, FAKE_KEY, backoff_factor=0, timeout=5)

    account = client.account_features()

    assert server.requests[0]["path"] == "/v3/public/accounts"
    assert server.requests[0]["authorization"] == FAKE_KEY
    assert account.account_plan_name == "Example Plan"
    assert account.daily_api_limit == 0
    assert account.features[0]["tag"] == "sandbox_request"


def test_account_client_drops_the_account_number(server):
    server.reply(200, _result())
    client = PolySwarmAccountClient(server.url, FAKE_KEY, backoff_factor=0, timeout=5)
    account = client.account_features()
    assert "000000000000" not in repr(vars(account))
    assert "000000000001" not in repr(vars(account))


def test_account_client_rejects_an_unexpected_body(server):
    server.reply(200, {"status": "OK"})
    client = PolySwarmAccountClient(server.url, FAKE_KEY, backoff_factor=0, timeout=5)
    with pytest.raises(Exception, match="Unexpected account response"):
        client.account_features()


def test_account_client_surfaces_a_429(server):
    server.reply(429, {"result": "limit"})
    client = PolySwarmAccountClient(
        server.url, FAKE_KEY, max_retries=0, backoff_factor=0, timeout=5
    )
    with pytest.raises(ApiRateLimitError):
        client.account_features()


def test_account_client_needs_a_key():
    with pytest.raises(ValueError):
        PolySwarmAccountClient("http://127.0.0.1:9", "")


def test_quota_settings_default_and_validation():
    assert make_settings().polyswarm.quota_warn_below == 100
    assert make_settings(quota_warn_below=0).polyswarm.quota_warn_below == 0
    with pytest.raises(Exception):
        make_settings(quota_warn_below=-1)
