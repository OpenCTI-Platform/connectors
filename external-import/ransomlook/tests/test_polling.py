"""Offline regression tests for bounded repeat polling and source cooldowns."""

import json
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import MethodType
from unittest.mock import MagicMock
from urllib.parse import urlsplit

import connector.connector as coordinator
import pytest
import requests
from connector.api_client import RansomLookAPIClient
from pydantic import SecretStr

from .test_api_client import streaming_response
from .test_connector import make_connector


class Clock(datetime):
    current = datetime(2026, 11, 21, 12, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls.current if tz else cls.current.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def fixed_time(monkeypatch):
    Clock.current = datetime(2026, 11, 21, 12, tzinfo=timezone.utc)
    monkeypatch.setattr(coordinator, "datetime", Clock)


def run(
    state,
    row,
    calls,
    deliveries,
    *,
    fail=False,
    fail_profile=False,
    fail_cooldown_save=False,
    refusal=None,
    oneshot=False,
    detail="source detail",
    **options
):
    connector = make_connector(
        **(
            {
                "enrich_actor_profiles": True,
                "import_notes": False,
                "import_wallets": False,
                "import_infrastructure": False,
                "import_torrents": False,
                "import_leaks": False,
                "import_analyses": False,
                "import_post_evidence": False,
                "import_victim_websites": False,
            }
            | options
        )
    )
    connector.client.get_post = MethodType(
        RansomLookAPIClient.get_post, connector.client
    )
    connector.helper.get_state.side_effect = lambda: deepcopy(state)
    connector.helper.get_run_and_terminate.return_value = oneshot

    def save(value):
        if fail_cooldown_save and "source_cooldown" in value:
            raise ValueError("synthetic cooldown save failure")
        state.clear()
        state.update(deepcopy(value))

    connector.helper.set_state.side_effect = save
    connector._try_create_named_actor_profiles = lambda *_a, **_kw: ({}, True)

    def get(url, **kwargs):
        path = urlsplit(url).path.split("/api/", 1)[-1]
        calls[path] += 1
        if refusal and (
            path == refusal
            or (refusal == "posts403" and path == "posts")
            or (refusal == "core403" and path in {"group/akira", "post/akira"})
        ):
            status = 403 if refusal in {"core403", "posts403"} else 429
            result = streaming_response(
                {}, status=status, headers={"Retry-After": "600"}
            )
            result.raise_for_status.side_effect = requests.HTTPError(str(status))
            return result
        if path == "posts":
            params = kwargs["params"]
            payload = (
                [row]
                if params["from"] <= row["discovered"][:10] <= params["to"]
                else []
            )
        elif path == "group/akira":
            payload = [{"meta": "actor metadata"}, []]
        elif path == "post/akira":
            assert kwargs["params"] == {"title": row["post_title"]}
            payload = {"description": detail}
        else:
            raise AssertionError(path)
        calls["bytes:" + path] += len(json.dumps(payload).encode())
        return streaming_response(payload)

    connector.client.session.get = get

    def deliver(objects, name):
        if fail:
            raise RuntimeError("synthetic delivery failure")
        if fail_profile and name.startswith("RansomLook actor profile"):
            raise RuntimeError("synthetic profile failure")
        deliveries.append((name, objects))
        return None, 1

    connector._deliver_objects = deliver
    connector.process_message()
    return connector


def post():
    return {
        "id": "p1",
        "group_name": "akira",
        "post_title": "Victim / 1",
        "discovered": "2026-11-21T10:00:00Z",
    }


def test_loading_oversized_cache_does_not_consume_past_limit():
    connector = make_connector()
    connector.FETCH_CACHE_MAX_ENTRIES = 2

    class OversizedRecords(dict):
        def items(self):
            yield "a" * 64, {"at": "2026-11-21T11:00:00Z"}
            yield "b" * 64, {"at": "2026-11-21T11:01:00Z"}
            raise AssertionError("cache read beyond the configured limit")

    loaded = connector._load_fetch_cache(
        {"namespace": connector._cache_namespace(), "profiles": OversizedRecords()}
    )
    assert set(loaded["profiles"]) == {"a" * 64, "b" * 64}


@pytest.mark.parametrize(
    "offset, accepted",
    [
        (timedelta(minutes=5), True),
        (timedelta(minutes=5, microseconds=1), False),
    ],
)
def test_cache_future_skew_is_consistent_on_load_and_use(offset, accepted):
    connector = make_connector()
    record = {"at": (Clock.current + offset).isoformat()}
    loaded = connector._load_fetch_cache(
        {"namespace": connector._cache_namespace(), "profiles": {"a" * 64: record}}
    )
    assert ("a" * 64 in loaded["profiles"]) is accepted
    assert connector._cache_fresh(record, timedelta(hours=24)) is accepted


def test_cache_eviction_orders_normalized_utc_timestamps():
    connector = make_connector()
    connector.FETCH_CACHE_MAX_ENTRIES = 2
    connector._fetch_cache = connector._load_fetch_cache(
        {
            "namespace": connector._cache_namespace(),
            "profiles": {
                "a" * 64: {"at": "2026-11-21T11:00:00Z"},
                "b" * 64: {"at": "2026-11-21T07:00:01-04:00"},
            },
        }
    )
    assert connector._fetch_cache["profiles"]["a" * 64]["at"] == (
        "2026-11-21T11:00:00.000000+00:00"
    )
    assert connector._cache_fresh(
        connector._fetch_cache["profiles"]["a" * 64], timedelta(hours=24)
    )
    connector._working_state = {}
    connector._save_fetch_cache(
        "profiles", {"c" * 64: {"at": "2026-11-21T11:00:00.500000+00:00"}}
    )
    assert set(connector._fetch_cache["profiles"]) == {"b" * 64, "c" * 64}
    assert connector._fetch_cache["profiles"]["c" * 64]["at"] == (
        "2026-11-21T11:00:00.500000+00:00"
    )


def test_cache_update_normalizes_new_timestamps_before_eviction():
    connector = make_connector()
    connector.FETCH_CACHE_MAX_ENTRIES = 1
    connector._working_state = {}
    connector._save_fetch_cache("profiles", {"a" * 64: {"at": "2026-11-21T11:00:00Z"}})
    connector._save_fetch_cache(
        "profiles", {"b" * 64: {"at": "2026-11-21T06:00:01-05:00"}}
    )
    assert connector._fetch_cache["profiles"] == {
        "b" * 64: {"at": "2026-11-21T11:00:01.000000+00:00"}
    }


def test_cache_update_skips_malformed_receipts_and_keeps_valid_entries():
    connector = make_connector()
    connector._working_state = {}
    valid = {"at": "2026-11-21T11:00:00Z", "fingerprint": "f" * 64}
    connector._save_fetch_cache(
        "claims",
        {
            "a" * 64: valid,
            "b" * 64: {},
            "c" * 64: {"at": "invalid", "fingerprint": "f" * 64},
            "d" * 64: {"at": "0001-01-01T00:00:00+14:00", "fingerprint": "f" * 64},
            "e" * 64: {"at": valid["at"], "fingerprint": "invalid"},
            "f" * 64: None,
        },
    )

    assert connector._fetch_cache["claims"] == {
        "a" * 64: {"at": "2026-11-21T11:00:00.000000+00:00", "fingerprint": "f" * 64}
    }


@pytest.mark.parametrize("family", ["claims", "profiles"])
def test_cache_receipts_only_persist_allowed_fields(family):
    connector = make_connector()
    connector._working_state = {}
    receipt = {
        "at": "2026-11-21T11:00:00Z",
        "fingerprint": "f" * 64,
        "source": "sensitive payload",
        "metadata": {"nested": "sensitive payload"},
    }

    connector._save_fetch_cache(family, {"a" * 64: receipt})
    connector._save_state()

    saved = connector.helper.set_state.call_args.args[0]["fetch_cache"][family]
    expected = {"at": "2026-11-21T11:00:00.000000+00:00"}
    if family == "claims":
        expected["fingerprint"] = "f" * 64
    assert saved == {"a" * 64: expected}


def test_cache_bulk_eviction_keeps_earliest_inserted_when_timestamps_tie():
    connector = make_connector()
    connector.FETCH_CACHE_MAX_ENTRIES = 3
    connector._working_state = {}
    timestamp = "2026-11-21T10:00:00Z"
    connector._save_fetch_cache(
        "profiles", {key * 64: {"at": timestamp} for key in "abc"}
    )
    previous = connector._fetch_cache
    connector._save_fetch_cache(
        "profiles",
        {
            "d" * 64: {"at": "2026-11-21T11:00:00Z"},
            "e" * 64: {"at": "2026-11-21T12:00:00Z"},
        },
    )

    assert set(connector._fetch_cache["profiles"]) == {key * 64 for key in "ade"}
    assert set(previous["profiles"]) == {key * 64 for key in "abc"}


def test_cache_update_recovers_missing_family_and_discards_unbound_receipts():
    connector = make_connector()
    connector._working_state = {}
    connector._fetch_cache = {"profiles": {"a" * 64: {"at": "2026-11-21T11:00:00Z"}}}
    connector._save_fetch_cache("claims", {})
    assert connector._fetch_cache == {
        "namespace": connector._cache_namespace(),
        "claims": {},
        "profiles": {},
    }
    del connector._fetch_cache["profiles"]
    connector._save_fetch_cache("profiles", {"b" * 64: {"at": "2026-11-21T11:00:00Z"}})
    assert "b" * 64 in connector._fetch_cache["profiles"]


def test_corrupt_persisted_cache_families_are_replaced_before_update():
    connector = make_connector()
    connector._working_state = {}
    connector._fetch_cache = connector._load_fetch_cache(
        {
            "namespace": connector._cache_namespace(),
            "claims": ["invalid"],
            "profiles": "invalid",
        }
    )
    assert connector._fetch_cache["claims"] == {}
    assert connector._fetch_cache["profiles"] == {}

    connector._save_fetch_cache(
        "profiles", {"a" * 64: {"at": Clock.current.isoformat()}}
    )
    assert "a" * 64 in connector._fetch_cache["profiles"]


def test_cache_update_requires_initialized_working_state():
    connector = make_connector()
    with pytest.raises(RuntimeError, match="working state is not initialized"):
        connector._save_fetch_cache("profiles", {})
    assert connector._fetch_cache == {}


def test_cache_updates_preserve_prior_snapshots_and_other_family():
    connector = make_connector()
    connector._fetch_cache = connector._load_fetch_cache(
        {
            "namespace": connector._cache_namespace(),
            "claims": {
                "a" * 64: {"at": "2026-11-21T11:00:00Z", "fingerprint": "b" * 64}
            },
            "profiles": {"c" * 64: {"at": "2026-11-21T11:00:00Z"}},
        }
    )
    original = connector._fetch_cache
    connector._working_state = {}
    entries = {"d" * 64: {"at": "2026-11-21T11:30:00+00:00"}}
    connector._save_fetch_cache("profiles", entries)
    first_staged = connector._working_state["fetch_cache"]
    connector._save_fetch_cache(
        "profiles", {"e" * 64: {"at": "2026-11-21T11:45:00+00:00"}}
    )
    entries["d" * 64]["at"] = "changed by caller"
    assert set(original["profiles"]) == {"c" * 64}
    assert set(first_staged["profiles"]) == {"c" * 64, "d" * 64}
    assert first_staged["profiles"]["d" * 64]["at"] == (
        "2026-11-21T11:30:00.000000+00:00"
    )
    assert (
        connector._fetch_cache["profiles"]["d" * 64]["at"]
        == "2026-11-21T11:30:00.000000+00:00"
    )
    assert connector._fetch_cache["claims"] == original["claims"]


def test_cache_rejects_unknown_family():
    connector = make_connector()
    with pytest.raises(ValueError, match="Unknown RansomLook fetch-cache family"):
        connector._save_fetch_cache("unknown", {})


def test_failed_cache_persistence_does_not_mutate_saved_state():
    connector = make_connector()
    saved = {
        "claims": {"cursor": "original"},
        "enrichment": {},
        "fetch_cache": {
            "namespace": connector._cache_namespace(),
            "claims": {},
            "profiles": {},
        },
    }
    before = deepcopy(saved)
    connector._fetch_cache = connector._load_fetch_cache(saved["fetch_cache"])
    connector._working_state = deepcopy(saved)
    connector.helper.set_state.side_effect = RuntimeError("state save failed")
    connector._save_fetch_cache(
        "profiles", {"a" * 64: {"at": Clock.current.isoformat()}}
    )
    with pytest.raises(RuntimeError, match="state save failed"):
        connector._save_state()
    assert saved == before


def test_out_of_range_timestamp_is_a_cache_miss():
    connector = make_connector()
    invalid = {"at": "0001-01-01T00:00:00+14:00"}
    loaded = connector._load_fetch_cache(
        {
            "namespace": connector._cache_namespace(),
            "profiles": {"a" * 64: invalid},
        }
    )
    assert not loaded["profiles"]
    assert not connector._cache_fresh(invalid, timedelta(hours=24))


def test_successful_replay_skips_full_history_and_detail_until_changed_or_due():
    state, calls, delivered, row = {}, Counter(), [], post()
    run(state, row, calls, delivered)
    assert calls["group/akira"] == calls["post/akira"] == 1
    first_posts = calls["posts"]
    first_group_bytes = calls["bytes:group/akira"]
    first_detail_bytes = calls["bytes:post/akira"]
    run(state, row, calls, delivered)
    assert calls["group/akira"] == calls["post/akira"] == 1
    assert calls["posts"] == first_posts + 1
    assert calls["bytes:group/akira"] == first_group_bytes
    assert calls["bytes:post/akira"] == first_detail_bytes
    row["title_change"] = "updated index"
    run(state, row, calls, delivered)
    assert calls["post/akira"] == 2
    Clock.current += timedelta(hours=7)
    run(state, row, calls, delivered)
    assert calls["post/akira"] == 3
    Clock.current += timedelta(hours=18)
    run(state, row, calls, delivered)
    assert calls["group/akira"] == 4
    assert len(state["fetch_cache"]["claims"]) == 1
    assert len(state["fetch_cache"]["profiles"]) == 1
    assert "source detail" not in str(state["fetch_cache"])


def test_failed_claim_delivery_does_not_acknowledge_freshness():
    state, calls, delivered, row = {}, Counter(), [], post()
    with pytest.raises(RuntimeError, match="synthetic delivery failure"):
        run(state, row, calls, delivered, fail=True)
    assert not state.get("fetch_cache", {}).get("claims")
    run(state, row, calls, delivered)
    assert calls["post/akira"] == 2
    assert state["fetch_cache"]["claims"]


def test_trailing_replay_date_is_not_hidden_by_freshness():
    state, calls, delivered, row = {}, Counter(), [], post()
    row["discovered"] = "2026-11-20T12:00:00Z"
    Clock.current = datetime(2026, 11, 21, 23, tzinfo=timezone.utc)
    run(state, row, calls, delivered)
    Clock.current += timedelta(hours=1)
    run(state, row, calls, delivered, detail="changed detail")
    assert calls["post/akira"] == 2
    assert any(
        "changed detail" in obj.serialize() for _, batch in delivered for obj in batch
    )
    Clock.current += timedelta(hours=1)
    run(state, row, calls, delivered, detail="changed detail")
    assert calls["post/akira"] == 2


def test_zero_day_replay_keeps_same_day_claims_visible():
    state, calls, delivered, row = {}, Counter(), [], post()
    Clock.current = datetime(2026, 11, 21, 23, tzinfo=timezone.utc)
    run(state, row, calls, delivered, replay_window_days=0)
    run(state, row, calls, delivered, replay_window_days=0)
    assert calls["post/akira"] == 1
    Clock.current += timedelta(hours=1)
    run(state, row, calls, delivered, replay_window_days=0, detail="changed detail")
    assert calls["post/akira"] == 2
    assert any(
        "changed detail" in obj.serialize() for _, batch in delivered for obj in batch
    )


def test_failed_profile_delivery_remains_due_without_replaying_claim():
    state, calls, delivered, row = {}, Counter(), [], post()
    run(state, row, calls, delivered, fail_profile=True)
    assert state["fetch_cache"]["claims"]
    assert not state["fetch_cache"]["profiles"]
    run(state, row, calls, delivered)
    assert calls["group/akira"] == 2
    assert calls["post/akira"] == 1
    assert state["fetch_cache"]["profiles"]


def test_changed_policy_discards_only_disposable_freshness():
    state, calls, delivered, row = {}, Counter(), [], post()
    run(state, row, calls, delivered)
    first_namespace = state["fetch_cache"]["namespace"]
    run(state, row, calls, delivered, import_victim_websites=True)
    assert state["fetch_cache"]["namespace"] != first_namespace
    assert calls["post/akira"] == 2


def test_cache_namespace_is_computed_once_per_run(monkeypatch):
    original = coordinator.RansomLookConnector._cache_namespace
    count = []

    def counted(connector):
        count.append(1)
        return original(connector)

    monkeypatch.setattr(coordinator.RansomLookConnector, "_cache_namespace", counted)
    state, calls, delivered = {}, Counter(), []
    connector = run(state, post(), calls, delivered)
    first_namespace = state["fetch_cache"]["namespace"]
    assert len(count) == 1
    assert connector._run_cache_namespace is None
    connector.config.ransomlook.labels.append("changed-label")
    connector.process_message()
    assert len(count) == 2
    assert connector._run_cache_namespace is None
    assert state["fetch_cache"]["namespace"] != first_namespace
    assert calls["post/akira"] == 2


def test_changed_api_key_discards_freshness_without_storing_the_secret():
    state, calls, delivered, row = {}, Counter(), [], post()
    first_key = "ransomlook-test-api-key-one"
    second_key = "ransomlook-test-api-key-two"
    run(state, row, calls, delivered, api_key=SecretStr(first_key))
    namespace = state["fetch_cache"]["namespace"]

    run(state, row, calls, delivered, api_key=SecretStr(first_key))
    assert state["fetch_cache"]["namespace"] == namespace
    assert calls["post/akira"] == 1

    run(state, row, calls, delivered, api_key=SecretStr(second_key))
    assert state["fetch_cache"]["namespace"] != namespace
    assert calls["post/akira"] == 2
    assert first_key not in json.dumps(state)
    assert second_key not in json.dumps(state)

    run(state, row, calls, delivered, api_key=None)
    assert calls["post/akira"] == 3


def test_adding_api_key_discards_anonymous_freshness():
    state, calls, delivered, row = {}, Counter(), [], post()
    run(state, row, calls, delivered)
    namespace = state["fetch_cache"]["namespace"]
    run(state, row, calls, delivered, api_key=SecretStr("new-api-key"))

    assert state["fetch_cache"]["namespace"] != namespace
    assert calls["post/akira"] == 2


@pytest.mark.parametrize("refusal, status", [("posts403", 403), ("posts", 429)])
def test_clean_start_logs_first_source_refusal(refusal, status):
    state, calls, delivered = {}, Counter(), []
    connector = run(state, post(), calls, delivered, refusal=refusal)
    connector.helper.connector_logger.warning.assert_any_call(
        "RansomLook source is cooling down",
        meta={
            "retry_not_before": state["source_cooldown"]["retry_not_before"],
            "status_code": status,
            "endpoint": "posts",
            "retry_source": "retry_after",
            "request_attempts": 1,
            "cooldown_state": "staged",
        },
    )
    assert calls["posts"] == 1
    assert not delivered


@pytest.mark.parametrize(
    "payload, reason",
    [
        ({"posts": "private response content"}, "unexpected_response_shape"),
        ({"posts": [{"screen": []}]}, "invalid_capture_type"),
    ],
)
def test_invalid_first_posts_response_logs_safe_reason(payload, reason):
    from connector.api_client import RansomLookAPIError

    connector = make_connector()
    connector.client.session.get = lambda *_args, **_kwargs: streaming_response(payload)
    with pytest.raises(RansomLookAPIError):
        connector.process_message()
    connector.helper.connector_logger.error.assert_any_call(
        "RansomLook import failed",
        {"error_type": "RansomLookAPIError", "reason": reason},
    )


@pytest.mark.parametrize(
    "failure, code",
    [
        (requests.ConnectTimeout, "api.timeout"),
        (requests.ConnectionError, "api.connection"),
    ],
)
@pytest.mark.parametrize("request_budget", [1, 2000])
def test_recurring_source_failure_reports_error_and_schedules_retry(
    monkeypatch, failure, code, request_budget
):
    import connector.api_client as api_module
    from pycti import OpenCTIConnectorHelper
    from pycti.connector.opencti_connector_helper import ConnectorInfo

    monkeypatch.setattr(api_module.time, "sleep", lambda _delay: None)
    connector = make_connector()
    helper = connector.helper
    helper.connect_run_and_terminate = False
    helper.connector_info = ConnectorInfo()
    helper.check_connector_buffering.return_value = False
    helper.scheduler = MagicMock()
    helper.schedule_process = MethodType(
        OpenCTIConnectorHelper.schedule_process, helper
    )
    helper._run_and_collect_errors = MethodType(
        OpenCTIConnectorHelper._run_and_collect_errors, helper
    )
    helper._schedule_process = MethodType(
        OpenCTIConnectorHelper._schedule_process, helper
    )
    state = {"claims": {"last_successful_run": "2026-11-20T00:00:00+00:00"}}
    original = deepcopy(state)
    helper.get_state.side_effect = lambda: deepcopy(state)

    def save(value):
        state.clear()
        state.update(deepcopy(value))

    helper.set_state.side_effect = save
    connector.client._MAX_ATTEMPTS = 2
    connector.client.max_requests_per_run = request_budget
    connector.client.session.get = MagicMock(side_effect=failure("private URL"))

    connector.run()
    assert helper.scheduler.enter.call_count == 1
    assert helper.connector_info.errors[0]["code"] == code
    assert helper.connector_info.errors[0]["criticity"] == 40
    assert "private URL" not in repr(helper.connector_info.errors)
    assert state == original
    helper.set_state.assert_not_called()
    assert not helper.connector_logger.error.called

    connector.client.session.get = MagicMock(
        side_effect=lambda *_args, **_kwargs: streaming_response({"posts": []})
    )
    connector.client.max_requests_per_run = 2000
    helper._schedule_process(helper.scheduler, connector._scheduled_process, 3600.0)
    assert helper.connector_info.errors == []
    assert helper.scheduler.enter.call_count == 2
    assert (
        state["claims"]["last_successful_run"]
        != original["claims"]["last_successful_run"]
    )


def test_one_shot_source_timeout_still_raises(monkeypatch):
    import connector.api_client as api_module
    from connector.api_client import RansomLookTransportError

    monkeypatch.setattr(api_module.time, "sleep", lambda _delay: None)
    connector = make_connector()
    connector.helper.get_run_and_terminate.return_value = True
    connector.client._MAX_ATTEMPTS = 1
    connector.client.session.get = MagicMock(
        side_effect=requests.ConnectTimeout("timeout")
    )
    with pytest.raises(RansomLookTransportError):
        connector.process_message()
    connector.helper.set_state.assert_not_called()


def test_retry_deadline_after_timeout_reports_transport_failure(monkeypatch):
    import connector.api_client as api_module

    monkeypatch.setattr(api_module.time, "sleep", lambda _delay: None)
    connector = make_connector()
    connector.client.session.get = MagicMock(
        side_effect=requests.ConnectTimeout("timeout")
    )
    connector.client.remaining_seconds = MagicMock(side_effect=[10.0, 0.5])
    result = connector._scheduled_process()
    assert result == [
        {
            "code": "api.timeout",
            "message": "RansomLook source request timed out",
            "criticity": 40,
        }
    ]
    connector.helper.set_state.assert_not_called()


def test_non_transport_budget_failure_is_not_swallowed():
    from connector.api_client import RansomLookCycleBudgetExhausted

    connector = make_connector()
    connector.process_message = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("ordinary budget exhaustion")
    )
    with pytest.raises(RansomLookCycleBudgetExhausted):
        connector._scheduled_process()


@pytest.mark.parametrize(
    "failure", [requests.exceptions.SSLError, requests.exceptions.ProxyError]
)
@pytest.mark.parametrize("budget_first", [False, True])
def test_tls_and_proxy_errors_are_not_treated_as_transient_connection_failures(
    monkeypatch, failure, budget_first
):
    import connector.api_client as api_module
    from connector.api_client import RansomLookAPIError, RansomLookCycleBudgetExhausted

    monkeypatch.setattr(api_module.time, "sleep", lambda _delay: None)
    connector = make_connector()
    connector.client._MAX_ATTEMPTS = 2 if budget_first else 1
    connector.client.max_requests_per_run = 1 if budget_first else 2000
    connector.client.session.get = MagicMock(side_effect=failure("configuration error"))
    expected = RansomLookCycleBudgetExhausted if budget_first else RansomLookAPIError
    with pytest.raises(expected):
        connector._scheduled_process()
    connector.helper.set_state.assert_not_called()


def test_later_group_invalid_json_logs_same_safe_reason():
    connector = make_connector()
    connector.client.session.get = lambda *_args, **_kwargs: streaming_response(
        b"private response content"
    )
    assert connector._try_get_group_data("private-group") == ({}, [], False)
    message, meta = connector.helper.connector_logger.warning.call_args.args
    assert message.startswith("Unable to enrich RansomLook group")
    assert meta["reason"] == "invalid_json"
    connector.helper.connector_logger.debug.assert_any_call(
        "RansomLook response rejected",
        meta={
            "endpoint": "group",
            "error_type": "RansomLookAPIError",
            "reason": "invalid_json",
            "request_attempts": 1,
        },
    )
    assert "private" not in repr(meta)


def test_source_refusal_is_persisted_without_advancing_cursor():
    state, calls, delivered, row = {}, Counter(), [], post()
    connector = run(state, row, calls, delivered, refusal="group/akira")
    assert connector._run_cache_namespace is None
    # A 429 aborts before delivery; the cooldown is the only persisted progress.
    assert state["source_cooldown"]["retry_not_before"]
    connector.helper.connector_logger.warning.assert_any_call(
        "RansomLook source is cooling down",
        meta={
            "retry_not_before": state["source_cooldown"]["retry_not_before"],
            "status_code": 429,
            "endpoint": "group",
            "retry_source": "retry_after",
            "request_attempts": calls["posts"] + calls["group/akira"],
            "cooldown_state": "staged",
        },
    )
    assert not state.get("claims", {}).get("last_successful_run")
    before = calls.copy()
    saved_state = deepcopy(state)
    connector = run(state, row, calls, delivered)
    connector.helper.connector_logger.warning.assert_any_call(
        "RansomLook request skipped due to active cooldown",
        meta={
            "retry_not_before": state["source_cooldown"]["retry_not_before"],
            "status_code": None,
            "endpoint": None,
            "retry_source": "restored",
            "request_attempts": 0,
            "cooldown_state": "restored",
        },
    )
    assert calls == before
    assert state == saved_state
    connector.helper.set_state.assert_not_called()
    assert not delivered


def test_restored_cooldown_resets_metrics_on_same_connector():
    state, calls, delivered = {}, Counter(), []
    connector = run(state, post(), calls, delivered, refusal="posts")
    assert connector.client.request_attempts == 1
    connector.metrics.fetched_posts = 17
    before = calls.copy()
    connector.process_message()
    assert calls == before
    assert connector.client.request_attempts == 0
    metric_call = connector.helper.connector_logger.info.call_args_list[-1]
    assert metric_call.args[0] == "RansomLook run metrics"
    assert metric_call.args[1]["request_attempts"] == 0
    assert metric_call.args[1]["posts_fetched"] == 0


def test_first_run_honors_persisted_cooldown_without_network_or_state_changes():
    probe = make_connector()
    state = {
        "source_cooldown": {
            "source_key": probe.client.source_key,
            "retry_not_before": (
                datetime.now(timezone.utc) + timedelta(hours=1)
            ).isoformat(),
        },
        "unrelated_checkpoint": "preserved",
    }
    saved_state = deepcopy(state)
    calls, delivered = Counter(), []

    connector = run(state, post(), calls, delivered)

    assert not calls
    assert not delivered
    assert state == saved_state
    connector.helper.set_state.assert_not_called()
    connector.helper.connector_logger.warning.assert_any_call(
        "RansomLook request skipped due to active cooldown",
        meta={
            "retry_not_before": state["source_cooldown"]["retry_not_before"],
            "status_code": None,
            "endpoint": None,
            "retry_source": "restored",
            "request_attempts": 0,
            "cooldown_state": "restored",
        },
    )


@pytest.mark.parametrize("kind", ["expired", "invalid", "other_source"])
def test_inactive_cooldown_is_removed_on_normal_state_save(kind):
    probe = make_connector()
    cooldown = {
        "source_key": probe.client.source_key,
        "retry_not_before": (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat(),
    }
    if kind == "invalid":
        cooldown["retry_not_before"] = "invalid"
    elif kind == "other_source":
        cooldown["source_key"] = "another source"
    state = {"source_cooldown": cooldown, "unrelated_checkpoint": "preserved"}
    calls, delivered = Counter(), []

    run(state, post(), calls, delivered)

    assert calls["posts"] > 0
    assert "source_cooldown" not in state
    assert state["unrelated_checkpoint"] == "preserved"


def test_new_refusal_replaces_expired_cooldown():
    probe = make_connector()
    old_deadline = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    state = {
        "source_cooldown": {
            "source_key": probe.client.source_key,
            "retry_not_before": old_deadline,
        }
    }
    calls, delivered = Counter(), []

    run(state, post(), calls, delivered, refusal="posts")

    assert calls["posts"] == 1
    assert state["source_cooldown"]["source_key"] == probe.client.source_key
    assert state["source_cooldown"]["retry_not_before"] != old_deadline
    assert not delivered


def test_repeated_core_403_stops_before_cursor_commit():
    state, calls, delivered, row = {}, Counter(), [], post()
    run(state, row, calls, delivered, refusal="core403")
    assert calls["group/akira"] == calls["post/akira"] == 1
    assert state["source_cooldown"]["retry_not_before"]
    assert not state.get("claims", {}).get("last_successful_run")
    before = calls.copy()
    run(state, row, calls, delivered)
    assert calls == before
    assert not delivered


def test_profile_429_stops_cycle_and_one_shot_reports_failure():
    from connector.api_client import RansomLookSourceDeferred

    state, calls, delivered, row = {}, Counter(), [], post()
    with pytest.raises(RansomLookSourceDeferred) as error:
        run(
            state,
            row,
            calls,
            delivered,
            refusal="notes/group/akira",
            oneshot=True,
            import_notes=True,
        )
    assert calls["notes/group/akira"] == 1
    assert state["source_cooldown"]["retry_not_before"]
    assert state["source_cooldown"]["retry_not_before"] in str(error.value)
    assert not state.get("claims", {}).get("last_successful_run")
    assert not delivered


def test_failed_cooldown_persistence_aborts_optional_enrichment():
    from connector.api_client import RansomLookCooldownPersistenceError

    state, calls, delivered = {}, Counter(), []
    with pytest.raises(RansomLookCooldownPersistenceError) as error:
        run(
            state,
            post(),
            calls,
            delivered,
            refusal="notes/group/akira",
            import_notes=True,
            fail_cooldown_save=True,
        )
    assert isinstance(error.value.__cause__, ValueError)
    assert calls["notes/group/akira"] == 1
    assert not state.get("claims", {}).get("last_successful_run")
    assert not delivered
