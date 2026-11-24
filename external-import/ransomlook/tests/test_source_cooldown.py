"""Offline controls for source refusal and post routing."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import connector.api_client as module
import pytest
import requests


def response(status, body=b"{}", headers=None):
    value = MagicMock(spec=requests.Response)
    value.status_code = status
    value.headers = headers or {}
    value.iter_content.return_value = [body]
    if status >= 400:
        value.raise_for_status.side_effect = requests.HTTPError("rejected")
    return value


def client():
    return module.RansomLookAPIClient(MagicMock(), "https://example.test/api")


def test_post_title_is_query_parameter():
    c = client()
    c._get = MagicMock(return_value={})
    assert c.get_post("space group", "victim/name") == {}
    c._get.assert_called_once_with(
        "post/space%20group",
        params={"title": "victim/name"},
        allow_404=True,
        log_errors=False,
    )


def test_429_persists_and_stops_subsequent_network():
    c = client()
    saved = []
    c.on_cooldown = saved.append
    reply = response(429, headers={"Retry-After": "600"})
    c.session.get = MagicMock(return_value=reply)
    with pytest.raises(module.RansomLookSourceDeferred) as first:
        c._get("posts")
    assert first.value.status_code == 429
    assert first.value.endpoint == "posts"
    assert first.value.retry_source == "retry_after"
    assert c.request_attempts == 1 and len(saved) == 1
    assert set(saved[0]) == {"source_key", "retry_not_before"}
    c.helper.connector_logger.debug.assert_any_call(
        "RansomLook request received an error response",
        meta={"endpoint": "posts", "status_code": 429, "request_attempts": 1},
    )
    reply.close.assert_called_once()
    other = client()
    other.restore_cooldown(saved[0])
    other.session.get = MagicMock()
    with pytest.raises(module.RansomLookSourceDeferred) as restored:
        other._get("posts")
    assert str(first.value) == str(restored.value)
    assert saved[0]["retry_not_before"] in str(restored.value)
    other.session.get.assert_not_called()
    other.retry_not_before = datetime.now(timezone.utc) - timedelta(seconds=1)
    other.session.get.return_value = response(200)
    assert other._get("posts") == {}


def test_torrent_429_reports_standardized_category():
    c = client()
    c.session.get = MagicMock(return_value=response(429))
    with pytest.raises(module.RansomLookSourceDeferred) as deferred:
        c.get_torrents()
    assert deferred.value.endpoint == "torrents"
    c.helper.connector_logger.debug.assert_any_call(
        "RansomLook request received an error response",
        meta={"endpoint": "torrents", "status_code": 429, "request_attempts": 1},
    )


def test_restored_utc_z_cooldown_blocks_requests():
    c = client()
    deadline = datetime.now(timezone.utc) + timedelta(minutes=5)
    c.restore_cooldown(
        {
            "source_key": c.source_key,
            "retry_not_before": deadline.isoformat().replace("+00:00", "Z"),
        }
    )
    assert c.retry_not_before == deadline
    c.session.get = MagicMock()
    with pytest.raises(module.RansomLookSourceDeferred) as deferred:
        c._get("posts")
    assert deferred.value.retry_source == "restored"
    c.session.get.assert_not_called()


def test_restore_utc_z_with_parser_that_requires_explicit_offset(monkeypatch):
    class OlderDatetime(datetime):
        @classmethod
        def fromisoformat(cls, value):
            if value.endswith("Z"):
                raise ValueError("Z suffix unsupported")
            return super().fromisoformat(value)

    c = client()
    deadline = datetime.now(timezone.utc) + timedelta(minutes=5)
    monkeypatch.setattr(module, "datetime", OlderDatetime)
    c.restore_cooldown(
        {
            "source_key": c.source_key,
            "retry_not_before": deadline.isoformat().replace("+00:00", "Z"),
        }
    )
    c.session.get = MagicMock()
    with pytest.raises(module.RansomLookSourceDeferred):
        c._get("posts")
    assert c.retry_not_before == deadline
    c.session.get.assert_not_called()


def test_restore_cooldown_rejects_timestamp_without_timezone():
    c = client()
    c.restore_cooldown(
        {"source_key": c.source_key, "retry_not_before": "2026-11-21T12:00:00"}
    )
    assert c.retry_not_before is None


def test_retry_after_http_date_and_source_binding():
    c = client()
    future = datetime.now(timezone.utc) + timedelta(minutes=5)
    from email.utils import format_datetime

    c.session.get = MagicMock(
        return_value=response(
            429, headers={"Retry-After": format_datetime(future, usegmt=True)}
        )
    )
    with pytest.raises(module.RansomLookSourceDeferred) as deferred:
        c._get("posts")
    assert deferred.value.status_code == 429
    assert deferred.value.endpoint == "posts"
    assert deferred.value.retry_source == "retry_after"
    assert c.retry_not_before >= future.replace(microsecond=0)
    other = module.RansomLookAPIClient(MagicMock(), "https://different.test/api")
    other.restore_cooldown(c.export_cooldown())
    assert other.retry_not_before is None


@pytest.mark.parametrize(
    "retry_after", [None, "invalid", "-1", "Sat, 21 Nov 2026 12:00:00"]
)
def test_invalid_or_missing_retry_after_uses_one_hour_cooldown(
    monkeypatch, retry_after
):
    class Clock(datetime):
        current = datetime(2026, 11, 21, 12, tzinfo=timezone.utc)

        @classmethod
        def now(cls, tz=None):
            return cls.current if tz else cls.current.replace(tzinfo=None)

    monkeypatch.setattr(module, "datetime", Clock)
    c = client()
    saved = []
    c.on_cooldown = saved.append
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    c.session.get = MagicMock(
        side_effect=[response(429, headers=headers), response(200)]
    )
    with pytest.raises(module.RansomLookSourceDeferred) as deferred:
        c._get("posts")
    assert deferred.value.retry_source == "default"
    assert c.retry_not_before == Clock.current + timedelta(hours=1)
    assert saved[0]["retry_not_before"] == c.retry_not_before.isoformat()
    with pytest.raises(module.RansomLookSourceDeferred):
        c._get("posts")
    assert c.session.get.call_count == 1
    Clock.current += timedelta(hours=1)
    assert c._get("posts") == {}
    assert c.session.get.call_count == 2


def test_distinct_core_403_stops_but_optional_403_does_not():
    c = client()
    c.session.get = MagicMock(return_value=response(403))
    with pytest.raises(module.RansomLookCapabilityUnavailable):
        c._get("actors/", optional_capability="actors")
    assert not c._denied_resources
    with pytest.raises(module.RansomLookAPIError):
        c._get("post/g", params={"title": "one"})
    assert c.retry_not_before is None
    with pytest.raises(module.RansomLookAPIError):
        c._get("post/g", params={"title": "one"})
    assert c.retry_not_before is None
    with pytest.raises(module.RansomLookSourceDeferred):
        c._get("post/g", params={"title": "two"})
    assert c.request_attempts == 4


def test_core_403_normalizes_leading_slashes_before_counting():
    c = client()
    c.session.get = MagicMock(return_value=response(403))
    for path in ("post/g", "/post/g"):
        with pytest.raises(module.RansomLookAPIError):
            c._get(path, params={"title": "one"})
    assert c.retry_not_before is None
    assert len(c._denied_resources) == 1
    with pytest.raises(module.RansomLookSourceDeferred):
        c._get("post/g", params={"title": "two"})


def test_posts_index_403_persists_cooldown_before_another_request():
    c = client()
    saved = []
    c.on_cooldown = saved.append
    reply = response(403, headers={"Retry-After": "600"})
    c.session.get = MagicMock(return_value=reply)
    with pytest.raises(module.RansomLookSourceDeferred) as deferred:
        c._get("posts")
    assert deferred.value.status_code == 403
    assert deferred.value.endpoint == "posts"
    assert deferred.value.retry_source == "retry_after"
    assert len(saved) == 1
    c.helper.connector_logger.debug.assert_any_call(
        "RansomLook request received an error response",
        meta={"endpoint": "posts", "status_code": 403, "request_attempts": 1},
    )
    assert saved[0]["retry_not_before"] == c.retry_not_before.isoformat()
    reply.close.assert_called_once()
    with pytest.raises(module.RansomLookSourceDeferred):
        c._get("post/g", params={"title": "one"})
    assert c.session.get.call_count == 1
    assert c.request_attempts == 1


def test_cooldown_diagnostics_do_not_expose_unknown_paths():
    c = client()
    c.session.get = MagicMock(return_value=response(429))
    with pytest.raises(module.RansomLookSourceDeferred) as deferred:
        c._get("sensitive-identifier/path", params={"title": "private"})
    assert deferred.value.endpoint == "other"
    assert deferred.value.retry_source == "default"


def test_failed_cooldown_staging_still_logs_source_status():
    c = client()
    c.helper.connector_logger = MagicMock(
        spec_set=["debug", "info", "warning", "error"]
    )
    c.on_cooldown = MagicMock(side_effect=RuntimeError("save failed"))
    c.session.get = MagicMock(return_value=response(403))
    with pytest.raises(module.RansomLookCooldownPersistenceError):
        c._get("posts")
    c.helper.connector_logger.error.assert_called_once_with(
        "Unable to stage RansomLook source cooldown",
        meta={
            "status_code": 403,
            "endpoint": "posts",
            "retry_not_before": c.retry_not_before.isoformat(),
            "retry_source": "default",
            "request_attempts": 1,
        },
    )


@pytest.mark.parametrize(
    "path, log_errors, endpoint",
    [("posts", True, "posts"), ("private-path", False, "other")],
)
def test_timeout_log_survives_request_budget_exhaustion(
    monkeypatch, path, log_errors, endpoint
):
    c = module.RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_requests_per_run=2
    )
    monkeypatch.setattr(module.time, "sleep", lambda _delay: None)
    c.session.get = MagicMock(
        side_effect=requests.ConnectTimeout("private exception detail")
    )
    with pytest.raises(module.RansomLookCycleBudgetExhausted):
        c._get(path, params={"title": "private-value"}, log_errors=log_errors)
    log = (
        c.helper.connector_logger.warning
        if log_errors
        else c.helper.connector_logger.debug
    )
    for attempt in (1, 2):
        log.assert_any_call(
            "RansomLook request attempt failed",
            meta={
                "endpoint": endpoint,
                "status_code": None,
                "error_type": "ConnectTimeout",
                "request_attempts": attempt,
            },
        )
    logs = repr(log.call_args_list)
    assert "private" not in logs


def test_falsey_http_error_response_keeps_status_in_debug_log(monkeypatch):
    c = module.RansomLookAPIClient(
        MagicMock(), "https://example.test/api", max_requests_per_run=1
    )
    monkeypatch.setattr(module.time, "sleep", lambda _delay: None)
    reply = requests.Response()
    reply.status_code = 503
    reply._content = b""
    reply._content_consumed = True
    c.session.get = MagicMock(return_value=reply)
    with pytest.raises(module.RansomLookCycleBudgetExhausted) as budget:
        c._get("posts")
    assert budget.value.transport_reason is None
    c.helper.connector_logger.warning.assert_any_call(
        "RansomLook request attempt failed",
        meta={
            "endpoint": "posts",
            "status_code": 503,
            "error_type": "HTTPError",
            "request_attempts": 1,
        },
    )


def test_initial_and_later_http_errors_use_same_diagnostic(monkeypatch):
    c = client()
    monkeypatch.setattr(module.time, "sleep", lambda _delay: None)
    c.session.get = MagicMock(side_effect=[response(503), response(200), response(429)])
    assert c._get("posts") == {}
    with pytest.raises(module.RansomLookSourceDeferred):
        c._get("posts")
    for status, attempt in ((503, 1), (429, 3)):
        c.helper.connector_logger.debug.assert_any_call(
            "RansomLook request received an error response",
            meta={
                "endpoint": "posts",
                "status_code": status,
                "request_attempts": attempt,
            },
        )


def test_invalid_json_logs_safe_reason():
    c = client()
    c.session.get = MagicMock(return_value=response(200, body=b"private invalid JSON"))
    with pytest.raises(module.RansomLookAPIError, match="invalid JSON"):
        c._get("posts")
    message, meta = c.helper.connector_logger.error.call_args.args
    assert message == "RansomLook API response rejected"
    assert meta["reason"] == "invalid_json"
    assert "private" not in repr(meta)
