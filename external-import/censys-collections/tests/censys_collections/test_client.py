"""Tests for censys_collections.client."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from censys_collections.client import _RETRY_CONFIG, Client
from censys_platform import AssetChangeTypes, ChangeTypes


def test_client_default_timeout() -> None:
    client = Client(organisation_id="org", token="tok")
    assert client._timeout_ms == 60_000


def test_client_custom_timeout() -> None:
    client = Client(organisation_id="org", token="tok", request_timeout_seconds=30)
    assert client._timeout_ms == 30_000


def test_new_sdk_configures_timeout_and_retries() -> None:
    client = Client(organisation_id="org", token="tok", request_timeout_seconds=45)
    with client._new_sdk() as sdk:
        assert sdk.sdk_configuration.timeout_ms == 45_000
        assert sdk.sdk_configuration.retry_config is _RETRY_CONFIG


def test_retry_config_retries_connection_errors() -> None:
    assert _RETRY_CONFIG.retry_connection_errors is True
    assert _RETRY_CONFIG.strategy == "backoff"


def _events_response(events: list | None) -> MagicMock:
    response = MagicMock()
    if events is None:
        response.result.result = None
    else:
        response.result.result.events = events
    return response


def _patched_list_events(response: MagicMock):
    return patch(
        "censys_platform.collections.Collections.list_events",
        return_value=response,
    )


def test_has_added_assets_since_queries_added_asset_events() -> None:
    client = Client(organisation_id="org", token="tok")
    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with _patched_list_events(_events_response([MagicMock()])) as list_events:
        assert client.has_added_assets_since("coll-1", since) is True

    request = list_events.call_args.kwargs["request"]
    assert request.collection_uid == "coll-1"
    assert request.organization_id == "org"
    assert request.page_size == 1
    assert request.change_types == [ChangeTypes.ASSET]
    assert request.asset_change_types == [AssetChangeTypes.ADDED]
    assert request.start_time == since


def test_has_added_assets_since_false_without_events() -> None:
    client = Client(organisation_id="org", token="tok")
    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with _patched_list_events(_events_response([])):
        assert client.has_added_assets_since("coll-1", since) is False
    with _patched_list_events(_events_response(None)):
        assert client.has_added_assets_since("coll-1", since) is False
