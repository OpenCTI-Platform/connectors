"""Tests for censys_collections.client."""

from __future__ import annotations

from censys_collections.client import Client, _RETRY_CONFIG


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
