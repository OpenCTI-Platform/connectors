"""Tests for the Kaspersky client retry/backoff configuration (issue #5942)."""

from unittest.mock import MagicMock

from kaspersky.client import KasperskyClient


def _make_client():
    helper = MagicMock()
    return KasperskyClient(
        helper=helper,
        base_url="https://tip.kaspersky.com",
        user="user",
        password="password",
        certificate_path="",
    )


def test_retry_adapter_mounted_for_http_and_https():
    client = _make_client()

    https_adapter = client.session.get_adapter("https://tip.kaspersky.com")
    http_adapter = client.session.get_adapter("http://tip.kaspersky.com")

    assert https_adapter is not None
    assert http_adapter is not None


def test_retry_strategy_configuration():
    client = _make_client()

    retries = client.session.get_adapter("https://tip.kaspersky.com").max_retries

    assert retries.total == 5
    assert retries.backoff_factor == 5
    assert retries.respect_retry_after_header is True
    assert retries.raise_on_status is False


def test_transient_statuses_are_retried():
    client = _make_client()

    retries = client.session.get_adapter("https://tip.kaspersky.com").max_retries

    for status in (429, 500, 502, 503, 504):
        assert status in retries.status_forcelist


def test_permanent_statuses_are_not_retried():
    client = _make_client()

    retries = client.session.get_adapter("https://tip.kaspersky.com").max_retries

    for status in (400, 401, 403, 404):
        assert status not in retries.status_forcelist


def test_post_requests_are_retried():
    client = _make_client()

    retries = client.session.get_adapter("https://tip.kaspersky.com").max_retries

    assert "POST" in retries.allowed_methods
