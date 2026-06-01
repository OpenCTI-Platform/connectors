from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, MispFeed


def _build_settings(http_authorization_header: str | None) -> ConnectorSettings:
    """Build a `ConnectorSettings` whose `misp_feed.http_authorization_header` is
    set to ``http_authorization_header``.

    The Pydantic models are frozen, so the value has to be injected through the
    standard `_load_config_dict` extension point rather than mutated afterwards.
    """

    class _StubSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            misp_feed: dict[str, Any] = {
                "source_type": "url",
                "url": "http://test.com",
                "ssl_verify": True,
            }
            if http_authorization_header is not None:
                misp_feed["http_authorization_header"] = http_authorization_header
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {
                        "id": "connector-id",
                        "name": "Test Connector",
                        "scope": "test, connector",
                        "log_level": "error",
                        "duration_period": "PT5M",
                    },
                    "misp_feed": misp_feed,
                }
            )

    return _StubSettings()


@pytest.fixture
def fake_requests_get(monkeypatch):
    fake_response = MagicMock()
    fake_response.text = "payload"
    fake_get = MagicMock(return_value=fake_response)
    monkeypatch.setattr("connector.connector.requests.get", fake_get)
    return fake_get


def test_retrieve_data_without_authorization_header_omits_headers(fake_requests_get):
    """When `http_authorization_header` is not set, no `Authorization` header is sent."""
    connector = MispFeed(config=_build_settings(None), helper=MagicMock())

    result = connector._retrieve_data("http://test.com/feed")

    assert result == "payload"
    fake_requests_get.assert_called_once()
    kwargs = fake_requests_get.call_args.kwargs
    assert kwargs.get("verify") is True
    assert kwargs.get("headers") is None


def test_retrieve_data_with_authorization_header_sets_it(fake_requests_get):
    """When `http_authorization_header` is set, it is forwarded to `requests.get`."""
    connector = MispFeed(config=_build_settings("Bearer secret"), helper=MagicMock())

    result = connector._retrieve_data("http://test.com/feed")

    assert result == "payload"
    fake_requests_get.assert_called_once()
    kwargs = fake_requests_get.call_args.kwargs
    assert kwargs.get("headers") == {"Authorization": "Bearer secret"}
