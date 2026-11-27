"""Shared factories for the connector tests."""

from typing import Any

from connector import ConnectorSettings

PASSWORD = "s3cret-password"
USERNAME = "user@example.com"
AUTH_KEY = "community-auth-key"


def make_settings(**section: Any) -> ConnectorSettings:
    class FakeSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {
                        "id": "connector-id",
                        "name": "Test",
                        "scope": "test",
                        "log_level": "error",
                        "duration_period": "PT5M",
                    },
                    "urlhaus_recent_payloads": section,
                }
            )

    return FakeSettings()


COMMUNITY = {"auth_key": AUTH_KEY}
COMMERCIAL = {"spamhaus_username": USERNAME, "spamhaus_password": PASSWORD}
BOTH = {**COMMUNITY, **COMMERCIAL}
