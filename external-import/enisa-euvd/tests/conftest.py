"""Shared pytest fixtures for the whole test suite."""

import os
import sys
from typing import Any

import pytest

# Let test files import "enisa_euvd" the same way `main.py` does.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from enisa_euvd import ConnectorSettings


class FakeLogger:
    """Minimal stand-in for `ConnectorLogger`, used throughout this test suite."""

    def info(self, *args: Any, **kwargs: Any) -> None:
        pass

    def debug(self, *args: Any, **kwargs: Any) -> None:
        pass

    def warning(self, *args: Any, **kwargs: Any) -> None:
        pass

    def error(self, *args: Any, **kwargs: Any) -> None:
        pass


@pytest.fixture
def fake_logger() -> FakeLogger:
    """A fresh `FakeLogger` for each test."""
    return FakeLogger()


class TestConnectorSettings(ConnectorSettings):
    """Fake but valid `ConnectorSettings` for tests.

    Bypasses reading real environment variables/`config.yml` by overriding
    `_load_config_dict` with a fixed, valid dict.
    """

    @classmethod
    def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "vulnerability",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "euvd": {
                    "tlp_level": "clear",
                },
            }
        )


@pytest.fixture
def connector_settings() -> TestConnectorSettings:
    """A fresh `TestConnectorSettings` for each test."""
    return TestConnectorSettings()
