"""Shared pytest fixtures for the whole test suite.

Every test file under `tests/` can use the fixtures defined here without
importing anything -- pytest makes fixtures declared in a `conftest.py`
available to every test in the same folder and its subfolders.
"""

import os
import sys
from typing import Any

import pytest

# Let test files import "connector"/"template_client" the same way `main.py` does.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402


class FakeLogger:
    """Minimal stand-in for `ConnectorLogger`, used throughout this test suite.

    It implements the same four logging methods (`info`/`debug`/
    `warning`/`error`) but does nothing with them -- just enough for the
    code under test to log without needing a real, pycti-backed
    `OpenCTIConnectorHelper`.
    """

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

    Bypasses reading real environment variables/`config.yml` (as the
    connector normally does) by overriding `_load_config_dict` with a
    fixed, valid dict -- the same fake-input pattern used in
    `tests_connector/test_settings.py` to test settings validation itself.
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
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "template": {
                    "api_key": "test-api-key",
                    "tlp_level": "clear",
                },
            }
        )


@pytest.fixture
def connector_settings() -> TestConnectorSettings:
    """A fresh `TestConnectorSettings` for each test."""
    return TestConnectorSettings()
