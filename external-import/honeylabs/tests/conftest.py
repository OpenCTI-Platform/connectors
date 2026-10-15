"""Shared pytest fixtures."""

import os
import sys
from typing import Any

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402


class FakeLogger:
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
    return FakeLogger()


@pytest.fixture
def connector_settings() -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "test-id",
                        "name": "HoneyLabs",
                        "scope": "Indicator",
                        "log_level": "error",
                    },
                    "honeylabs": {"api_key": "hlk_test"},
                }
            )

    return FakeConnectorSettings()
