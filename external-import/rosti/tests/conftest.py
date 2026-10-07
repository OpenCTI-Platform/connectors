"""Shared pytest fixtures."""

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

# Import "connector" and "rosti_client" the same way `main.py` does.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeLogger:
    """Stand-in for `ConnectorLogger` that records messages."""

    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []

    def _log(self, level: str, message: str, *_: Any, **__: Any) -> None:
        self.messages.append((level, message))

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log("info", message)

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log("debug", message)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log("warning", message)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log("error", message)


@pytest.fixture
def fake_logger() -> FakeLogger:
    return FakeLogger()


def make_settings(**rosti_overrides: Any) -> ConnectorSettings:
    """Valid settings without reading env vars or config.yml."""

    class TestConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id", "log_level": "error"},
                    "rosti": {
                        "api_key": "test-api-key",
                        "import_since": "2026-09-01T00:00:00Z",
                        **rosti_overrides,
                    },
                }
            )

    return TestConnectorSettings()


@pytest.fixture
def connector_settings() -> ConnectorSettings:
    return make_settings()
