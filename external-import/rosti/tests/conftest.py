"""Shared pytest fixtures."""

import json
import os
import sys
from pathlib import Path
from typing import Any, NamedTuple

import pytest

# Import "connector" and "rosti_client" the same way `main.py` does.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class LogRecord(NamedTuple):
    level: str
    message: str
    meta: dict[str, Any] | None


class FakeLogger:
    """Stand-in for the SDK's `ConnectorLoggerAdapter` that records every call.

    Like the real logger, it takes context only as `meta=`. A positional
    argument raises: the real logger would treat it as a %-format argument
    and drop it silently.
    """

    def __init__(self) -> None:
        self.records: list[LogRecord] = []

    @property
    def messages(self) -> list[tuple[str, str]]:
        return [(record.level, record.message) for record in self.records]

    def find(self, message: str) -> list[LogRecord]:
        return [record for record in self.records if record.message == message]

    def _log(
        self,
        level: str,
        message: str,
        *args: Any,
        meta: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if args:
            raise TypeError(
                f"Log context must be passed as meta=, got positional {args!r}"
            )
        unknown = set(kwargs) - {"exc_info", "stack_info", "stacklevel", "extra"}
        if unknown:
            raise TypeError(f"Unexpected logger arguments: {sorted(unknown)}")
        self.records.append(LogRecord(level, message, meta))

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log("debug", message, *args, **kwargs)

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log("info", message, *args, **kwargs)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log("warning", message, *args, **kwargs)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log("error", message, *args, **kwargs)

    def exception(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._log("error", message, *args, **kwargs)


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
