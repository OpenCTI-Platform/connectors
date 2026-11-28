"""Shared pytest fixtures."""

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

# Let test files import "connector"/"offensive_agency_client" the same way `main.py` does.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402

RESOURCES = Path(__file__).parent / "resources"


class FakeLogger:
    """Stand-in for the SDK logger that ignores every call."""

    def info(self, *args: Any, **kwargs: Any) -> None:
        pass

    def debug(self, *args: Any, **kwargs: Any) -> None:
        pass

    def warning(self, *args: Any, **kwargs: Any) -> None:
        pass

    def error(self, *args: Any, **kwargs: Any) -> None:
        pass

    def exception(self, *args: Any, **kwargs: Any) -> None:
        pass


@pytest.fixture
def fake_logger() -> FakeLogger:
    """A fresh `FakeLogger` for each test."""
    return FakeLogger()


def make_settings(offensive_agency: dict[str, Any] | None = None) -> ConnectorSettings:
    """Build valid `ConnectorSettings` without reading the environment."""

    class TestConnectorSettings(ConnectorSettings):
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
                        "log_level": "error",
                    },
                    "offensive_agency": offensive_agency or {},
                }
            )

    return TestConnectorSettings()


@pytest.fixture
def connector_settings() -> ConnectorSettings:
    """Valid settings with the default feed options."""
    return make_settings()


@pytest.fixture
def raw_feed() -> dict[str, Any]:
    """An anonymised copy of the feed, as returned by the API."""
    return json.loads((RESOURCES / "feed_sample.json").read_text(encoding="utf-8"))
