"""Shared pytest fixtures for the whole test suite."""

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

# Let test files import "enisa_euvd" the same way `main.py` does.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from enisa_euvd import ConnectorSettings

RESOURCES_DIR = Path(__file__).parent / "resources"


def load_resource(name: str) -> Any:
    """Load and parse a JSON fixture from `tests/resources/`.

    Args:
        name: File name relative to `tests/resources/` (e.g. `"search_page.json"`).

    Returns:
        The parsed JSON content (dict or list).
    """
    with (RESOURCES_DIR / name).open(encoding="utf-8") as handle:
        return json.load(handle)


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
                "enisa_euvd": {
                    "tlp_level": "clear",
                },
            }
        )


@pytest.fixture
def connector_settings() -> TestConnectorSettings:
    """A fresh `TestConnectorSettings` for each test."""
    return TestConnectorSettings()


@pytest.fixture
def search_page() -> dict[str, Any]:
    """A `/search` response page with three anonymised vulnerabilities."""
    return load_resource("search_page.json")


@pytest.fixture
def search_page_empty() -> dict[str, Any]:
    """An empty `/search` response page (`items: []`)."""
    return load_resource("search_page_empty.json")


@pytest.fixture
def single_vulnerability() -> dict[str, Any]:
    """A single anonymised EUVD vulnerability item."""
    return load_resource("single_vulnerability.json")
