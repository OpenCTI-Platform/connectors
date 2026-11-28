import os
import sys
from typing import Any

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402


class FakeLogger:
    def __init__(self) -> None:
        self.warnings: list[tuple[str, dict]] = []

    def info(self, *args: Any, **kwargs: Any) -> None:
        pass

    def debug(self, *args: Any, **kwargs: Any) -> None:
        pass

    def warning(self, message: str, meta: dict | None = None) -> None:
        self.warnings.append((message, meta or {}))

    def error(self, *args: Any, **kwargs: Any) -> None:
        pass

    def exception(self, *args: Any, **kwargs: Any) -> None:
        pass


@pytest.fixture
def fake_logger() -> FakeLogger:
    return FakeLogger()


class TestConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id", "log_level": "error"},
                "offseq_mirage": {"batch_size": 100},
            }
        )


@pytest.fixture
def connector_settings() -> TestConnectorSettings:
    return TestConnectorSettings()
