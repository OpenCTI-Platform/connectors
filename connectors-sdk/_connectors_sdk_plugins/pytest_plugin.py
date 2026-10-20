"""pytest plugin of the connectors SDK, loaded automatically when the SDK is installed.

During tests, the SDK leaves the root logger alone, so that pytest keeps its handlers
(used by `caplog`) and its level.
"""

import pytest

_monkeypatch = pytest.MonkeyPatch()


def _noop_set_sdk_json_handler() -> None:
    """Do nothing, instead of the SDK's `_set_sdk_json_handler()`."""


def _noop_set_root_level(level: str) -> None:
    """Do nothing, instead of the SDK's `_set_root_level()`.

    Args:
        level (str): Ignored.
    """


def pytest_load_initial_conftests() -> None:
    """Stop the SDK from changing the root logger, before any `conftest.py` is loaded."""
    # Imported here rather than at the top, so that pytest-cov already measures the SDK
    from connectors_sdk.logger import _logger

    _monkeypatch.setattr(_logger, "_set_sdk_json_handler", _noop_set_sdk_json_handler)
    _monkeypatch.setattr(_logger, "_set_root_level", _noop_set_root_level)


def pytest_unconfigure() -> None:
    """Put the SDK's functions back."""
    _monkeypatch.undo()
