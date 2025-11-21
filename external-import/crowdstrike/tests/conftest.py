"""Conftest file for CrowdStrike connector pytest fixtures."""

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from pytest import fixture

# Add src to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if TYPE_CHECKING:
    from os import _Environ


def mock_env_vars(os_environ: "_Environ[str]", wanted_env: dict[str, str]) -> Any:
    """Fixture to mock environment variables dynamically and clean up after."""
    mock_env = patch.dict(os_environ, wanted_env)
    mock_env.start()

    return mock_env


@fixture(autouse=True)
def mock_opencti_api_client() -> Any:
    """Fixture to mock OpenCTI API calls and clean up after."""
    mock_api = patch("requests.Session")
    mock_healthcheck = patch(
        "pycti.api.opencti_api_client.OpenCTIApiClient.health_check"
    )
    mock_query = patch("pycti.api.opencti_api_client.OpenCTIApiClient.query")

    mock_api.start()
    mock_healthcheck.start()
    mock_query.start()

    yield mock_api, mock_healthcheck, mock_query

    mock_api.stop()
    mock_healthcheck.stop()
    mock_query.stop()


@fixture(autouse=True)
def patch_logger_for_tests(monkeypatch):
    """Patch logger methods to format logs with dictionary data for tests."""
    import logging

    def create_enhanced_log_method(original_method):
        def enhanced_log(self, msg, *args, **kwargs):
            if args and len(args) == 1 and isinstance(args[0], dict):
                log_dict = args[0]
                formatted_msg = f"{msg} - {log_dict}"
                return original_method(self, formatted_msg)
            else:
                return original_method(self, msg, *args, **kwargs)

        return enhanced_log

    orig_info = logging.Logger.info
    orig_debug = logging.Logger.debug
    orig_warning = logging.Logger.warning
    orig_error = logging.Logger.error

    monkeypatch.setattr(logging.Logger, "info", create_enhanced_log_method(orig_info))
    monkeypatch.setattr(logging.Logger, "debug", create_enhanced_log_method(orig_debug))
    monkeypatch.setattr(
        logging.Logger, "warning", create_enhanced_log_method(orig_warning)
    )
    monkeypatch.setattr(logging.Logger, "error", create_enhanced_log_method(orig_error))
