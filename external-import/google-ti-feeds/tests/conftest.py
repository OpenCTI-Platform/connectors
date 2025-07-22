"""Conftest file for Pytest fixtures."""

import sys
import types
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from pytest import fixture

if TYPE_CHECKING:
    from os import _Environ


@fixture(autouse=True)
def disable_dotenv() -> Any:
    """Fixture to disable dotenv loading for tests."""
    fake_dotenv = types.ModuleType("dotenv")
    fake_dotenv.load_dotenv = lambda *args, **kwargs: None

    sys.modules["dotenv"] = fake_dotenv
    yield
    sys.modules.pop("dotenv", None)


def mock_env_vars(os_environ: "_Environ[str]", wanted_env: dict[str, str]) -> Any:
    """Fixture to mock environment variables dynamically and clean up after."""
    mock_env = patch.dict(os_environ, wanted_env)
    mock_env.start()

    return mock_env


@fixture(autouse=True)
def disable_config_yml() -> Any:
    """Fixture to disable config.yml for tests by stubbing yml_settings → {}."""

    def fake_settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        def yml_settings() -> dict:
            return {}

        return (yml_settings, env_settings, dotenv_settings, file_secret_settings)

    patcher = patch(
        "connector.src.octi.interfaces.base_config.BaseConfig.settings_customise_sources",
        new=classmethod(fake_settings_customise_sources),
    )
    patcher.start()

    yield patcher

    patcher.stop()


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
