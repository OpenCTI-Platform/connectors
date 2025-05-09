"""Conftest file for Pytest fixtures."""

from typing import TYPE_CHECKING, Any
import sys
import types
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
def mock_opencti_api_client() -> Any:
    """Fixture to mock OpenCTI API calls and clean up after."""
    mock_api = patch("requests.Session.post")
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
