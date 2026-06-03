import os
import sys
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from lib import SafeBrowsing as safebrowsing_module  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_safe_browsing_env(monkeypatch):
    """Ensure the Safe Browsing env vars are unset unless a test sets them."""
    for var in (
        "SAFE_BROWSING_API_KEY",
        "SAFE_BROWSING_API_URL",
        "GOOGLE_SAFE_BROWSING_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def connector(mocker: MockerFixture):
    """A SafeBrowsingConnector with a mocked OpenCTI helper (no real connection)."""
    mocker.patch.object(
        safebrowsing_module, "OpenCTIConnectorHelper", return_value=MagicMock()
    )
    return safebrowsing_module.SafeBrowsingConnector()
