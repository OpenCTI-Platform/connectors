from __future__ import annotations

import sys
from unittest.mock import MagicMock

# Pre-stub libmagic-dependent modules so ``import pycti`` succeeds even
# when the system libmagic isn't installed. ``setdefault`` keeps the
# real module if it's importable (CI runners with libmagic installed).
sys.modules.setdefault("magic", MagicMock())

import pytest  # noqa: E402
from connector.settings import ConfigConnector  # noqa: E402


@pytest.fixture(autouse=True)
def _connector_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test a valid configuration and a fresh settings singleton.

    ``ConfigConnector()`` builds a real ``ConnectorSettings`` from the
    environment, and the library-level call sites (``BaseEntity``,
    ``AdapterCoreMixin``) do it without any injection. Without these variables
    a clean runner (CI) fails validation, and the process-wide
    ``_shared_settings`` cache would make the result depend on test order.
    """
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("TI_API_URL", "https://tap.group-ib.com/api/v2/")
    monkeypatch.setenv("TI_API_USERNAME", "test@example.com")
    monkeypatch.setenv("TI_API_TOKEN", "test-token")
    monkeypatch.setattr(ConfigConnector, "_shared_settings", None)
