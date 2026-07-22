"""Shared pytest fixtures and path setup for the connector test suite."""

import os
import sys
import types

# Make `src/` importable so tests can do `from connector...`, `from email_client...`,
# `from attachment_handler...` exactly the way the runtime image does.
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# ---------------------------------------------------------------------------
# Stub `connectors_sdk` for unit tests.
#
# The connectors-sdk package is installed from a git tag in production, but
# we don't want unit tests to depend on a network install. We replace the
# module with thin pydantic.BaseModel subclasses that match the surface area
# settings.py uses (BaseConfigModel, BaseConnectorSettings,
# BaseExternalImportConnectorConfig).
# ---------------------------------------------------------------------------
if "connectors_sdk" not in sys.modules:
    from pydantic import BaseModel, ConfigDict

    fake_sdk = types.ModuleType("connectors_sdk")

    class _SdkBase(BaseModel):
        # Allow ignoring extra env-style keys when settings are constructed in tests
        model_config = ConfigDict(extra="ignore")

    class BaseConfigModel(_SdkBase):
        pass

    class BaseConnectorSettings(_SdkBase):
        pass

    class BaseExternalImportConnectorConfig(_SdkBase):
        pass

    fake_sdk.BaseConfigModel = BaseConfigModel
    fake_sdk.BaseConnectorSettings = BaseConnectorSettings
    fake_sdk.BaseExternalImportConnectorConfig = BaseExternalImportConnectorConfig
    sys.modules["connectors_sdk"] = fake_sdk

# ---------------------------------------------------------------------------
# Stub `google.*` for gmail_client unit tests.
#
# gmail_client imports `from google.auth.transport.requests import Request` and
# `from google.oauth2 import service_account` at module load. google-auth is an
# optional protocol dependency that isn't installed in the unit-test env, so we
# register thin module stubs (placeholder Request / service_account.Credentials).
# Tests patch the module-level `Request`/`service_account` names directly.
# ---------------------------------------------------------------------------
if "google.auth" not in sys.modules:
    _mod_names = [
        "google",
        "google.auth",
        "google.auth.transport",
        "google.auth.transport.requests",
        "google.oauth2",
        "google.oauth2.service_account",
    ]
    for _name in _mod_names:
        sys.modules.setdefault(_name, types.ModuleType(_name))
    # Wire submodules as attributes on their parents so `from X import Y` works.
    sys.modules["google"].auth = sys.modules["google.auth"]
    sys.modules["google.auth"].transport = sys.modules["google.auth.transport"]
    sys.modules["google.auth.transport"].requests = sys.modules[
        "google.auth.transport.requests"
    ]
    sys.modules["google"].oauth2 = sys.modules["google.oauth2"]
    sys.modules["google.oauth2"].service_account = sys.modules[
        "google.oauth2.service_account"
    ]

    class _Request:  # placeholder, patched in tests
        pass

    class _Credentials:  # placeholder, patched in tests
        @staticmethod
        def from_service_account_file(*a, **k):
            raise NotImplementedError

    sys.modules["google.auth.transport.requests"].Request = _Request
    sys.modules["google.oauth2.service_account"].Credentials = _Credentials

# ---------------------------------------------------------------------------
# Warm-up imports.
#
# `connector/__init__.py` eagerly imports `connector.connector`, which in turn
# imports `attachment_handler.registry`. If a test starts by importing from
# `attachment_handler.*` first, the chain re-enters `attachment_handler.registry`
# while it is still being initialized (because `archive_handler` reaches back
# into `connector.utils`, which triggers the connector package init), and the
# circular import fails.
#
# In production, `main.py` imports `connector` first, so the chain warms up in
# the right order. We replicate that here so tests don't depend on which test
# file is collected first.
# ---------------------------------------------------------------------------
import connector  # noqa: E402,F401  pylint: disable=wrong-import-position,unused-import
