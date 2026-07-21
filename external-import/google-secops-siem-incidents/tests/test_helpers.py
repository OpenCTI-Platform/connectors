"""Shared test helpers providing config dicts and the make_stub_settings factory."""

import os
import sys
from typing import Any

# Ensure src/ is importable when this module is imported directly.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from google_secops_siem_incidents.settings import ConnectorSettings  # noqa: E402

# ---------------------------------------------------------------------------
# Shared Chronicle SA fields — reused across config dicts
# ---------------------------------------------------------------------------
_SERVICE_ACCOUNT: dict[str, str] = {
    "project_id": "test-project",
    "project_region": "us",
    "project_instance": "test-instance-uuid",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n",
    "private_key_id": "key-id-1",
    "client_email": "sa@test.iam.gserviceaccount.com",
    "client_id": "123456789",
    "client_cert_url": (
        "https://www.googleapis.com/robot/v1/metadata/x509/sa%40test.iam.gserviceaccount.com"
    ),
}

# ---------------------------------------------------------------------------
# Full valid config dict
# ---------------------------------------------------------------------------
FULL_VALID_CONFIG: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Test Google SecOps",
        "scope": "google-secops-siem-incidents",
        "log_level": "error",
        "duration_period": "PT1H",
    },
    "google_secops_siem_incidents": _SERVICE_ACCOUNT | {"tlp_level": "amber"},
}

# Minimal config — only mandatory fields, no optional overrides
MINIMAL_VALID_CONFIG: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "scope": "google-secops-siem-incidents",
    },
    "google_secops_siem_incidents": _SERVICE_ACCOUNT.copy(),
}


# ---------------------------------------------------------------------------
# Stub settings helper
# ---------------------------------------------------------------------------
def make_stub_settings(config_dict: dict[str, Any] | None = None):
    """Return a *class* (not instance) that injects *config_dict* into settings."""
    cfg = config_dict if config_dict is not None else FULL_VALID_CONFIG

    class StubConnectorSettings(ConnectorSettings):
        """Override _load_config_dict to avoid reading env/config files."""

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(cfg)

    return StubConnectorSettings
