import os
import sys
from pathlib import Path

import pytest
from connectors_sdk.settings._settings_loader import _SettingsLoader

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def required_environment(monkeypatch):
    for name in os.environ:
        if name.startswith(("OPENCTI_", "CONNECTOR_", "TRUKNO_")):
            monkeypatch.delenv(name)
    monkeypatch.setattr(_SettingsLoader, "_get_config_yml_file_path", lambda: None)
    monkeypatch.setattr(_SettingsLoader, "_get_dot_env_file_path", lambda: None)
    monkeypatch.setenv("OPENCTI_URL", "http://opencti:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "opencti-token")
    monkeypatch.setenv("CONNECTOR_ID", "connector-id")
    monkeypatch.setenv("TRUKNO_API_KEY", "trukno-secret")
