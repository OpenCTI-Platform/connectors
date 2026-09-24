from typing import Any

import pytest
from connectors_sdk import ConfigValidationError

from connector import ConnectorSettings


def _settings_with(config: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
            return handler(config)

    return FakeConnectorSettings()


def test_defaults_point_at_honeylabs_and_the_public_collections():
    s = _settings_with(
        {
            "opencti": {"url": "http://localhost:8080", "token": "t"},
            "honeylabs": {"api_key": "hlk_x"},
        }
    )
    assert s.honeylabs.api_root == "https://honeylabs.net/taxii2/api/"
    assert s.honeylabs.collections == ["attackers", "malware-infrastructure"]
    assert s.honeylabs.tlp_level.value == "clear"
    assert s.connector.name == "HoneyLabs"
    assert s.honeylabs.api_key.get_secret_value() == "hlk_x"


def test_collections_accept_a_comma_separated_string():
    s = _settings_with(
        {
            "opencti": {"url": "http://localhost:8080", "token": "t"},
            "honeylabs": {"api_key": "k", "collections": "exploiters, cve-probers"},
        }
    )
    assert s.honeylabs.collections == ["exploiters", "cve-probers"]


def test_api_key_is_required():
    with pytest.raises(ConfigValidationError):
        _settings_with({"opencti": {"url": "http://localhost:8080", "token": "t"}})
