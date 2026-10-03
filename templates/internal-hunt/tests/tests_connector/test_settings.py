import copy
from typing import Any

import pytest
from conftest import VALID_SETTINGS
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def test_settings_should_accept_valid_input():
    # Given/When valid settings are loaded
    settings = _settings(copy.deepcopy(VALID_SETTINGS))

    # Then every namespace is validated and the connector type is INTERNAL_HUNT
    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.template, BaseConfigModel)
    assert settings.connector.type == "INTERNAL_HUNT"
    assert settings.connector.platform == "opensearch"


def test_settings_should_accept_minimal_input():
    # Given settings with only the values without default
    minimal = {
        "opencti": VALID_SETTINGS["opencti"],
        "template": {"api_base_url": "https://siem.example.com", "api_key": "k"},
    }

    # When/Then the defaults are applied
    settings = _settings(minimal)
    assert settings.connector.security_platform_name == "Template SIEM"
    assert settings.template.sigma_pipeline == "none"


@pytest.mark.parametrize(
    "path, value",
    [
        pytest.param(("template", "api_key"), None, id="missing_api_key"),
        pytest.param(("connector", "scope"), "unknown", id="unknown_platform"),
        pytest.param(("template", "api_base_url"), "not a url", id="invalid_url"),
    ],
)
def test_settings_should_raise_when_invalid_input(path, value):
    # Given settings with one invalid value
    settings_dict = copy.deepcopy(VALID_SETTINGS)
    namespace, key = path
    if value is None:
        settings_dict[namespace].pop(key)
    else:
        settings_dict[namespace][key] = value

    # When/Then the settings are rejected
    with pytest.raises(ConfigValidationError) as err:
        _settings(settings_dict)
    assert key in str(err.value.__cause__)
