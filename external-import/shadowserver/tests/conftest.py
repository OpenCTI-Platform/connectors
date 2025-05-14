import os
import sys
from copy import deepcopy
from typing import Any

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from pytest_mock import MockerFixture
from shadowserver.config import ConnectorSettings


@pytest.fixture(name="config_dict")
def fixture_config_dict() -> dict[str, dict[str, Any]]:
    return {
        "opencti": {
            "url": "http://test-opencti-url/",
            "token": "ChangeMe",
        },
        "connector": {
            "id": "ChangeMe",
            "name": "Shadowserver",
            "scope": "stix2",
            "log_level": "info",
            "duration_period": "2d",
        },
        "shadowserver": {
            "api_key": "CHANGEME",
            "api_secret": "CHANGEME",
            "marking": "TLP:CLEAR",
            "create_incident": "true",
            "incident_severity": "high",
            "incident_priority": "P1",
        },
    }


@pytest.fixture(name="mock_config")
def fixture_mock_config(
    mocker: MockerFixture, config_dict: dict[str, dict[str, Any]]
) -> None:
    # Make sure the local config is not loaded in the tests
    ConnectorSettings.model_config["yaml_file"] = ""
    ConnectorSettings.model_config["env_file"] = ""

    environ = deepcopy(os.environ)
    for key, value in config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)
