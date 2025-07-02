import datetime
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import HttpUrl
from pydantic_settings import SettingsConfigDict
from shadowserver.config import ConfigRetrievalError, ConnectorSettings


class _ConnectorSettings(ConnectorSettings):
    model_config = SettingsConfigDict(env_file="", yaml_file="")


@pytest.mark.usefixtures("mock_config")
def test_config() -> None:
    config = _ConnectorSettings().model_dump()

    assert config["opencti"]["url"] == HttpUrl("http://test-opencti-url/")
    assert config["opencti"]["token"] == "ChangeMe"

    assert config["connector"]["id"] == "ChangeMe"
    assert config["connector"]["name"] == "Shadowserver"
    assert config["connector"]["scope"] == ["stix2"]
    assert config["connector"]["duration_period"] == datetime.timedelta(days=2)

    assert len(config["shadowserver"]) == 6
    assert config["shadowserver"]["api_key"] == "CHANGEME"
    assert config["shadowserver"]["api_secret"] == "CHANGEME"
    assert config["shadowserver"]["marking"] == "TLP:CLEAR"
    assert config["shadowserver"]["create_incident"] == True
    assert config["shadowserver"]["incident_severity"] == "high"
    assert config["shadowserver"]["incident_priority"] == "P1"


@pytest.mark.usefixtures("mock_config")
def test_config_run_every_deprecated(recwarn: pytest.WarningsRecorder) -> None:
    # Assert warning is not raised when run_every is not set
    _ConnectorSettings().model_dump()
    assert len(recwarn) == 0

    os.environ["CONNECTOR_RUN_EVERY"] = "3d"

    # Assert run_every and duration_period are mutually exclusive
    with pytest.raises(ConfigRetrievalError):
        _ConnectorSettings().model_dump()

    os.environ.pop("CONNECTOR_DURATION_PERIOD")
    config = _ConnectorSettings().model_dump()

    # Assert run_every is deprecated and the warning is raised
    assert recwarn[0].category == UserWarning
    assert recwarn[0].message.args == (
        "CONNECTOR_RUN_EVERY is deprecated. Use CONNECTOR_DURATION_PERIOD instead.",
    )

    assert config["connector"]["duration_period"] == datetime.timedelta(days=3)


def test_yaml_config() -> None:
    class YamlConfig(_ConnectorSettings):
        model_config = SettingsConfigDict(
            yaml_file=f"{Path(__file__).parent}/config.test.yml"
        )

    config = YamlConfig()
    assert config.model_dump_pycti() == {
        "connector": {
            "duration_period": "PT5M",
            "id": "ChangeMe",
            "log_level": "info",
            "name": "Shadowserver config.test.yml",
            "scope": "stix2",
            "type": "EXTERNAL_IMPORT",
        },
        "opencti": {
            "token": "test-opencti-token",
            "url": "http://test-opencti-url/",
        },
        "shadowserver": {
            "api_key": "CHANGEME",
            "api_secret": "CHANGEME",
            "create_incident": True,
            "incident_priority": "P1",
            "incident_severity": "high",
            "marking": "TLP:CLEAR",
        },
    }


def test_dotenv_config(config_dict: dict[str, dict[str, Any]]) -> None:
    class DotEnvConfig(_ConnectorSettings):
        model_config = SettingsConfigDict(env_file=f"{Path(__file__).parent}/.env.test")

    config = DotEnvConfig()
    assert config.model_dump_pycti() == {
        "connector": {
            "duration_period": "PT5M",
            "id": "ChangeMe",
            "log_level": "info",
            "name": "Shadowserver .env.test",
            "scope": "stix2",
            "type": "EXTERNAL_IMPORT",
        },
        "opencti": {
            "token": "test-opencti-token",
            "url": "http://test-opencti-url/",
        },
        "shadowserver": {
            "api_key": "CHANGEME",
            "api_secret": "CHANGEME",
            "create_incident": True,
            "incident_priority": "P1",
            "incident_severity": "high",
            "marking": "TLP:CLEAR",
        },
    }


@pytest.mark.usefixtures("mock_config")
def test_env_config(config_dict: dict[str, dict[str, Any]]) -> None:
    config = _ConnectorSettings()
    assert config.model_dump_pycti() == config_dict


@pytest.mark.usefixtures("mock_config")
def test_missing_values(config_dict: dict[str, dict[str, Any]]) -> None:
    os.environ.pop("OPENCTI_URL")
    with pytest.raises(ConfigRetrievalError):
        _ConnectorSettings()


def test_fail_config() -> None:
    with pytest.raises(ConfigRetrievalError) as exc_info:
        _ConnectorSettings()

    errors = exc_info.value.args[1].errors()
    assert errors[0]["msg"] == "Field required"
    assert errors[1]["msg"] == "Field required"
    assert errors[0]["type"] == "missing"
    assert errors[1]["type"] == "missing"

    assert {error["loc"] for error in errors} == {("url",), ("token",)}
