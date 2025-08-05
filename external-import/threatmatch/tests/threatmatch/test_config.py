import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import HttpUrl
from pydantic_settings import SettingsConfigDict
from threatmatch.config import ConfigRetrievalError, ConnectorSettings


@pytest.mark.usefixtures("mock_config")
def test_config() -> None:
    config = ConnectorSettings().model_dump()

    assert config["opencti"]["url"] == HttpUrl("http://test-opencti-url/")
    assert config["opencti"]["token"] == "test-opencti-token"

    assert config["connector"]["id"] == "threatmatch-connector-id"
    assert config["connector"]["type"] == "EXTERNAL_IMPORT"
    assert config["connector"]["name"] == "ThreatMatch"
    assert config["connector"]["scope"] == ["threatmatch"]
    assert config["connector"]["log_level"] == "info"

    assert len(config["threatmatch"]) == 8
    assert config["threatmatch"]["url"] == HttpUrl("https://test-threatmatch-url")
    assert config["threatmatch"]["client_id"] == "threatmatch-client-id"
    assert config["threatmatch"]["client_secret"] == "threatmatch-client-secret"
    assert config["threatmatch"]["interval"] == 1
    assert config["threatmatch"]["import_from_date"] == "2025-01-01 00:00"
    assert config["threatmatch"]["import_profiles"] is True
    assert config["threatmatch"]["import_alerts"] is True
    assert config["threatmatch"]["import_iocs"] is True


def test_yaml_config(config_dict: dict[str, dict[str, Any]]) -> None:
    class YamlConfig(ConnectorSettings):
        model_config = SettingsConfigDict(
            yaml_file=f"{Path(__file__).parent}/config.test.yml"
        )

    config = YamlConfig()
    assert config.model_dump_pycti() == config_dict


@pytest.mark.usefixtures("mock_config")
def test_env_config(config_dict: dict[str, dict[str, Any]]) -> None:
    config = ConnectorSettings()
    assert config.model_dump_pycti() == config_dict


@pytest.mark.usefixtures("mock_config")
def test_missing_values(config_dict: dict[str, dict[str, Any]]) -> None:
    config = ConnectorSettings()
    assert config.model_dump_pycti() == config_dict
    os.environ.pop("OPENCTI_URL")
    with pytest.raises(ConfigRetrievalError):
        ConnectorSettings()


def test_fail_config() -> None:
    with pytest.raises(ConfigRetrievalError) as exc_info:
        ConnectorSettings()

    errors = exc_info.value.args[1].errors()

    assert errors[0]["msg"] == "Field required"
    assert errors[0]["type"] == "missing"
    assert errors[0]["loc"] == ("url",)

    assert errors[1]["msg"] == "Field required"
    assert errors[1]["type"] == "missing"
    assert errors[1]["loc"] == ("token",)
