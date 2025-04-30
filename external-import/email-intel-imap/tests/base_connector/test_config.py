import os
from pathlib import Path
from typing import Any

import pytest
from base_connector.config import BaseConnectorSettings
from base_connector.errors import ConfigRetrievalError
from pydantic_settings import SettingsConfigDict


class ConnectorSettings(BaseConnectorSettings):
    pass


def test_yaml_config(config_dict: dict[str, dict[str, Any]]) -> None:
    class YamlConfig(ConnectorSettings):
        model_config = SettingsConfigDict(
            yaml_file=f"{Path(__file__).parent}/config.test.yml"
        )

    config = YamlConfig()
    assert config.model_dump_pycti() == config_dict


def test_dotenv_config(config_dict: dict[str, dict[str, Any]]) -> None:
    class DotEnvConfig(ConnectorSettings):
        model_config = SettingsConfigDict(env_file=f"{Path(__file__).parent}/.env.test")

    config = DotEnvConfig()
    assert config.model_dump_pycti() == config_dict


@pytest.mark.usefixtures("mocked_environ")
def test_env_config(config_dict: dict[str, dict[str, Any]]) -> None:
    config = ConnectorSettings()
    assert config.model_dump_pycti() == config_dict


@pytest.mark.usefixtures("mocked_environ")
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
    assert errors[0]["loc"] == ("opencti",)

    assert errors[1]["msg"] == "Field required"
    assert errors[1]["type"] == "missing"
    assert errors[1]["loc"] == ("connector",)
