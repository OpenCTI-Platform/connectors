import os
from pathlib import Path
from typing import Any

import pytest
from pydantic_settings import SettingsConfigDict
from rflib import ConfigRetrievalError, ConnectorConfig


def test_yaml_config(config_dict: dict[str, dict[str, Any]]) -> None:
    class YamlConfig(ConnectorConfig):
        model_config = SettingsConfigDict(
            yaml_file=f"{Path(__file__).parent.parent}/config.test.yml",
            env_file=None,
        )

    config = YamlConfig()
    assert config.model_dump_pycti() == config_dict


def test_dotenv_config(config_dict: dict[str, dict[str, Any]]) -> None:
    class DotEnvConfig(ConnectorConfig):
        model_config = SettingsConfigDict(
            yaml_file=None,
            env_file=f"{Path(__file__).parent.parent}/.env.test",
        )

    config = DotEnvConfig()
    assert config.model_dump_pycti() == config_dict


@pytest.mark.usefixtures("mocked_environ")
def test_env_config(config_dict: dict[str, dict[str, Any]]) -> None:
    config = ConnectorConfig()
    assert config.model_dump_pycti() == config_dict


@pytest.mark.usefixtures("mocked_environ")
def test_env_config_missing_values(config_dict: dict[str, dict[str, Any]]) -> None:
    config = ConnectorConfig()
    assert config.model_dump_pycti() == config_dict

    os.environ.pop("OPENCTI_URL")
    with pytest.raises(ConfigRetrievalError):
        ConnectorConfig()


@pytest.mark.usefixtures("mocked_environ")
def test_env_config_out_of_range_values(config_dict: dict[str, dict[str, Any]]) -> None:
    config = ConnectorConfig()
    assert config.model_dump_pycti() == config_dict

    os.environ["CONNECTOR_SCOPE"] = "random_value_1,random_value_2"
    with pytest.raises(ConfigRetrievalError):
        ConnectorConfig()


def test_no_env_vars() -> None:
    with pytest.raises(ConfigRetrievalError) as exc_info:
        ConnectorConfig()

    errors = exc_info.value.args[1].errors()

    assert errors[0]["msg"] == "Field required"
    assert errors[0]["type"] == "missing"
    assert errors[0]["loc"] == ("opencti",)

    assert errors[1]["msg"] == "Field required"
    assert errors[1]["type"] == "missing"
    assert errors[1]["loc"] == ("connector",)
