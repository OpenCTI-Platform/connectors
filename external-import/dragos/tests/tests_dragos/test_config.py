import os

import pytest
from dragos.config import Config
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict


@pytest.fixture(name="minimal_config_dict")
def fixture_minimal_config_dict() -> dict:
    return {
        "opencti": {
            "url": "http://test-opencti-url/",
            "token": "test-opencti-token",
        },
        "connector": {
            "id": "test-connector-id",
            "name": "External Import Connector Template",
            "type": "EXTERNAL_IMPORT",
            "scope": "ChangeMe",
            "duration_period": "PT5M",
        },
        "dragos": {
            "api_base_url": "http://test-dragos-url/",
            "api_token": "test-dragos-api-token",
            "import_start_date": "2023-01-01T00:00:00Z",
            "tlp_level": "clear",
        },
    }


@pytest.fixture(
    name="config_dict",
)
def fixture_config_dict() -> dict:
    return {
        "opencti": {
            "json_logging": True,
            "ssl_verify": False,
            "token": "test-opencti-token",
            "url": "http://test-opencti-url/",
        },
        "connector": {
            "auto": False,
            "duration_period": "PT5M",
            "expose_metrics": False,
            "id": "test-connector-id",
            "listen_protocol": "AMQP",
            "listen_protocol_api_path": "/api/callback",
            "listen_protocol_api_port": 7070,
            "listen_protocol_api_ssl": False,
            "listen_protocol_api_uri": "http://127.0.0.1:7070",
            "live_stream_id": None,
            "live_stream_listen_delete": True,
            "live_stream_no_dependencies": False,
            "live_stream_recover_iso_date": None,
            "live_stream_start_timestamp": None,
            "live_stream_with_inferences": False,
            "log_level": "info",
            "metrics_port": 9095,
            "name": "External Import Connector Template",
            "only_contextual": False,
            "queue_protocol": "amqp",
            "queue_threshold": 500,
            "run_and_terminate": False,
            "scope": "ChangeMe",
            "send_to_directory": False,
            "send_to_directory_path": None,
            "send_to_directory_retention": 7,
            "send_to_queue": False,
            "type": "EXTERNAL_IMPORT",
            "validate_before_import": False,
        },
        "dragos": {
            "api_base_url": "http://test-dragos-url/",
            "api_token": "test-dragos-api-token",
            "import_start_date": "2023-01-01T00:00:00Z",
            "tlp_level": "clear",
        },
    }


def test_yaml_config(config_dict) -> None:
    class YamlConfig(Config):
        model_config = SettingsConfigDict(yaml_file="tests_dragos/config.test.yml")

    assert YamlConfig().model_dump(mode="json") == config_dict


def test_dotenv_config(config_dict) -> None:
    class DotEnvConfig(Config):
        model_config = SettingsConfigDict(env_file="tests_dragos/.env.test")

    assert DotEnvConfig().model_dump(mode="json") == config_dict


def test_env_config(config_dict) -> None:
    for key, value in config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value:
                os.environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)

    assert Config().model_dump(mode="json") == config_dict


def test_fail_config() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Config()

    errors = exc_info.value.errors()

    assert errors[0]["msg"] == "Field required"
    assert errors[0]["type"] == "missing"
    assert errors[0]["loc"] == ("connector",)

    assert errors[1]["msg"] == "Field required"
    assert errors[1]["type"] == "missing"
    assert errors[1]["loc"] == ("dragos",)

    assert errors[2]["msg"] == "Field required"
    assert errors[2]["type"] == "missing"
    assert errors[2]["loc"] == ("opencti",)


def test_missing_values(config_dict: dict, minimal_config_dict: dict):
    for key, value in minimal_config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value:
                os.environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)

    config = Config()
    assert config.model_dump(mode="json") == config_dict

    os.environ.pop("OPENCTI_URL")
    with pytest.raises(ValidationError):
        Config()
