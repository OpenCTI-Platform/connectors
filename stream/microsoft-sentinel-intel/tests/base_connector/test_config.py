import os
from pathlib import Path
from typing import Any

import pytest
from base_connector.config import BaseConnectorSettings
from base_connector.errors import ConfigRetrievalError
from pycti import OpenCTIConnectorHelper
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


@pytest.mark.usefixtures("mocked_minimal_environ")
def test_default_config(config_dict: dict[str, dict[str, Any]]) -> None:
    config = ConnectorSettings()
    assert config.model_dump_pycti() == config_dict


@pytest.mark.usefixtures("mocked_minimal_environ")
def test_opencti_default_config(
    mocker, minimal_config_dict: dict, config_dict: dict[str, dict[str, Any]]
) -> None:
    mocker.patch("pycti.connector.opencti_connector_helper.OpenCTIApiClient")
    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper({"connector": {"type": "STREAM"}})
    assert config.model_dump_pycti() == {
        "opencti": {
            "url": helper.opencti_url,
            "token": helper.opencti_token,
            "ssl_verify": helper.opencti_ssl_verify,
            "json_logging": helper.opencti_json_logging,
        },
        "connector": {
            "id": helper.connect_id,
            "name": helper.connect_name,
            "type": helper.connect_type,
            "scope": helper.connect_scope,
            "log_level": helper.log_level.lower(),
            "live_stream_id": helper.connect_live_stream_id,
            "live_stream_listen_delete": helper.connect_live_stream_listen_delete,
            "live_stream_no_dependencies": helper.connect_live_stream_no_dependencies,
            "live_stream_with_inferences": helper.connect_live_stream_with_inferences,
            "live_stream_recover_iso_date": helper.connect_live_stream_recover_iso_date,
            "live_stream_start_timestamp": helper.connect_live_stream_start_timestamp,
            "listen_protocol": helper.listen_protocol,
            "listen_protocol_uri": helper.listen_protocol_api_uri,
            "listen_protocol_path": helper.listen_protocol_api_path,
            "listen_protocol_ssl": helper.listen_protocol_api_ssl,
            "listen_protocol_port": helper.listen_protocol_api_port,
            "auto": helper.connect_auto,
            "expose_metrics": False,  # Not saved in helper
            "metrics_port": 9095,  # Not saved in helper
            "only_contextual": helper.connect_only_contextual,
            "run_and_terminate": helper.connect_run_and_terminate,
            "validate_before_import": helper.connect_validate_before_import,
            "queue_protocol": helper.queue_protocol,
            "queue_threshold": helper.connect_queue_threshold,
            "send_to_queue": helper.bundle_send_to_queue,
            "send_to_directory": helper.bundle_send_to_directory,
            "send_to_directory_path": helper.bundle_send_to_directory_path,
            "send_to_directory_retention": helper.bundle_send_to_directory_retention,
        },
    }


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
