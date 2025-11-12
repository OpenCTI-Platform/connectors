import os
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture


@pytest.fixture(name="config_dict")
def fixture_config_dict() -> dict[str, dict[str, Any]]:
    return {
        "opencti": {
            "json_logging": True,
            "ssl_verify": False,
            "token": "test-opencti-token",
            "url": "http://test-opencti-url/",
        },
        "connector": {
            "live_stream_id": "live-stream-id",
            "live_stream_listen_delete": True,
            "live_stream_no_dependencies": True,
            "live_stream_with_inferences": False,
            "live_stream_recover_iso_date": None,
            "live_stream_start_timestamp": None,
            "listen_protocol": "AMQP",
            "listen_protocol_path": "/api/callback",
            "listen_protocol_port": 7070,
            "listen_protocol_ssl": False,
            "listen_protocol_uri": "http://127.0.0.1:7070",
            "auto": False,
            "expose_metrics": False,
            "id": "test-connector-id",
            "log_level": "info",
            "metrics_port": 9095,
            "name": "Stream Connector",
            "only_contextual": False,
            "queue_protocol": "amqp",
            "queue_threshold": 500,
            "run_and_terminate": False,
            "scope": "ChangeMe",
            "send_to_directory": False,
            "send_to_directory_path": None,
            "send_to_directory_retention": 7,
            "send_to_queue": True,
            "type": "STREAM",
            "validate_before_import": False,
        },
    }


@pytest.fixture(name="minimal_config_dict")
def fixture_minimal_config_dict() -> dict[str, dict[str, Any]]:
    return {
        "opencti": {
            "token": "test-opencti-token",
            "url": "http://test-opencti-url/",
        },
        "connector": {
            "live_stream_id": "live-stream-id",
            "id": "test-connector-id",
            "log_level": "info",
            "name": "Stream Connector",
            "scope": "ChangeMe",
        },
    }


@pytest.fixture(name="mocked_environ")
def fixture_mocked_environ(
    mocker: MockerFixture, config_dict: dict[str, dict[str, Any]]
) -> None:
    environ = deepcopy(os.environ)
    for key, value in config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)


@pytest.fixture(name="mocked_minimal_environ")
def fixture_mocked_minimal_environ(
    mocker: MockerFixture, minimal_config_dict: dict[str, dict[str, Any]]
) -> None:
    environ = deepcopy(os.environ)
    for key, value in minimal_config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> MagicMock:
    # helper = mocker.patch("pycti.OpenCTIConnectorHelper")
    # helper.connect_id = "test-connector-id"
    # helper.connect_name = "Test Connector"
    # helper.api.work.initiate_work.return_value = "work-id"
    # helper.get_state.return_value = {"last_run": "2025-04-17T15:20:00Z"}
    # helper.stix2_create_bundle.return_value = "bundle"
    return {}
