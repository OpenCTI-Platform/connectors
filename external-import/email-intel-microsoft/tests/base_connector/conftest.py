import os
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from pytest_mock import MockerFixture


@pytest.fixture(
    name="config_dict",
)
def fixture_config_dict() -> dict[str, dict[str, Any]]:
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
            "send_to_queue": True,
            "type": "EXTERNAL_IMPORT",
            "validate_before_import": False,
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


@pytest.fixture(name="mocked_config")
def fixture_mocked_config() -> Mock:
    config = Mock()
    config.tlp_level = "white"
    return config


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> MagicMock:
    helper = mocker.patch("pycti.OpenCTIConnectorHelper", MagicMock())
    helper.connect_id = "test-connector-id"
    helper.connect_name = "Test Connector"
    helper.api.work.initiate_work.return_value = "work-id"
    helper.get_state.return_value = {"last_run": "2025-04-17T15:20:00Z"}
    helper.stix2_create_bundle.return_value = "bundle"
    return helper
