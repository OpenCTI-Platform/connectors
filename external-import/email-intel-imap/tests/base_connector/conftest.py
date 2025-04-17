import os
from copy import deepcopy
from typing import Any

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
