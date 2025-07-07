import os
import sys
from copy import deepcopy
from typing import Any, Callable, Union
from unittest.mock import MagicMock, Mock

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from pytest_mock import MockerFixture


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
            "duration_period": "P2D",
            "type": "EXTERNAL_IMPORT",
        },
        "shadowserver": {
            "api_key": "CHANGEME",
            "api_secret": "CHANGEME",
            "marking": "TLP:CLEAR",
            "create_incident": True,
            "incident_severity": "high",
            "incident_priority": "P1",
        },
    }


@pytest.fixture(name="mock_config")
def fixture_mock_config(
    mocker: MockerFixture, config_dict: dict[str, dict[str, Any]]
) -> None:
    environ = deepcopy(os.environ)
    for key, value in config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> Mock:
    def schedule_process(
        message_callback: Callable[[], None], duration_period: Union[int, float]
    ) -> None:
        message_callback()

    helper = mocker.patch("pycti.OpenCTIConnectorHelper", MagicMock())
    helper.schedule_process.side_effect = schedule_process
    helper.connect_id = "test-connector-id"
    helper.connect_name = "Test Connector"
    helper.api.work.initiate_work.return_value = "work-id"
    helper.get_state.return_value = {}
    helper.stix2_create_bundle.return_value = "bundle"
    return helper
