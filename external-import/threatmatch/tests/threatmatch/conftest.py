import os
import time
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture


@pytest.fixture(name="config_dict")
def fixture_config_dict() -> dict[str, Any]:
    return {
        "opencti": {
            "url": "http://test-opencti-url/",
            "token": "test-opencti-token",
        },
        "connector": {
            "id": "threatmatch-connector-id",
            "type": "EXTERNAL_IMPORT",
            "name": "ThreatMatch",
            "scope": "threatmatch",
            "log_level": "info",
            "duration_period": "P1D",
        },
        "threatmatch": {
            "url": "https://test-threatmatch-url/",
            "client_id": "threatmatch-client-id",
            "client_secret": "threatmatch-client-secret",
            "import_from_date": "2025-01-01 00:00",
            "import_profiles": True,
            "import_alerts": True,
            "import_iocs": True,
            "tlp_level": "amber",
        },
    }


@pytest.fixture(name="mock_config")
def mock_config(mocker: MockerFixture, config_dict: dict[str, Any]) -> None:
    environ = deepcopy(os.environ)
    for key, value in config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)

    # Ensure the timezone is set to UTC for consistent datetime handling
    os.environ["TZ"] = "UTC"
    time.tzset()

    mocker.patch("os.environ", environ)


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> MockerFixture:
    helper = mocker.patch("main.OpenCTIConnectorHelper", MagicMock())
    helper.get_state.return_value = {}
    helper.api.work.initiate_work.return_value = "work-id"
    return helper
