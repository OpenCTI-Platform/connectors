from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture


@pytest.fixture
def config_dict() -> dict[str, Any]:
    return {
        "opencti": {
            "url": "http://test-opencti-url/",
            "token": "test-opencti-token",
        },
        "connector": {
            "id": "ctx-connector-id",
            "type": "EXTERNAL_IMPORT",
            "name": "CyberThreatExchange",
            "scope": "cyberthreatexchange",
            "log_level": "info",
        },
        "cyberthreatexchange": {
            "base_url": "https://test-ctx-url/",
            "api_key": "test-api-key",
            "feed_ids": "feed-1,feed-2",
            "interval_hours": "1",
        },
    }


@pytest.fixture
def mock_config(config_dict: dict[str, Any], monkeypatch: pytest.MonkeyPatch):
    for key, value in config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                monkeypatch.setenv(f"{key.upper()}_{sub_key.upper()}", str(sub_value))

    yield


@pytest.fixture
def mocked_helper(mocker: MockerFixture):
    helper = MagicMock()
    mocker.patch("connector.OpenCTIConnectorHelper", return_value=helper)
    helper.get_state.return_value = {}
    helper.api.work.initiate_work.return_value = "work-id"
    helper.connect_id = "connector-id"
    helper.connect_name = "CyberThreatExchange"
    yield helper


@pytest.fixture
def mock_session(mocker: MockerFixture) -> MagicMock:
    session = MagicMock()
    mocker.patch("connector.requests.Session", return_value=session)
    return session
