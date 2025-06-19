import os
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from pycti import OpenCTIConnectorHelper

# from socprime_microsoft.config import ConnectorSettings
from pytest_mock import MockerFixture


@pytest.fixture(name="socprime_config_dict")
def fixture_socprime_config_dict() -> dict[str, dict[str, Any]]:
    return {
        "opencti": {
            "url": "http://test-opencti-url/",
            "token": "test-opencti-token",
        },
        "connector": {
            "id": "test-connector-id",
            "name": "Soc Prime",
            "type": "EXTERNAL_IMPORT",
            "scope": "socprime",
            "log_level": "error",
            "update_existing_data": True,
        },
        "socprime": {
            "api_key": "api-key",
            "content_list_name": "name1,name2",
            "job_ids": "job1,job2",
            "siem_type": "devo,snowflake",
            "indicator_siem_type": "ChangeMe",
            "interval_sec": 2000,
        },
    }


@pytest.fixture(name="mock_socprime_config")
def fixture_mock_socprime_config(
    mocker: MockerFixture, socprime_config_dict: dict[str, dict[str, Any]]
) -> None:
    environ = deepcopy(os.environ)
    for key, value in socprime_config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)


@pytest.fixture(name="mocked_tdm_api_client_requests")
def fixture_mocked_tdm_api_client(mocker: MockerFixture) -> None:
    mocked_tdm_api_client_requests = mocker.patch("socprime.tdm_api_client.requests")
    mocked_tdm_api_client_requests.request.return_value = Mock(ok=True, json=lambda: {})
    return mocked_tdm_api_client_requests


@pytest.fixture(name="mocked_mitre_attack_requests")
def fixture_mocked_mitre_attack_requests(mocker: MockerFixture) -> Mock:
    mocked_mitre_attack_requests = mocker.patch("socprime.mitre_attack.requests")
    mocked_mitre_attack_requests.get.return_value = Mock(
        ok=True, json=lambda: {"objects": []}
    )
    return mocked_mitre_attack_requests


@pytest.fixture(name="mocked_opencti_api_client")
def fixture_mocked_opencti_api_client(mocker: MockerFixture) -> Mock:
    return mocker.patch("pycti.connector.opencti_connector_helper.OpenCTIApiClient")


@pytest.fixture(name="mocked_opencti_helper")
def fixture_mocked_helper(
    mocker: MockerFixture, mocked_opencti_api_client: None
) -> Mock:
    mocked_opencti_helper = mocker.patch(
        "socprime.core.OpenCTIConnectorHelper", OpenCTIConnectorHelper
    )
    # Mock the OpenCTI Connector Helper methods
    mocked_opencti_helper.send_stix2_bundle = MagicMock()
    mocked_opencti_helper.force_ping = MagicMock()
    mocked_opencti_helper.connect_run_and_terminate = True
    return mocked_opencti_helper
