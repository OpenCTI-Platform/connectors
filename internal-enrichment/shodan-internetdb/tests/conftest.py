import json
import os
import sys
from unittest.mock import Mock

import pytest
from pycti import OpenCTIConnectorHelper
from pytest_mock.plugin import MockerFixture

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(name="helper")
def fixture_helper(mocker: MockerFixture) -> OpenCTIConnectorHelper:
    mocker.patch("pycti.OpenCTIApiClient.health_check", lambda x: True)
    mocker.patch("pycti.OpenCTIApiConnector.ping")
    mocker.patch("pycti.OpenCTIApiConnector.register")
    return OpenCTIConnectorHelper(
        {
            "connector": {
                "name": "name",
                "scope": "IPv4-Addr",
                "type": "INTERNAL_ENRICHMENT",
                "send_to_queue": False,
            },
            "opencti": {"token": "token", "url": "localhost", "json_logging": False},
        }
    )


@pytest.fixture(name="mocked_requests")
def fixture_mocked_requests(
    mocker: MockerFixture,
) -> MockerFixture:
    response = Mock()
    response.status_code = 200
    response.text = json.dumps(
        {
            "cpes": [],
            "hostnames": [],
            "ip": "123.123.123.123",
            "ports": [53],
            "tags": [],
            "vulns": [],
        }
    )

    return mocker.patch(
        "shodan_internetdb.client.requests.Session.get",
        return_value=response,
    )
