import os
import sys
from unittest.mock import Mock

import pytest
from pycti import OpenCTIConnectorHelper
from pytest_mock.plugin import MockerFixture

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(name="mocked_campaign")
def fixture_mocked_campaign() -> dict:
    return {
        "created": "2025-03-01T00:00:00.000Z",
        "modified": "2025-03-11T00:00:00.000Z",  # 10 days later
        "description": "Campaign Description",
        "external_references": [
            {"source_name": "Campaign Source", "url": "https://www.url-campaign.com"}
        ],
        "id": "campaign--uuid",
        "name": "Campaign Name",
        "objective": "Campaign Objective",
        "spec_version": "1.0",
        "type": "campaign",
    }


@pytest.fixture(name="mocked_threat_actor")
def fixture_mocked_threat_actor() -> dict:
    return {
        "created": "2025-03-02T00:00:00.000Z",
        "modified": "2025-03-12T00:00:00.000Z",  # 10 days later
        "id": "threat-actor--uuid",
        "name": "Threat Actor Name",
        "spec_version": "1.1",
        "type": "threat-actor",
    }


@pytest.fixture(name="mocked_attack_pattern")
def fixture_mocked_attack_pattern() -> dict:
    return {
        "created": "2025-03-03T00:00:00.000Z",
        "modified": "2025-03-13T00:00:00.000Z",  # 10 days later
        "id": "attack-pattern--uuid",
        "name": "Attack Pattern Name",
        "spec_version": "1.2",
        "type": "attack-pattern",
    }


@pytest.fixture(name="mocked_malware")
def fixture_mocked_malware() -> dict:
    return {
        "created": "2025-03-04T00:00:00.000Z",
        "modified": "2025-03-14T00:00:00.000Z",  # 10 days later
        "id": "malware--uuid",
        "malware_types": ["Malware Type"],
        "name": "Malware Name",
        "spec_version": "1.3",
        "type": "malware",
    }


@pytest.fixture(name="mocked_tool")
def fixture_mocked_tool() -> dict:
    return {
        "created": "2025-03-05T00:00:00.000Z",
        "modified": "2025-03-15T00:00:00.000Z",  # 10 days later
        "id": "tool--uuid",
        "name": "Tool Name",
        "spec_version": "1.4",
        "type": "tool",
    }


@pytest.fixture(name="mocked_relationship")
def fixture_mocked_relationship() -> dict:
    return {
        "id": "relationship--uuid",
        "relationship_type": "uses",
        "source_ref": "campaign--uuid",
        "spec_version": "1.5",
        "target_ref": "attack-pattern--uuid",
        "type": "relationship",
    }


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> OpenCTIConnectorHelper:
    mocked_helper = mocker.patch("pycti.OpenCTIConnectorHelper")

    mocked_helper.api = Mock()
    mocked_helper.connector_logger = Mock()
    mocked_helper.connect_id = Mock()
    mocked_helper.connect_name = "Connect Name"
    mocked_helper.get_state = lambda: None

    return mocked_helper


@pytest.fixture(name="mocked_requests")
def fixture_mocked_requests(
    mocker: MockerFixture,
    mocked_campaign: dict,
    mocked_threat_actor: dict,
    mocked_attack_pattern: dict,
    mocked_malware: dict,
    mocked_tool: dict,
    mocked_relationship: dict,
) -> MockerFixture:
    response = Mock()
    response.status_code = 200
    response.json = lambda: {
        "objects": [
            mocked_campaign,
            mocked_threat_actor,
            mocked_attack_pattern,
            mocked_malware,
            mocked_tool,
            mocked_relationship,
        ]
    }
    return mocker.patch(
        "src.external_import_connector.client_api.requests.Session.get",
        return_value=response,
    )
