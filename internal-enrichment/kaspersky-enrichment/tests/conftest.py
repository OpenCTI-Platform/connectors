import json
import os
import sys
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from connector import KasperskyConnector
from kaspersky_client.api_client import KasperskyClient


@pytest.fixture(scope="class")
def setup_config(request):
    """
    Setup configuration for class method
    Create fake pycti OpenCTI helper
    """
    request.cls.mock_helper = MagicMock()
    request.cls.mock_config = Mock()
    request.cls.connector = KasperskyConnector(
        config=request.cls.mock_config, helper=request.cls.mock_helper
    )
    request.cls.api_client = KasperskyClient(
        helper=request.cls.mock_helper,
        base_url="https://test.url/",
        api_key="key",
        params={},
    )

    yield


@pytest.fixture
def enrichment_data():
    with open(
        os.path.join(
            os.path.join(os.path.dirname(__file__), "fixtures"), "enrichment_data.json"
        )
    ) as file:
        return json.load(file)


@pytest.fixture
def fixture_data() -> dict[str, Any]:
    return {
        "event_type": "INTERNAL_ENRICHMENT",
        "entity_id": "hostname--01a98dfa-fdb3-4da1-be9a-ed06c3f8e940",
        "entity_type": "Hostname",
        "stix_entity": {
            "id": "hostname--01a98dfa-fdb3-4da1-be9a-ed06c3f8e940",
            "spec_version": "2.1",
            "x_opencti_score": 0,
            "value": "hostname-to-enrich.com",
            "x_opencti_id": "b2a3351f-df4a-4f7d-bc3e-7732f00e29fc",
            "x_opencti_type": "Hostname",
            "type": "hostname",
        },
        "stix_objects": [
            {
                "id": "hostname--01a98dfa-fdb3-4da1-be9a-ed06c3f8e940",
                "spec_version": "2.1",
                "x_opencti_score": 0,
                "value": "hostname-to-enrich.com",
                "x_opencti_id": "b2a3351f-df4a-4f7d-bc3e-7732f00e29fc",
                "x_opencti_type": "Hostname",
                "type": "hostname",
            }
        ],
        "enrichment_entity": {
            "id": "b2a3351f-df4a-4f7d-bc3e-7732f00e29fc",
            "standard_id": "hostname--01a98dfa-fdb3-4da1-be9a-ed06c3f8e940",
            "entity_type": "Hostname",
            "parent_types": [
                "Basic-Object",
                "Stix-Object",
                "Stix-Core-Object",
                "Stix-Cyber-Observable",
            ],
            "spec_version": "2.1",
            "created_at": "2025-12-24T08:15:03.998Z",
            "updated_at": "2025-12-24T08:15:09.337Z",
            "objectOrganization": [],
            "creators": [
                {"id": "88ec0c6a-13ce-5e39-b486-354fe4a7084f", "name": "admin"}
            ],
            "createdBy": None,
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
            "objectLabel": [],
            "externalReferences": [],
            "observable_value": "hostname-to-enrich.com",
            "x_opencti_description": None,
            "x_opencti_score": 0,
            "indicators": [],
            "value": "hostname-to-enrich.com",
            "importFiles": [],
            "createdById": None,
            "objectMarkingIds": [],
            "objectLabelIds": [],
            "externalReferencesIds": [],
            "indicatorsIds": [],
            "importFilesIds": [],
        },
    }
