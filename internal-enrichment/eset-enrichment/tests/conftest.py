import json
import os
import sys
from unittest import mock

import pytest
from pycti import OpenCTIConnectorHelper

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from src.eset import EsetConnector  # noqa: E402


@pytest.fixture(scope="class")
def setup_config(request):
    env = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "changeme",
        "CONNECTOR_ID": "0a669039-bfbf-42b6-8da0-d67ac8b46b4f",
        "CONNECTOR_SCOPE": "report",
        "CONNECTOR_LOG_LEVEL": "debug",
        "CONNECTOR_AUTO": "true",
        "CONNECTOR_TYPE": "INTERNAL_ENRICHMENT",
        "ESET_API_KEY": "changeme",
        "ESET_API_SECRET": "changeme",
    }

    # Restore the environment afterwards so that it doesn't leak into other tests
    with mock.patch.dict(os.environ, env):
        with mock.patch("pycti.connector.opencti_connector_helper.OpenCTIApiClient"):
            with mock.patch.object(OpenCTIConnectorHelper, "send_stix2_bundle"):
                request.cls.connector = EsetConnector()
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
def report_payload():
    return b"THIS IS MOCK REPORT"
