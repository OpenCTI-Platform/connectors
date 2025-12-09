import json
import os
from unittest import mock

import pytest
from pycti import OpenCTIConnectorHelper
from src.eset import EsetConnector


@pytest.fixture(scope="class")
def setup_config(request):
    os.environ["CONNECTOR_ID"] = "0a669039-bfbf-42b6-8da0-d67ac8b46b4f"
    os.environ["CONNECTOR_SCOPE"] = "report"
    os.environ["CONNECTOR_LOG_LEVEL"] = "debug"
    os.environ["CONNECTOR_AUTO"] = "true"
    os.environ["CONNECTOR_TYPE"] = "INTERNAL_ENRICHMENT"
    os.environ["ESET_API_KEY"] = "changeme"
    os.environ["ESET_API_SECRET"] = "changeme"

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
