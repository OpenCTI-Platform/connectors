from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from sumologic_intel_connector.api_client import SumologicClient

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


def make_indicator(score=None, confidence=50):
    indicator = {
        "id": "indicator--1234",
        "type": "indicator",
        "name": "test-indicator",
        "pattern_type": "stix",
        "confidence": confidence,
        "extensions": {
            OPENCTI_EXTENSION_ID: {
                "extension_type": "property-extension",
                "detection": True,
            }
        },
    }
    if score is not None:
        indicator["extensions"][OPENCTI_EXTENSION_ID]["score"] = score
    return indicator


@pytest.fixture
def sumologic_client():
    helper = MagicMock()
    helper.get_attribute_in_extension.side_effect = (
        lambda key, obj: OpenCTIConnectorHelper.get_attribute_in_extension(key, obj)
    )
    config = MagicMock()
    config.sumologic_intel.api_base_url = "https://api.sumologic.com"
    config.sumologic_intel.access_id = "access-id"
    config.sumologic_intel.access_key.get_secret_value.return_value = "access-key"

    client = SumologicClient(helper=helper, config=config)

    captured = {}

    def fake_send_request(method, url, body, **kwargs):
        captured["body"] = body
        response = MagicMock()
        response.status_code = 200
        response.ok = True
        return response

    client._send_request = MagicMock(side_effect=fake_send_request)
    return client, captured


def test_score_is_sent_as_confidence(sumologic_client):
    """The OpenCTI score MUST override the confidence field sent to Sumologic."""
    client, captured = sumologic_client
    indicator = make_indicator(score=80, confidence=50)

    client.upload_stix_indicator(source_name="OpenCTI", stix_indicator=indicator)

    uploaded = captured["body"]["indicators"][0]
    assert uploaded["confidence"] == 80
    assert "extensions" not in uploaded


def test_confidence_unchanged_when_no_score(sumologic_client):
    """When no score is present, the confidence field MUST remain untouched."""
    client, captured = sumologic_client
    indicator = make_indicator(score=None, confidence=42)

    client.upload_stix_indicator(source_name="OpenCTI", stix_indicator=indicator)

    uploaded = captured["body"]["indicators"][0]
    assert uploaded["confidence"] == 42
    assert "extensions" not in uploaded
