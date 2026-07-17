import json
from unittest.mock import MagicMock

import pytest

from connector.converter_to_stix import ConverterToStix


@pytest.fixture
def converter():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return ConverterToStix(helper=helper)


def test_item_to_sdo_builds_intrusion_set_with_upstream_id(converter):
    item = {
        "standard_id": "intrusion-set--c8d782e1-6566-4c2b-a9f8-87a757c379a4",
        "entity_type": "Intrusion-Set",
        "name": "APT Example",
        "description": "Test intrusion set",
        "confidence": 75,
        "aliases": ["Example Group"],
        "objectLabel": ["RST Threat Library"],
    }

    sdo = converter.item_to_sdo(item, "intrusion-sets", ["RST Threat Library"])

    assert sdo is not None
    payload = json.loads(sdo.serialize())
    assert payload["id"] == item["standard_id"]
    assert payload["name"] == "APT Example"
    assert payload["aliases"] == ["Example Group"]
    assert payload["confidence"] == 75
    assert "RST Threat Library" in payload["labels"]


def test_item_to_sdo_returns_none_when_standard_id_missing(converter):
    item = {"entity_type": "Malware", "name": "No ID Malware"}

    assert converter.item_to_sdo(item, "malware", []) is None
    converter.helper.connector_logger.warning.assert_called()


def test_build_identity_uses_upstream_standard_id(converter):
    identity = converter.build_identity(
        {
            "standard_id": "identity--a1b2c3d4-e5f6-4789-a012-3456789abcde",
            "name": "RST Cloud",
        }
    )

    payload = json.loads(identity.serialize())
    assert payload["id"] == "identity--a1b2c3d4-e5f6-4789-a012-3456789abcde"
    assert payload["name"] == "RST Cloud"
