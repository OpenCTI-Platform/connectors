from unittest.mock import MagicMock

import stix2
from connector.converter_to_stix import ConverterToStix


def _converter(tlp_level: str = "amber") -> ConverterToStix:
    return ConverterToStix(MagicMock(), tlp_level=tlp_level)


def test_author_is_identity():
    converter = _converter()
    assert converter.author["type"] == "identity"
    assert converter.author["name"] == "CTM360 ThreatCover"


def test_amber_strict_marking():
    converter = _converter("amber+strict")
    assert converter.tlp_marking["definition_type"] == "statement"
    assert converter.tlp_marking["x_opencti_definition"] == "TLP:AMBER+STRICT"


def test_clear_marking_is_opencti_custom_not_white():
    converter = _converter("clear")
    # TLP:CLEAR must be the OpenCTI custom statement marking (definition_type
    # "statement" + x_opencti_definition), not the legacy STIX TLP:WHITE whose
    # definition_type is "tlp" (they share the same deterministic id).
    assert stix2.TLP_WHITE["definition_type"] == "tlp"
    assert converter.tlp_marking["definition_type"] == "statement"
    assert converter.tlp_marking["x_opencti_definition"] == "TLP:CLEAR"


def test_process_objects_attributes_sdo():
    converter = _converter()
    indicator = {
        "type": "indicator",
        "id": "indicator--11111111-1111-4111-8111-111111111111",
        "created": "2024-05-01T00:00:00.000Z",
        "pattern": "[ipv4-addr:value='1.2.3.4']",
        "pattern_type": "stix",
    }

    result = converter.process_objects([indicator])
    assert len(result) == 1
    enriched = result[0]
    assert converter.tlp_marking["id"] in enriched["object_marking_refs"]
    assert enriched["created_by_ref"] == converter.author["id"]


def test_process_objects_passthrough_marking_definition():
    converter = _converter()
    marking = {"type": "marking-definition", "id": "marking-definition--x"}
    result = converter.process_objects([marking])
    assert result == [marking]


def test_process_objects_sco_gets_marking_without_created_by_ref():
    converter = _converter()
    sco = {
        "type": "ipv4-addr",
        "id": "ipv4-addr--22222222-2222-4222-8222-222222222222",
        "value": "1.2.3.4",
    }

    result = converter.process_objects([sco])
    enriched = result[0]
    assert converter.tlp_marking["id"] in enriched["object_marking_refs"]
    assert "created_by_ref" not in enriched


def test_process_objects_skips_invalid():
    converter = _converter()
    result = converter.process_objects(
        ["not-a-dict", {"type": "indicator"}, {"id": "x--1"}]
    )
    assert result == []
