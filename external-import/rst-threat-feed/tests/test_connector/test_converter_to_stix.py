from datetime import datetime, timezone
from unittest.mock import MagicMock

from pycti import Identity, Indicator, Malware

from connector.converter_to_stix import ConverterToStix


def _helper():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return helper


def test_create_stix_objects_orders_author_marking_entities_relationships():
    helper = _helper()
    converter = ConverterToStix(
        helper,
        min_score_detection={
            "IPv4-Addr": 45,
            "Domain-Name": 45,
            "Url": 45,
            "StixFile": 45,
        },
        create_custom_ttps=True,
        create_mitre_ttps=False,
    )

    now = datetime(2024, 1, 1, tzinfo=timezone.utc)
    indicator_id = Indicator.generate_id("[domain-name:value = 'evil.example']")
    malware_id = Malware.generate_id("Emotet")
    sector_id = Identity.generate_id("Financial", "class")

    iocs = {
        indicator_id: {
            "name": "evil.example",
            "descr": "test",
            "tags": ["c2"],
            "threats": ["emotet"],
            "src": [{"name": "example.com", "url": "https://example.com/report"}],
            "score": 80,
            "confidence": 70,
            "pattern": "[domain-name:value = 'evil.example']",
            "observable_type": "Domain-Name",
            "fseen": now,
            "lseen": now,
            "collect": now,
        }
    }
    threats = {
        malware_id: {
            "name": "Emotet",
            "type": "malware",
            "aliases": ["emotet"],
            "src": {"example.com": "https://example.com/report"},
        },
        sector_id: {
            "name": "Financial",
            "type": "sector",
            "src": {"example.com": "https://example.com/report"},
        },
    }
    mapping = [
        (
            indicator_id,
            malware_id,
            now,
            now,
            [{"name": "example.com", "url": "https://example.com/report"}],
        ),
        (
            indicator_id,
            sector_id,
            now,
            now,
            [{"name": "example.com", "url": "https://example.com/report"}],
        ),
    ]

    objects = converter.create_stix_objects(iocs, threats, mapping)
    types = [obj.type for obj in objects]

    assert types[0] == "identity"
    assert objects[0].identity_class == "organization"
    assert types[1] == "marking-definition"
    assert "indicator" in types
    assert "malware" in types
    assert types.count("identity") == 2 
    assert types.index("relationship") > types.index("indicator")
    assert types.index("relationship") > types.index("malware")

    emitted_ids = {obj.id for obj in objects}
    relationships = [obj for obj in objects if obj.type == "relationship"]
    assert len(relationships) == 2
    for rel in relationships:
        assert rel.source_ref in emitted_ids
        assert rel.target_ref in emitted_ids

    sector = next(
        obj
        for obj in objects
        if obj.type == "identity" and getattr(obj, "identity_class", None) == "class"
    )
    assert sector.name == "Financial"
