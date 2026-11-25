import importlib.util
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pycti import (
    AttackPattern,
    Campaign,
    Identity,
    Indicator,
    IntrusionSet,
    Malware,
    Tool,
    Vulnerability,
)


def _load_converter_modules():
    """Import converter modules without requiring connectors-sdk via package init."""
    try:
        from connector.converter_to_stix import ConverterToStix
        from connector.feed_converter import ThreatTypes

        return ConverterToStix, ThreatTypes
    except ModuleNotFoundError as exc:
        if getattr(exc, "name", None) != "connectors_sdk":
            raise

    src_connector = Path(__file__).resolve().parents[2] / "src" / "connector"
    if "connector" not in sys.modules:
        pkg = types.ModuleType("connector")
        pkg.__path__ = [str(src_connector)]
        sys.modules["connector"] = pkg

    def _load(mod_name: str, filename: str):
        full_name = f"connector.{mod_name}"
        if full_name in sys.modules:
            return sys.modules[full_name]
        spec = importlib.util.spec_from_file_location(
            full_name, src_connector / filename
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[full_name] = module
        spec.loader.exec_module(module)
        return module

    feed_converter = _load("feed_converter", "feed_converter.py")
    converter_to_stix = _load("converter_to_stix", "converter_to_stix.py")
    return converter_to_stix.ConverterToStix, feed_converter.ThreatTypes


ConverterToStix, ThreatTypes = _load_converter_modules()


def _helper():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return helper


def _converter(**kwargs):
    defaults = {
        "min_score_detection": {
            "IPv4-Addr": 45,
            "Domain-Name": 45,
            "Url": 45,
            "StixFile": 45,
            "Network-Traffic": 45,
        },
        "create_custom_ttps": True,
        "create_mitre_ttps": True,
    }
    defaults.update(kwargs)
    return ConverterToStix(_helper(), **defaults)


def _src():
    return {"example.com": "https://example.com/report"}


def test_create_stix_objects_orders_author_marking_entities_relationships():
    converter = _converter(create_mitre_ttps=False)

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
            "src": _src(),
        },
        sector_id: {
            "name": "Financial",
            "type": "sector",
            "src": _src(),
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


@pytest.mark.parametrize(
    ("threat_type", "expected_type", "malware_types", "id_factory"),
    [
        (ThreatTypes.MALWARE, "malware", None, lambda n: Malware.generate_id(n)),
        (
            ThreatTypes.RANSOMWARE,
            "malware",
            ["ransomware"],
            lambda n: Malware.generate_id(n),
        ),
        (
            ThreatTypes.BACKDOOR,
            "malware",
            ["backdoor"],
            lambda n: Malware.generate_id(n),
        ),
        (
            ThreatTypes.RAT,
            "malware",
            ["remote-access-trojan"],
            lambda n: Malware.generate_id(n),
        ),
        (
            ThreatTypes.EXPLOIT,
            "malware",
            ["exploit-kit"],
            lambda n: Malware.generate_id(n),
        ),
        (
            ThreatTypes.CRYPTOMINER,
            "malware",
            ["resource-exploitation"],
            lambda n: Malware.generate_id(n),
        ),
        (
            ThreatTypes.GROUP,
            "intrusion-set",
            None,
            lambda n: IntrusionSet.generate_id(n),
        ),
        (ThreatTypes.CAMPAIGN, "campaign", None, lambda n: Campaign.generate_id(n)),
        (ThreatTypes.TOOL, "tool", None, lambda n: Tool.generate_id(n)),
    ],
)
def test_make_threat_type_matrix(
    threat_type, expected_type, malware_types, id_factory
):
    converter = _converter()
    name = f"Sample {threat_type}"
    obj = converter._make_threat(
        id_factory(name),
        {
            "name": name,
            "type": threat_type,
            "aliases": ["sample_threat"],
            "src": _src(),
        },
    )

    assert obj is not None
    assert obj.type == expected_type
    assert obj.name == name
    if malware_types is not None:
        assert list(obj.malware_types) == malware_types


def test_make_threat_custom_ttp_attack_pattern():
    converter = _converter(create_custom_ttps=True, create_mitre_ttps=False)
    obj = converter._make_threat(
        AttackPattern.generate_id("Custom Technique"),
        {
            "name": "Custom Technique",
            "type": ThreatTypes.TTP,
            "aliases": ["custom_technique"],
            "src": _src(),
        },
    )
    assert obj is not None
    assert obj.type == "attack-pattern"


def test_make_threat_mitre_ttp_attack_pattern():
    converter = _converter(create_custom_ttps=False, create_mitre_ttps=True)
    obj = converter._make_threat(
        AttackPattern.generate_id(name="Command and Scripting Interpreter", x_mitre_id="T1059"),
        {
            "name": "Command and Scripting Interpreter",
            "type": ThreatTypes.TTP,
            "mitre_id": "T1059",
            "src": _src(),
        },
    )
    assert obj is not None
    assert obj.type == "attack-pattern"
    assert obj.x_mitre_id == "T1059"


def test_make_threat_ttp_disabled_returns_none():
    converter = _converter(create_custom_ttps=False, create_mitre_ttps=False)
    assert (
        converter._make_threat(
            AttackPattern.generate_id("Custom Technique"),
            {
                "name": "Custom Technique",
                "type": ThreatTypes.TTP,
                "aliases": ["custom_technique"],
                "src": _src(),
            },
        )
        is None
    )
    assert (
        converter._make_threat(
            AttackPattern.generate_id(
                name="Command and Scripting Interpreter", x_mitre_id="T1059"
            ),
            {
                "name": "Command and Scripting Interpreter",
                "type": ThreatTypes.TTP,
                "mitre_id": "T1059",
                "src": _src(),
            },
        )
        is None
    )


def test_make_threat_vulnerability_cve_and_named():
    converter = _converter()
    cve = converter._make_threat(
        Vulnerability.generate_id("CVE-2024-1234"),
        {"name": "cve-2024-1234", "type": "vulnerability", "src": _src()},
    )
    assert cve is not None
    assert cve.type == "vulnerability"
    assert cve.external_references[0].external_id == "CVE-2024-1234"

    named = converter._make_threat(
        Vulnerability.generate_id("PrintNightmare"),
        {
            "name": "PrintNightmare",
            "type": ThreatTypes.VULNERABILITY,
            "aliases": ["printnightmare_vuln"],
            "src": _src(),
        },
    )
    assert named is not None
    assert named.type == "vulnerability"
    assert named.x_opencti_aliases == ["printnightmare_vuln"]


def test_make_threat_unknown_type_returns_none():
    converter = _converter()
    assert (
        converter._make_threat(
            Malware.generate_id("Nope"),
            {"name": "Nope", "type": "unknown-type", "src": _src()},
        )
        is None
    )


def test_indicator_detection_flag_uses_score_threshold():
    converter = _converter()
    now = datetime(2024, 1, 1, tzinfo=timezone.utc)
    pattern = "[domain-name:value = 'evil.example']"
    base = {
        "name": "evil.example",
        "descr": "test",
        "tags": [],
        "threats": [],
        "src": [{"name": "example.com", "url": "https://example.com/report"}],
        "confidence": 70,
        "pattern": pattern,
        "observable_type": "Domain-Name",
        "fseen": now,
        "lseen": now,
        "collect": now,
    }

    detected = converter._make_indicator(
        Indicator.generate_id(pattern + "|high"), {**base, "score": 80}
    )
    not_detected = converter._make_indicator(
        Indicator.generate_id(pattern + "|low"), {**base, "score": 45}
    )

    assert detected.x_opencti_detection is True
    assert not_detected.x_opencti_detection is False


def test_relationship_skipped_when_endpoint_missing():
    converter = _converter()
    now = datetime(2024, 1, 1, tzinfo=timezone.utc)
    indicator_id = Indicator.generate_id("[domain-name:value = 'evil.example']")
    missing_threat = Malware.generate_id("Missing")

    objects = converter.create_stix_objects(
        {
            indicator_id: {
                "name": "evil.example",
                "descr": "test",
                "tags": [],
                "threats": [],
                "src": [{"name": "example.com", "url": "https://example.com/report"}],
                "score": 80,
                "confidence": 70,
                "pattern": "[domain-name:value = 'evil.example']",
                "observable_type": "Domain-Name",
                "fseen": now,
                "lseen": now,
                "collect": now,
            }
        },
        {},
        [
            (
                indicator_id,
                missing_threat,
                now,
                now,
                [{"name": "example.com", "url": "https://example.com/report"}],
            )
        ],
    )

    assert not any(obj.type == "relationship" for obj in objects)
