from unittest.mock import Mock

from connectors_sdk.models import (
    URL,
    AttackPattern,
    AutonomousSystem,
    DomainName,
    EmailAddress,
    File,
    Indicator,
    IntrusionSet,
    IPV6Address,
    Malware,
    Organization,
    Relationship,
    Sighting,
    Text,
)
from connectors_sdk.models.enums import RelationshipType
from flashpoint_connector.indicator_converter_to_stix import IndicatorConverterToStix


def _build_converter() -> IndicatorConverterToStix:
    helper = Mock()
    helper.connector_logger = Mock()
    return IndicatorConverterToStix(helper=helper)


def test_convert_extracted_config_indicator_to_stix_should_create_text_indicator():
    converter = _build_converter()
    indicator = {
        "id": "ind-anon-001",
        "type": "extracted_config",
        "value": '{"Hosts":"203.0.113.10,,example.org","urls":["http://example.com/path/config"],"c2":["198.51.100.21","https://example.net/endpoint"]}',
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "score": {"value": "malicious"},
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    assert len(octi_objects) > 0
    indicator_obj = next(obj for obj in octi_objects if isinstance(obj, Indicator))
    assert "text:value" in indicator_obj.pattern
    text_objects = [obj for obj in octi_objects if isinstance(obj, Text)]
    assert len(text_objects) == 1
    assert any(
        isinstance(obj, Relationship) and obj.type == RelationshipType.BASED_ON
        for obj in octi_objects
    )


def test_convert_extracted_config_indicator_to_stix_should_support_json_string_value():
    converter = _build_converter()
    indicator = {
        "id": "ind-anon-002",
        "type": "extracted_config",
        "value": '{"type":"stealer","urls":["http://example.org/collector"],"Hosts":"one.example.com"}',
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    assert len(octi_objects) > 0
    indicator_obj = next(obj for obj in octi_objects if isinstance(obj, Indicator))
    assert "text:value" in indicator_obj.pattern
    text_objects = [obj for obj in octi_objects if isinstance(obj, Text)]
    assert len(text_objects) == 1
    assert (
        text_objects[0].value
        == '{"type":"stealer","urls":["http://example.org/collector"],"Hosts":"one.example.com"}'
    )


def test_convert_indicator_to_stix_should_use_md5_pattern_for_file_hash():
    converter = _build_converter()
    md5_hash = "44d88612fea8a8f36de82e1278abb02f"
    indicator = {
        "id": "ind-file-md5",
        "type": "file",
        "value": md5_hash,
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    indicator_obj = next(obj for obj in octi_objects if isinstance(obj, Indicator))
    assert "hashes.MD5" in indicator_obj.pattern
    assert "hashes.'SHA-256'" not in indicator_obj.pattern


def test_convert_indicator_to_stix_should_use_sha1_pattern_for_file_hash():
    converter = _build_converter()
    sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    indicator = {
        "id": "ind-file-sha1",
        "type": "file",
        "value": sha1_hash,
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    indicator_obj = next(obj for obj in octi_objects if isinstance(obj, Indicator))
    assert (
        "hashes.'SHA-1'" in indicator_obj.pattern
        or "hashes.SHA-1" in indicator_obj.pattern
    )
    assert "hashes.'SHA-256'" not in indicator_obj.pattern


def test_convert_indicator_to_stix_should_use_sha256_pattern_for_file_hash():
    converter = _build_converter()
    sha256_hash = "e3b0c44298fc1c149afbf4c8996fb924" "27ae41e4649b934ca495991b7852b855"
    indicator = {
        "id": "ind-file-sha256",
        "type": "file",
        "value": sha256_hash,
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    indicator_obj = next(obj for obj in octi_objects if isinstance(obj, Indicator))
    assert (
        "hashes.'SHA-256'" in indicator_obj.pattern
        or "hashes.SHA-256" in indicator_obj.pattern
    )


def test_convert_indicator_to_stix_should_return_empty_for_unknown_type():
    converter = _build_converter()
    indicator = {
        "id": "ind-fallback-001",
        "ioc_type": "ipv4",
        "ioc_value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    assert len(octi_objects) == 0


def test_convert_indicator_to_stix_should_build_email_observable_and_relationship():
    converter = _build_converter()
    indicator = {
        "id": "ind-email-001",
        "type": "email",
        "value": "user@example.com",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    assert any(isinstance(obj, EmailAddress) for obj in octi_objects)
    assert any(
        isinstance(obj, Relationship) and obj.type == RelationshipType.BASED_ON
        for obj in octi_objects
    )


def test_convert_indicator_to_stix_should_create_attack_pattern_and_uses():
    converter = _build_converter()
    indicator = {
        "id": "ind-mitre-001",
        "type": "domain",
        "value": "example.org",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "mitre_attack_ids": [
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
            }
        ],
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    assert any(isinstance(obj, AttackPattern) for obj in octi_objects)
    assert any(
        isinstance(obj, Relationship) and obj.type == RelationshipType.INDICATES
        for obj in octi_objects
    )


def test_convert_indicator_to_stix_should_create_sighting_and_source_identity():
    converter = _build_converter()
    indicator = {
        "id": "ind-sighting-001",
        "type": "ipv4",
        "value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "latest_sighting": {
            "id": "sight-001",
            "source": "flashpoint_detection",
            "sighted_at": "2026-03-06T11:30:00Z",
            "description": "Observation: sample",
        },
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    sighting_objects = [obj for obj in octi_objects if isinstance(obj, Sighting)]
    assert len(sighting_objects) == 1
    assert isinstance(sighting_objects[0].sighting_of, Indicator)
    assert any(
        isinstance(obj, Organization) and obj.name == "flashpoint_detection"
        for obj in octi_objects
    )


def test_convert_indicator_to_stix_should_create_malware_from_sighting_tags():
    converter = _build_converter()
    indicator = {
        "id": "ind-tag-malware-001",
        "type": "file",
        "value": "e3b0c44298fc1c149afbf4c899" "6fb92427ae41e4649b934ca495991b7852b855",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "sightings": [
            {
                "id": "sight-m-001",
                "source": "flashpoint_extraction",
                "sighted_at": "2026-03-06T11:00:00Z",
                "tags": [
                    "extracted_config:true",
                    "malware:cobaltstrike",
                    "source:flashpoint_extraction",
                    "type:backdoor",
                ],
            }
        ],
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    malware_objects = [obj for obj in octi_objects if isinstance(obj, Malware)]
    assert len(malware_objects) == 1
    assert malware_objects[0].name == "cobaltstrike"
    assert malware_objects[0].is_family is True

    indicates_malware = [
        obj
        for obj in octi_objects
        if isinstance(obj, Relationship)
        and obj.type == RelationshipType.INDICATES
        and isinstance(obj.target, Malware)
    ]
    assert len(indicates_malware) == 1


def test_convert_indicator_to_stix_should_create_intrusion_set_from_sighting_tags():
    converter = _build_converter()
    indicator = {
        "id": "ind-tag-actor-001",
        "type": "domain",
        "value": "example.org",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "latest_sighting": {
            "id": "sight-a-001",
            "source": "flashpoint_detection",
            "sighted_at": "2026-03-06T11:30:00Z",
            "tags": [
                "actor:apt29",
                "malware:cobaltstrike",
                "source:flashpoint_detection",
            ],
        },
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    intrusion_set_objects = [
        obj for obj in octi_objects if isinstance(obj, IntrusionSet)
    ]
    assert len(intrusion_set_objects) == 1
    assert intrusion_set_objects[0].name == "apt29"

    malware_objects = [obj for obj in octi_objects if isinstance(obj, Malware)]
    assert len(malware_objects) == 1
    assert malware_objects[0].name == "cobaltstrike"

    indicates_rels = [
        obj
        for obj in octi_objects
        if isinstance(obj, Relationship) and obj.type == RelationshipType.INDICATES
    ]
    assert len(indicates_rels) >= 2


def test_convert_indicator_to_stix_should_add_malware_description_from_html():
    converter = _build_converter()
    indicator = {
        "id": "ind-mw-desc-001",
        "type": "file",
        "value": "e3b0c44298fc1c149afbf4c899" "6fb92427ae41e4649b934ca495991b7852b855",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "malware_description": "<p>A <b>backdoor</b> trojan used by APT groups.</p>",
        "sightings": [
            {
                "id": "sight-desc-001",
                "source": "flashpoint_extraction",
                "sighted_at": "2026-03-06T11:00:00Z",
                "tags": ["malware:cobaltstrike"],
            }
        ],
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    malware_objects = [obj for obj in octi_objects if isinstance(obj, Malware)]
    assert len(malware_objects) == 1
    assert malware_objects[0].description == "A backdoor trojan used by APT groups."


def test_convert_indicator_to_stix_should_add_ignite_url_as_external_reference():
    converter = _build_converter()
    indicator = {
        "id": "ind-ignite-001",
        "type": "domain",
        "value": "example.org",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "platform_urls": {
            "ignite": "https://app.flashpoint.io/indicators/simple/abc123",
        },
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    indicator_obj = next(obj for obj in octi_objects if isinstance(obj, Indicator))
    ext_refs = indicator_obj.external_references or []
    ignite_refs = [ref for ref in ext_refs if ref.source_name == "Flashpoint Ignite"]
    assert len(ignite_refs) == 1
    assert ignite_refs[0].url == "https://app.flashpoint.io/indicators/simple/abc123"


def test_convert_indicator_to_stix_should_create_related_iocs_with_related_to():
    converter = _build_converter()
    indicator = {
        "id": "ind-related-001",
        "type": "domain",
        "value": "example.org",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "sightings": [
            {
                "id": "sight-rel-001",
                "source": "flashpoint_detection",
                "sighted_at": "2026-03-06T11:00:00Z",
                "related_iocs": [
                    {
                        "type": "file",
                        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    },
                    {"type": "domain", "value": "related.example.com"},
                ],
            }
        ],
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    related_to_rels = [
        obj
        for obj in octi_objects
        if isinstance(obj, Relationship) and obj.type == RelationshipType.RELATED_TO
    ]
    assert len(related_to_rels) == 2

    file_objects = [obj for obj in octi_objects if isinstance(obj, File)]
    assert len(file_objects) == 1

    domain_objects = [
        obj
        for obj in octi_objects
        if isinstance(obj, DomainName) and obj.value == "related.example.com"
    ]
    assert len(domain_objects) == 1


def test_convert_indicator_to_stix_should_create_text_observable_for_extracted_config_related_ioc():
    converter = _build_converter()
    indicator = {
        "id": "ind-related-ec-001",
        "type": "ipv4",
        "value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "sightings": [
            {
                "id": "sight-rel-ec-001",
                "source": "flashpoint_detection",
                "sighted_at": "2026-03-06T11:00:00Z",
                "related_iocs": [
                    {"type": "extracted_config", "value": '{"c2":"evil.example.com"}'},
                ],
            }
        ],
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    text_objects = [obj for obj in octi_objects if isinstance(obj, Text)]
    assert len(text_objects) == 1
    assert text_objects[0].value == '{"c2":"evil.example.com"}'

    related_to_rels = [
        obj
        for obj in octi_objects
        if isinstance(obj, Relationship) and obj.type == RelationshipType.RELATED_TO
    ]
    assert len(related_to_rels) == 1


def test_convert_indicator_to_stix_should_handle_tactics_plural():
    converter = _build_converter()
    indicator = {
        "id": "ind-tactics-001",
        "type": "domain",
        "value": "example.org",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "mitre_attack_ids": [
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "tactics": ["Command and Control", "Exfiltration"],
            }
        ],
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    attack_pattern_objects = [
        obj for obj in octi_objects if isinstance(obj, AttackPattern)
    ]
    assert len(attack_pattern_objects) == 1

    kill_chain_phases = attack_pattern_objects[0].kill_chain_phases or []
    phase_names = [phase.phase_name for phase in kill_chain_phases]
    assert "command-and-control" in phase_names
    assert "exfiltration" in phase_names
    assert len(phase_names) == 2


def test_parse_datetime_returns_none_for_invalid_string():
    result = IndicatorConverterToStix._parse_datetime("not-a-date")
    assert result is None


def test_parse_datetime_returns_none_for_empty_string():
    result = IndicatorConverterToStix._parse_datetime("")
    assert result is None


def test_parse_datetime_returns_none_for_none():
    result = IndicatorConverterToStix._parse_datetime(None)
    assert result is None


def test_extract_ioc_value_file_hash_fallback():
    indicator = {"hashes": {"sha256": "abc123"}}
    result = IndicatorConverterToStix._extract_ioc_value(indicator, "file")
    assert result == "abc123"


def test_extract_ioc_value_file_hash_fallback_sha1():
    indicator = {"hashes": {"sha1": "def456"}}
    result = IndicatorConverterToStix._extract_ioc_value(indicator, "file")
    assert result == "def456"


def test_extract_ioc_value_file_hash_fallback_md5():
    indicator = {"hashes": {"md5": "aabb"}}
    result = IndicatorConverterToStix._extract_ioc_value(indicator, "file")
    assert result == "aabb"


def test_extract_ioc_value_file_no_hashes_returns_none():
    indicator = {}
    result = IndicatorConverterToStix._extract_ioc_value(indicator, "file")
    assert result is None


def test_extract_ioc_value_non_file_no_value_returns_none():
    indicator = {}
    result = IndicatorConverterToStix._extract_ioc_value(indicator, "ipv4")
    assert result is None


def test_extract_file_ioc_from_hashes_dict_sha256():
    indicator = {"hashes": {"sha256": "a" * 64}}
    result = IndicatorConverterToStix._extract_file_ioc(indicator)
    assert result == ("hashes.SHA-256", "a" * 64)


def test_extract_file_ioc_from_hashes_dict_sha1():
    indicator = {"hashes": {"sha1": "b" * 40}}
    result = IndicatorConverterToStix._extract_file_ioc(indicator)
    assert result == ("hashes.SHA-1", "b" * 40)


def test_extract_file_ioc_from_hashes_dict_md5():
    indicator = {"hashes": {"md5": "c" * 32}}
    result = IndicatorConverterToStix._extract_file_ioc(indicator)
    assert result == ("hashes.MD5", "c" * 32)


def test_extract_file_ioc_md5_prefix():
    indicator = {"value": "md5:44d88612fea8a8f36de82e1278abb02f"}
    result = IndicatorConverterToStix._extract_file_ioc(indicator)
    assert result == ("hashes.MD5", "44d88612fea8a8f36de82e1278abb02f")


def test_extract_file_ioc_sha1_prefix():
    indicator = {"value": "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709"}
    result = IndicatorConverterToStix._extract_file_ioc(indicator)
    assert result == ("hashes.SHA-1", "da39a3ee5e6b4b0d3255bfef95601890afd80709")


def test_extract_file_ioc_sha256_prefix():
    indicator = {"value": "sha256:" + "a" * 64}
    result = IndicatorConverterToStix._extract_file_ioc(indicator)
    assert result == ("hashes.SHA-256", "a" * 64)


def test_extract_file_ioc_filename_fallback():
    indicator = {"value": "malware.exe"}
    result = IndicatorConverterToStix._extract_file_ioc(indicator)
    assert result == ("name", "malware.exe")


def test_extract_file_ioc_returns_none_when_empty():
    indicator = {}
    result = IndicatorConverterToStix._extract_file_ioc(indicator)
    assert result is None


def test_convert_asn_indicator():
    converter = _build_converter()
    indicator = {
        "id": "ind-asn-001",
        "type": "asn",
        "value": "AS12345",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    assert len(octi_objects) > 0
    indicator_obj = next(obj for obj in octi_objects if isinstance(obj, Indicator))
    assert "autonomous-system:number" in indicator_obj.pattern
    as_objects = [obj for obj in octi_objects if isinstance(obj, AutonomousSystem)]
    assert len(as_objects) == 1
    assert as_objects[0].number == 12345


def test_convert_asn_indicator_invalid_number():
    converter = _build_converter()
    indicator = {
        "id": "ind-asn-bad",
        "type": "asn",
        "value": "ASnotanumber",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)
    assert len(octi_objects) == 0


def test_convert_ipv6_indicator():
    converter = _build_converter()
    indicator = {
        "id": "ind-ipv6-001",
        "type": "ipv6",
        "value": "2001:db8::1",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    assert len(octi_objects) > 0
    assert any(isinstance(obj, IPV6Address) for obj in octi_objects)


def test_convert_url_indicator():
    converter = _build_converter()
    indicator = {
        "id": "ind-url-001",
        "type": "url",
        "value": "https://example.com/malicious",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    assert len(octi_objects) > 0
    assert any(isinstance(obj, URL) for obj in octi_objects)


def test_convert_domain_with_invalid_value_returns_empty():
    converter = _build_converter()
    indicator = {
        "id": "ind-domain-bad",
        "type": "domain",
        "value": "not a domain!",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)
    assert len(octi_objects) == 0
    converter.helper.connector_logger.warning.assert_called_once()


def test_convert_file_with_hashes_dict():
    converter = _build_converter()
    indicator = {
        "id": "ind-file-hashes",
        "type": "file",
        "hashes": {"sha256": "a" * 64},
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    assert len(octi_objects) > 0
    indicator_obj = next(obj for obj in octi_objects if isinstance(obj, Indicator))
    assert (
        "hashes.'SHA-256'" in indicator_obj.pattern
        or "hashes.SHA-256" in indicator_obj.pattern
    )
    file_objects = [obj for obj in octi_objects if isinstance(obj, File)]
    assert len(file_objects) == 1


def test_convert_file_with_name_value():
    converter = _build_converter()
    indicator = {
        "id": "ind-filename-001",
        "type": "file",
        "value": "malware.exe",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    assert len(octi_objects) > 0
    indicator_obj = next(obj for obj in octi_objects if isinstance(obj, Indicator))
    assert "file:name" in indicator_obj.pattern
    file_objects = [obj for obj in octi_objects if isinstance(obj, File)]
    assert len(file_objects) == 1
    assert file_objects[0].name == "malware.exe"


def test_convert_indicator_no_value_returns_empty():
    converter = _build_converter()
    indicator = {
        "id": "ind-no-value",
        "type": "ipv4",
        "created_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)
    assert len(octi_objects) == 0


def test_convert_indicator_no_type_returns_empty():
    converter = _build_converter()
    indicator = {
        "id": "ind-no-type",
        "value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)
    assert len(octi_objects) == 0


def test_normalize_attack_pattern_id_whitespace_only():
    result = IndicatorConverterToStix._normalize_attack_pattern_id("   ")
    assert result is None


def test_normalize_attack_pattern_id_no_technique():
    result = IndicatorConverterToStix._normalize_attack_pattern_id("not-a-technique")
    assert result is None


def test_normalize_attack_pattern_id_valid():
    result = IndicatorConverterToStix._normalize_attack_pattern_id("  t1059.001  ")
    assert result == "T1059.001"


def test_strip_html():
    result = IndicatorConverterToStix._strip_html("<p>Hello &amp; <b>world</b></p>")
    assert result == "Hello & world"


def test_normalize_kill_chain_phase_name_special_chars():
    result = IndicatorConverterToStix._normalize_kill_chain_phase_name(
        "Command & Control!!!"
    )
    assert result == "command-control"


def test_normalize_kill_chain_phase_name_whitespace_only():
    result = IndicatorConverterToStix._normalize_kill_chain_phase_name("   ")
    assert result is None


def test_normalize_kill_chain_phase_name_empty_after_strip():
    """Cover line 409: normalized_value is empty after strip().lower()."""
    result = IndicatorConverterToStix._normalize_kill_chain_phase_name("\t \n")
    assert result is None


def test_normalize_kill_chain_phase_name_none_input():
    """Cover line 409: value is None (falsy first guard)."""
    result = IndicatorConverterToStix._normalize_kill_chain_phase_name(None)
    assert result is None


def test_normalize_kill_chain_phase_name_empty_string():
    """Cover line 409: value is '' (falsy first guard)."""
    result = IndicatorConverterToStix._normalize_kill_chain_phase_name("")
    assert result is None


def test_normalize_kill_chain_phase_name_symbols_only():
    result = IndicatorConverterToStix._normalize_kill_chain_phase_name("---")
    assert result is None


def test_extract_attack_patterns_with_description_and_technique_name():
    indicator = {
        "mitre_attack_ids": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "description": "A technique description",
                "tactic": "Execution",
            }
        ]
    }
    result = IndicatorConverterToStix._extract_attack_patterns(indicator)
    assert len(result) == 1
    assert result[0]["mitre_id"] == "T1059"
    assert result[0]["name"] == "Command and Scripting Interpreter"
    assert result[0]["description"] == "A technique description"


def test_extract_attack_patterns_deduplication():
    indicator = {
        "mitre_attack_ids": [
            {"id": "T1059", "name": "CSI"},
            {"id": "T1059", "name": "CSI"},
        ]
    }
    result = IndicatorConverterToStix._extract_attack_patterns(indicator)
    assert len(result) == 1


def test_extract_attack_patterns_skips_entry_without_name_or_id():
    indicator = {
        "mitre_attack_ids": [
            {"description": "some desc"},
        ]
    }
    result = IndicatorConverterToStix._extract_attack_patterns(indicator)
    assert len(result) == 0


def test_extract_attack_patterns_name_only_no_mitre_id():
    indicator = {
        "mitre_attack_ids": [
            {"title": "Custom Technique"},
        ]
    }
    result = IndicatorConverterToStix._extract_attack_patterns(indicator)
    assert len(result) == 1
    assert result[0]["name"] == "Custom Technique"
    assert result[0]["mitre_id"] is None


def test_sighting_with_invalid_date_is_skipped():
    converter = _build_converter()
    indicator = {
        "id": "ind-sight-bad",
        "type": "ipv4",
        "value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "latest_sighting": {
            "id": "sight-bad",
            "source": "test_source",
            "sighted_at": "invalid-date",
        },
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    sighting_objects = [obj for obj in octi_objects if isinstance(obj, Sighting)]
    assert len(sighting_objects) == 0


def test_related_ioc_same_as_parent_is_skipped():
    converter = _build_converter()
    indicator = {
        "id": "ind-rel-dup",
        "type": "ipv4",
        "value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "sightings": [
            {
                "id": "sight-1",
                "source": "test",
                "sighted_at": "2026-03-06T11:00:00Z",
                "related_iocs": [
                    {"type": "ipv4", "value": "198.51.100.42"},
                ],
            }
        ],
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    related_to = [
        obj
        for obj in octi_objects
        if isinstance(obj, Relationship) and obj.type == RelationshipType.RELATED_TO
    ]
    assert len(related_to) == 0


def test_related_ioc_unknown_type_is_skipped():
    converter = _build_converter()
    indicator = {
        "id": "ind-rel-unk",
        "type": "ipv4",
        "value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "sightings": [
            {
                "id": "sight-1",
                "source": "test",
                "sighted_at": "2026-03-06T11:00:00Z",
                "related_iocs": [
                    {"type": "unknown_type", "value": "something"},
                ],
            }
        ],
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    related_to = [
        obj
        for obj in octi_objects
        if isinstance(obj, Relationship) and obj.type == RelationshipType.RELATED_TO
    ]
    assert len(related_to) == 0


def test_related_ioc_empty_type_or_value_is_skipped():
    result = IndicatorConverterToStix._extract_related_iocs(
        {
            "sightings": [
                {
                    "related_iocs": [
                        {"type": "", "value": "x"},
                        {"type": "ipv4", "value": ""},
                        {"type": None, "value": "y"},
                    ],
                }
            ]
        }
    )
    assert len(result) == 0


def test_extract_sightings_deduplication():
    result = IndicatorConverterToStix._extract_sightings(
        {
            "sightings": [
                {"id": "s1", "source": "src", "sighted_at": "2026-01-01T00:00:00Z"},
            ],
            "latest_sighting": {
                "id": "s1",
                "source": "src",
                "sighted_at": "2026-01-01T00:00:00Z",
            },
        }
    )
    assert len(result) == 1


def test_extract_sightings_skips_empty_source():
    result = IndicatorConverterToStix._extract_sightings(
        {
            "sightings": [
                {"id": "s1", "source": "", "sighted_at": "2026-01-01T00:00:00Z"},
                {"id": "s2", "source": "  ", "sighted_at": "2026-01-01T00:00:00Z"},
            ]
        }
    )
    assert len(result) == 0


def test_extract_sightings_skips_empty_sighted_at():
    result = IndicatorConverterToStix._extract_sightings(
        {
            "sightings": [
                {"id": "s1", "source": "src", "sighted_at": ""},
            ]
        }
    )
    assert len(result) == 0


def test_collect_sighting_tags_from_both_sources():
    tags = IndicatorConverterToStix._collect_sighting_tags(
        {
            "sightings": [{"tags": ["a", "b"]}],
            "latest_sighting": {"tags": ["c"]},
        }
    )
    assert set(tags) == {"a", "b", "c"}


def test_extract_entities_from_tags_empty_names_ignored():
    actors, malware = IndicatorConverterToStix._extract_entities_from_tags(
        {
            "sightings": [
                {
                    "tags": [
                        "actor:",
                        "actor:  ",
                        "malware:",
                        "malware: ",
                        "other:tag",
                    ]
                }
            ]
        }
    )
    assert len(actors) == 0
    assert len(malware) == 0


def test_build_external_references_with_href_and_id():
    converter = _build_converter()
    refs = converter._build_external_references(
        {
            "href": "https://fp.example.com/ind/1",
            "id": "fp-123",
        }
    )
    assert len(refs) == 2
    assert refs[0].url == "https://fp.example.com/ind/1"
    assert refs[1].external_id == "fp-123"


def test_extract_ignite_url_returns_none_when_missing():
    assert IndicatorConverterToStix._extract_ignite_url({}) is None
    assert (
        IndicatorConverterToStix._extract_ignite_url({"platform_urls": {"ignite": ""}})
        is None
    )


def test_resolve_score_informational():
    score = IndicatorConverterToStix._resolve_score(
        {"score": {"value": "informational"}}
    )
    assert score == 20


def test_resolve_score_suspicious():
    score = IndicatorConverterToStix._resolve_score({"score": {"value": "Suspicious"}})
    assert score == 50


def test_resolve_score_unknown_value():
    score = IndicatorConverterToStix._resolve_score({"score": {"value": "unknown"}})
    assert score == 50


def test_resolve_score_no_score_key():
    score = IndicatorConverterToStix._resolve_score({})
    assert score == 50


def test_resolve_observable_definition_unknown_type():
    result = IndicatorConverterToStix._resolve_observable_definition("unknown")
    assert result is None


def test_normalize_labels_deduplicates():
    result = IndicatorConverterToStix._normalize_labels(["a", "b", "a"])
    assert set(result) == {"a", "b"}
    assert len(result) == 2


def test_normalize_labels_empty():
    assert IndicatorConverterToStix._normalize_labels(None) == []
    assert IndicatorConverterToStix._normalize_labels([]) == []


def test_convert_indicator_valid_from_fallback_chain():
    converter = _build_converter()
    indicator = {
        "id": "ind-fallback-dates",
        "type": "ipv4",
        "value": "198.51.100.42",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    indicator_obj = next(obj for obj in octi_objects if isinstance(obj, Indicator))
    assert indicator_obj.valid_from is not None


def test_convert_indicator_with_malware_description_no_tags():
    converter = _build_converter()
    indicator = {
        "id": "ind-no-malware-tag",
        "type": "ipv4",
        "value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "malware_description": "<b>Desc</b>",
    }
    octi_objects = converter.convert_indicator_to_stix(indicator)
    malware_objects = [obj for obj in octi_objects if isinstance(obj, Malware)]
    assert len(malware_objects) == 0


def test_create_observable_returns_none_for_unknown_type():
    converter = _build_converter()
    result = converter._create_observable(
        stix_type="unknown",
        stix_path="value",
        ioc_value="test",
        labels=[],
        score=50,
    )
    assert result is None


def test_create_observable_domain_invalid():
    converter = _build_converter()
    result = converter._create_observable(
        stix_type="domain-name",
        stix_path="value",
        ioc_value="not a valid domain!!",
        labels=[],
        score=50,
    )
    assert result is None


def test_create_observable_as_invalid_number():
    converter = _build_converter()
    result = converter._create_observable(
        stix_type="autonomous-system",
        stix_path="number",
        ioc_value="ASnotanumber",
        labels=[],
        score=50,
    )
    assert result is None


def test_create_observable_file_unknown_hash_algorithm():
    converter = _build_converter()
    result = converter._create_observable(
        stix_type="file",
        stix_path="hashes.UNKNOWN",
        ioc_value="abcdef",
        labels=[],
        score=50,
    )
    assert result is None


def test_build_pattern_text_escaping():
    result = IndicatorConverterToStix._build_pattern(
        "text", "value", "hello\\world'test"
    )
    assert result == "[text:value = 'hello\\\\world\\'test']"


def test_tlp_levels():
    for tlp in ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]:
        helper = Mock()
        helper.connector_logger = Mock()
        converter = IndicatorConverterToStix(helper=helper, tlp_definition=tlp)
        assert converter.marking is not None


def test_related_iocs_from_latest_sighting():
    result = IndicatorConverterToStix._extract_related_iocs(
        {
            "latest_sighting": {
                "related_iocs": [
                    {"type": "ipv4", "value": "1.2.3.4"},
                ]
            }
        }
    )
    assert len(result) == 1


def test_related_iocs_deduplication():
    result = IndicatorConverterToStix._extract_related_iocs(
        {
            "sightings": [
                {
                    "related_iocs": [
                        {"type": "ipv4", "value": "1.2.3.4"},
                    ]
                }
            ],
            "latest_sighting": {
                "related_iocs": [
                    {"type": "ipv4", "value": "1.2.3.4"},
                ]
            },
        }
    )
    assert len(result) == 1


def test_build_attack_pattern_with_single_tactic_fallback():
    converter = _build_converter()
    indicator = {
        "id": "ind-tactic-single",
        "type": "ipv4",
        "value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "mitre_attack_ids": [
            {
                "id": "T1071",
                "name": "App Layer Protocol",
                "tactic": "command-and-control",
            }
        ],
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    ap_objects = [obj for obj in octi_objects if isinstance(obj, AttackPattern)]
    assert len(ap_objects) == 1
    assert ap_objects[0].kill_chain_phases is not None
    assert len(ap_objects[0].kill_chain_phases) == 1


def test_build_attack_pattern_tactics_all_invalid():
    """Cover line 519: all tactics normalize to None → kill_chain_phases = None."""
    converter = _build_converter()
    indicator = {
        "id": "ind-tactic-bad",
        "type": "ipv4",
        "value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "mitre_attack_ids": [
            {
                "id": "T1071",
                "name": "App Layer Protocol",
                "tactics": ["---", "***"],
            }
        ],
    }

    octi_objects = converter.convert_indicator_to_stix(indicator)

    ap_objects = [obj for obj in octi_objects if isinstance(obj, AttackPattern)]
    assert len(ap_objects) == 1
    assert ap_objects[0].kill_chain_phases is None


def test_convert_file_indicator_with_no_file_ioc_falls_back():
    """Cover line 891: file type where _extract_file_ioc returns None."""
    converter = _build_converter()
    indicator = {
        "id": "ind-file-empty",
        "type": "file",
        # no value, no hashes → _extract_file_ioc returns None
    }
    result = converter.convert_indicator_to_stix(indicator)
    assert result == []


def test_convert_indicator_unknown_observable_definition():
    """Cover line 900: type found but _resolve_observable_definition returns None."""
    converter = _build_converter()
    indicator = {
        "id": "ind-unknown-obs",
        "type": "unknown_type_xyz",
        "value": "some-value",
        "created_at": "2026-03-06T12:00:00Z",
    }
    result = converter.convert_indicator_to_stix(indicator)
    assert result == []


def test_related_ioc_with_invalid_asn_pattern_skipped():
    """Cover line 766: related IoC where _build_pattern returns None."""
    converter = _build_converter()
    indicator = {
        "id": "ind-rel-bad-asn",
        "type": "ipv4",
        "value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "sightings": [
            {
                "id": "sight-1",
                "source": "test",
                "sighted_at": "2026-03-06T11:00:00Z",
                "related_iocs": [
                    {"type": "asn", "value": "invalid_not_a_number"},
                ],
            }
        ],
    }
    octi_objects = converter.convert_indicator_to_stix(indicator)
    related_to = [
        obj
        for obj in octi_objects
        if isinstance(obj, Relationship) and obj.type == RelationshipType.RELATED_TO
    ]
    assert len(related_to) == 0


def test_create_observable_file_sha256_hash():
    """Cover line 409: File observable with hash algorithm."""
    converter = _build_converter()
    result = converter._create_observable(
        stix_type="file",
        stix_path="hashes.SHA-256",
        ioc_value="a" * 64,
        labels=[],
        score=50,
    )
    assert result is not None
    assert isinstance(result, File)
