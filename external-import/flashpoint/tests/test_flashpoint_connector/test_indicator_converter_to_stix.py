from unittest.mock import Mock

import stix2
from flashpoint_connector.indicator_converter_to_stix import IndicatorConverterToStix


def _build_converter() -> IndicatorConverterToStix:
    helper = Mock()
    helper.connector_logger = Mock()
    return IndicatorConverterToStix(helper=helper)


def test_convert_extracted_config_indicator_to_stix_should_extract_network_iocs():
    converter = _build_converter()
    indicator = {
        "id": "ind-anon-001",
        "type": "extracted_config",
        "value": {
            "Hosts": "203.0.113.10,,example.org",
            "urls": ["http://example.com/path/config"],
            "c2": ["198.51.100.21", "https://example.net/endpoint"],
            "Certificate": "MIICMzCCAZygAwIBAgIVAL...",
        },
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
        "score": {"value": "malicious"},
    }

    stix_objects = converter.convert_indicator_to_stix(indicator)

    assert len(stix_objects) > 0
    assert any(getattr(obj, "type", None) == "url" for obj in stix_objects)
    assert any(getattr(obj, "type", None) == "ipv4-addr" for obj in stix_objects)
    assert any(getattr(obj, "type", None) == "domain-name" for obj in stix_objects)


def test_convert_extracted_config_indicator_to_stix_should_support_json_string_value():
    converter = _build_converter()
    indicator = {
        "id": "ind-anon-002",
        "type": "extracted_config",
        "value": '{"type":"stealer","urls":["http://example.org/collector"],"Hosts":"one.example.com"}',
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    stix_objects = converter.convert_indicator_to_stix(indicator)

    assert len(stix_objects) > 0
    assert any(getattr(obj, "type", None) == "url" for obj in stix_objects)
    assert any(getattr(obj, "type", None) == "domain-name" for obj in stix_objects)


def test_convert_extracted_config_indicator_to_stix_should_strip_port_from_ipv4():
    converter = _build_converter()
    indicator = {
        "id": "ind-anon-003",
        "type": "extracted_config",
        "value": {
            "c2s": ["192.0.2.44:80"],
        },
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    stix_objects = converter.convert_indicator_to_stix(indicator)

    ipv4_values = [
        obj.value for obj in stix_objects if getattr(obj, "type", None) == "ipv4-addr"
    ]
    assert "192.0.2.44" in ipv4_values
    assert "192.0.2.44:80" not in ipv4_values


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

    stix_objects = converter.convert_indicator_to_stix(indicator)

    indicator_obj = next(
        obj for obj in stix_objects if getattr(obj, "type", None) == "indicator"
    )
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

    stix_objects = converter.convert_indicator_to_stix(indicator)

    indicator_obj = next(
        obj for obj in stix_objects if getattr(obj, "type", None) == "indicator"
    )
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

    stix_objects = converter.convert_indicator_to_stix(indicator)

    indicator_obj = next(
        obj for obj in stix_objects if getattr(obj, "type", None) == "indicator"
    )
    assert (
        "hashes.'SHA-256'" in indicator_obj.pattern
        or "hashes.SHA-256" in indicator_obj.pattern
    )


def test_convert_indicator_to_stix_should_support_ioc_type_ioc_value_payload():
    converter = _build_converter()
    indicator = {
        "id": "ind-fallback-001",
        "ioc_type": "ipv4",
        "ioc_value": "198.51.100.42",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    stix_objects = converter.convert_indicator_to_stix(indicator)

    assert len(stix_objects) > 0
    assert any(getattr(obj, "type", None) == "ipv4-addr" for obj in stix_objects)


def test_convert_indicator_to_stix_should_build_email_observable_and_relationship():
    converter = _build_converter()
    indicator = {
        "id": "ind-email-001",
        "type": "email",
        "value": "user@example.com",
        "created_at": "2026-03-06T12:00:00Z",
        "modified_at": "2026-03-06T12:00:00Z",
    }

    stix_objects = converter.convert_indicator_to_stix(indicator)

    assert any(isinstance(obj, stix2.EmailAddress) for obj in stix_objects)
    assert any(
        isinstance(obj, stix2.Relationship)
        and getattr(obj, "relationship_type", None) == "based-on"
        for obj in stix_objects
    )
