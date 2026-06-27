"""Tests for ConverterToStix (STIX object construction)."""

import json

import pytest
import stix2

from connector.converter_to_stix import ConverterToStix


@pytest.mark.parametrize(
    "value, expected_type",
    [
        ("1.2.3.4", "ipv4-addr"),
        ("2001:db8::1", "ipv6-addr"),
        ("example.com", "domain-name"),
    ],
)
def test_create_obs_detects_type(helper, value, expected_type):
    obs = ConverterToStix(helper).create_obs(value)
    assert obs.type == expected_type
    assert obs.value == value


def test_create_vulnerability_without_custom_properties(helper):
    # Regression: custom_properties defaults to None (not a shared mutable {}).
    vuln = ConverterToStix(helper).create_vulnerability(cve="CVE-2024-99999")
    assert vuln.type == "vulnerability"
    assert vuln.name == "CVE-2024-99999"


def test_author_and_external_reference_built(helper):
    converter = ConverterToStix(helper)
    assert converter.author.type == "identity"
    assert converter.author.identity_class == "organization"
    assert converter.external_reference


def test_create_vulnerability_deterministic_id(helper):
    converter = ConverterToStix(helper)
    vuln_a = converter.create_vulnerability(cve="CVE-2024-12345")
    vuln_b = converter.create_vulnerability(cve="CVE-2024-12345")
    assert vuln_a.type == "vulnerability"
    assert vuln_a.name == "CVE-2024-12345"
    assert vuln_a.id == vuln_b.id  # deterministic


def test_create_software(helper):
    converter = ConverterToStix(helper)
    software = converter.create_software(
        product="edge",
        vendor="microsoft",
        version="1.0",
        cpe="cpe:2.3:a:microsoft:edge",
    )
    assert software.type == "software"
    # name combines vendor + product
    assert software.name == "microsoft edge"


def test_create_relationship_uses_author(helper):
    converter = ConverterToStix(helper)
    vuln = converter.create_vulnerability(cve="CVE-2024-12345")
    software = converter.create_software(
        product="edge",
        vendor="microsoft",
        version="1.0",
        cpe="cpe:2.3:a:microsoft:edge",
    )
    rel = converter.create_relationship(
        source_id=software["id"], relationship_type="has", target_id=vuln["id"]
    )
    assert rel.relationship_type == "has"
    assert rel.source_ref == software["id"]
    assert rel.target_ref == vuln["id"]


def test_objects_form_a_serializable_bundle(helper):
    converter = ConverterToStix(helper)
    vuln = converter.create_vulnerability(cve="CVE-2024-12345")
    software = converter.create_software(
        product="edge",
        vendor="microsoft",
        version="1.0",
        cpe="cpe:2.3:a:microsoft:edge",
    )
    rel = converter.create_relationship(
        source_id=software["id"], relationship_type="has", target_id=vuln["id"]
    )
    bundle = stix2.Bundle(
        objects=[converter.author, vuln, software, rel], allow_custom=True
    )
    data = json.loads(bundle.serialize())
    types = {obj["type"] for obj in data["objects"]}
    assert {"identity", "vulnerability", "software", "relationship"} <= types
