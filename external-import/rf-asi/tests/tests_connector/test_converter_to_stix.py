from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import (
    INCIDENT_TYPE,
    LABEL_ADDED,
    SOURCE_NAME,
    ConverterToStix,
)
from connector.utils import build_asset_description, detect_observable_type
from connectors_sdk.models import (
    DomainName,
    Incident,
    IPV4Address,
    IPV6Address,
    Relationship,
    Vulnerability,
)
from pycti import Incident as PyctiIncident
from pycti import StixCoreRelationship as PyctiStixCoreRelationship
from stix2.v21 import Incident as Stix2Incident


@pytest.fixture
def converter(opencti_helper):
    return ConverterToStix(
        opencti_helper,
        tlp_level="amber+strict",
        project_id="test-project-id",
        portal_base_url="https://portal.example.com",
    )


@pytest.mark.parametrize(
    "rf_severity, expected_severity",
    [
        pytest.param("critical", "critical", id="critical"),
        pytest.param("moderate", "medium", id="moderate"),
        pytest.param("informational", "low", id="informational"),
        pytest.param("unknown", "low", id="unknown"),
        pytest.param("CRITICAL", "critical", id="case_insensitive"),
        pytest.param(None, "low", id="missing_severity"),
        pytest.param("unexpected", "low", id="unmapped_severity"),
    ],
)
def test_map_severity(rf_severity, expected_severity):
    assert ConverterToStix.map_severity(rf_severity) == expected_severity


def test_exposure_to_incident_maps_fields(converter, exposures_list_page):
    exposure = exposures_list_page["data"][0]
    signature = exposure["signature"]

    incident = converter.exposure_to_incident(exposure)

    assert isinstance(incident, Stix2Incident)
    assert incident.name == signature["name"]
    assert signature["description"] in incident.description
    assert f"Affected assets: {exposure['asset_count']}" in incident.description
    assert incident.severity == "critical"
    assert incident.incident_type == INCIDENT_TYPE
    assert incident.source == SOURCE_NAME
    assert incident.labels == [LABEL_ADDED]
    assert incident.created is not None
    assert "2024-06-01" in str(incident.created)
    assert incident.id == PyctiIncident.generate_id(
        name=signature["name"],
        created=incident.created,
    )


def test_exposure_to_incident_builds_external_reference(converter, exposures_list_page):
    exposure = exposures_list_page["data"][0]
    signature = exposure["signature"]

    incident = converter.exposure_to_incident(exposure)

    external_ref = incident.external_references[0]
    assert external_ref["source_name"] == SOURCE_NAME
    assert external_ref["external_id"] == signature["id"]
    assert external_ref["url"] == (
        f"https://portal.example.com/projects/test-project-id/exposures/{signature['id']}"
    )


def test_exposure_to_incident_omits_url_without_portal_base_url(
    opencti_helper, exposures_list_page
):
    converter = ConverterToStix(
        opencti_helper,
        tlp_level="clear",
        project_id="test-project-id",
        portal_base_url=None,
    )
    exposure = exposures_list_page["data"][0]

    incident = converter.exposure_to_incident(exposure)

    external_ref = incident.external_references[0]
    assert external_ref["external_id"] == exposure["signature"]["id"]
    assert "url" not in external_ref


def test_exposure_to_incident_id_is_stable(converter, exposures_list_page):
    exposure = exposures_list_page["data"][0]

    first_incident = converter.exposure_to_incident(exposure)
    second_incident = converter.exposure_to_incident(exposure)

    assert first_incident.id == second_incident.id


def test_exposure_to_incident_uses_fallback_created_when_added_at_missing(
    opencti_helper,
):
    converter = ConverterToStix(
        opencti_helper,
        tlp_level="clear",
        project_id="test-project-id",
    )
    fixed_now = datetime(2024, 6, 4, 10, 0, 0, tzinfo=timezone.utc)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            "connector.converter_to_stix.datetime",
            MagicMock(now=MagicMock(return_value=fixed_now)),
        )
        incident = converter.exposure_to_incident(
            {
                "signature": {
                    "id": "sig-missing-date",
                    "name": "Exposure without added_at",
                    "severity": "unknown",
                },
                "asset_count": 0,
            }
        )

    assert incident.created == fixed_now


def test_converter_exposes_author_and_tlp_marking(converter):
    assert converter.author["type"] == "identity"
    assert converter.author["name"] == "Recorded Future ASI"
    assert converter.tlp_marking["type"] == "marking-definition"
    assert converter.tlp_marking["x_opencti_definition"] == "TLP:AMBER+STRICT"


@pytest.mark.parametrize(
    "asset_id, expected_type",
    [
        pytest.param("203.0.113.10", "ipv4", id="ipv4"),
        pytest.param("203.0.113.0/24", "ipv4", id="ipv4_cidr"),
        pytest.param("2001:db8::1", "ipv6", id="ipv6"),
        pytest.param("example.com", "domain", id="domain"),
        pytest.param("  ", None, id="empty"),
    ],
)
def test_detect_observable_type(asset_id, expected_type):
    assert detect_observable_type(asset_id) == expected_type


def test_build_asset_description_includes_target_and_evidence():
    asset_exposure = {
        "instances": [{"port_number": 443}],
        "details": {
            "target": "203.0.113.10:443",
            "extractions": {"protocol": "tls1.0"},
        },
    }

    description = build_asset_description(asset_exposure)

    assert description is not None
    assert "Target: 203.0.113.10:443" in description
    assert "Evidence:" in description
    assert "tls1.0" in description
    assert "443" in description


def test_build_exposure_objects_maps_assets_vulnerabilities_and_relationships(
    converter, exposures_list_page, all_exposure_assets
):
    exposure = exposures_list_page["data"][0]
    sdk_objects = converter.build_exposure_objects(exposure, all_exposure_assets)

    incidents = [obj for obj in sdk_objects if isinstance(obj, Incident)]
    observables = [
        obj
        for obj in sdk_objects
        if isinstance(obj, (IPV4Address, IPV6Address, DomainName))
    ]
    vulnerabilities = [obj for obj in sdk_objects if isinstance(obj, Vulnerability)]
    relationships = [obj for obj in sdk_objects if isinstance(obj, Relationship)]

    assert len(incidents) == 1
    assert len(observables) == 3
    assert len(vulnerabilities) == 1
    assert len(relationships) == 4

    ipv4_observables = [obj for obj in observables if isinstance(obj, IPV4Address)]
    ipv6_observables = [obj for obj in observables if isinstance(obj, IPV6Address)]
    domain_observables = [obj for obj in observables if isinstance(obj, DomainName)]

    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "203.0.113.10"
    assert len(domain_observables) == 1
    assert domain_observables[0].value == "example.com"
    assert len(ipv6_observables) == 1
    assert ipv6_observables[0].value == "2001:db8::1"

    vulnerability = vulnerabilities[0]
    assert vulnerability.name == "CVE-2024-1234"
    assert vulnerability.cvss_v3_base_score == 9.8
    assert vulnerability.cvss_v3_vector_string == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert vulnerability.epss_score == 0.95
    assert vulnerability.labels == ["cwe-79"]
    assert vulnerability.external_references[0].source_name == SOURCE_NAME
    assert (
        vulnerability.external_references[0].url
        == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    )

    incident = incidents[0]
    related_targets = {relationship.target.id for relationship in relationships}
    expected_target_ids = {obj.id for obj in observables + vulnerabilities}
    for relationship in relationships:
        assert relationship.type == "related-to"
        assert relationship.source == incident
        assert relationship.target.id in expected_target_ids
    assert related_targets == expected_target_ids


def test_build_exposure_objects_relationship_stix_refs_are_stable(
    converter, exposures_list_page, all_exposure_assets
):
    exposure = exposures_list_page["data"][0]
    sdk_objects = converter.build_exposure_objects(exposure, all_exposure_assets)

    incident = next(obj for obj in sdk_objects if isinstance(obj, Incident))
    relationships = [obj for obj in sdk_objects if isinstance(obj, Relationship)]

    first_relationship = relationships[0]
    second_relationship = relationships[0]

    first_stix_relationship = first_relationship.to_stix2_object()
    second_stix_relationship = second_relationship.to_stix2_object()

    assert first_stix_relationship.id == second_stix_relationship.id
    assert first_stix_relationship.source_ref == incident.id
    assert first_stix_relationship.target_ref == first_relationship.target.id
    assert first_stix_relationship.id == PyctiStixCoreRelationship.generate_id(
        relationship_type="related-to",
        source_ref=incident.id,
        target_ref=first_relationship.target.id,
        start_time=None,
        stop_time=None,
    )


def test_build_exposure_objects_deduplicates_observables_and_vulnerabilities(
    converter, exposures_list_page, all_exposure_assets
):
    exposure = exposures_list_page["data"][0]

    first_objects = converter.build_exposure_objects(exposure, all_exposure_assets)
    second_objects = converter.build_exposure_objects(exposure, all_exposure_assets)

    first_observables = [
        obj
        for obj in first_objects
        if isinstance(obj, (IPV4Address, IPV6Address, DomainName))
    ]
    second_observables = [
        obj
        for obj in second_objects
        if isinstance(obj, (IPV4Address, IPV6Address, DomainName))
    ]
    first_vulnerabilities = [
        obj for obj in first_objects if isinstance(obj, Vulnerability)
    ]
    second_vulnerabilities = [
        obj for obj in second_objects if isinstance(obj, Vulnerability)
    ]

    assert len(first_observables) == 3
    assert second_observables == []
    assert len(first_vulnerabilities) == 1
    assert second_vulnerabilities == []
