from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import (
    EXPOSURE_INCIDENT_ID_ANCHOR,
    INCIDENT_TYPE,
    LABEL_ADDED,
    LABEL_CLEARED,
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


def test_map_severity_maps_v1_high_to_critical():
    assert ConverterToStix.map_severity("high") == "critical"


@pytest.mark.parametrize(
    "classification, expected",
    [
        pytest.param("high", "critical", id="high_to_critical"),
        pytest.param("critical", "critical", id="critical"),
        pytest.param("moderate", "moderate", id="moderate"),
        pytest.param("informational", "informational", id="informational"),
        pytest.param("unknown", "unknown", id="unknown"),
        pytest.param(None, "unknown", id="missing"),
        pytest.param("HIGH", "critical", id="case_insensitive"),
        pytest.param("unexpected", "unknown", id="unmapped"),
    ],
)
def test_normalize_classification(classification, expected):
    assert ConverterToStix.normalize_classification(classification) == expected


@pytest.mark.parametrize(
    "classification, filter_min, filter_exact, expected",
    [
        pytest.param("high", "critical", None, True, id="min_critical_high_passes"),
        pytest.param(
            "moderate", "critical", None, False, id="min_critical_moderate_fails"
        ),
        pytest.param("high", None, "moderate", False, id="exact_moderate_high_fails"),
        pytest.param("moderate", None, "moderate", True, id="exact_moderate_match"),
        pytest.param("moderate", None, None, True, id="no_filter_passes_all"),
    ],
)
def test_rule_matches_severity_filter(
    classification, filter_min, filter_exact, expected
):
    rule = {"classification": classification}
    assert (
        ConverterToStix.rule_matches_severity_filter(
            rule,
            filter_severity_min=filter_min,
            filter_severity_exact=filter_exact,
        )
        is expected
    )


def test_history_rule_to_exposure_summary_maps_fields(risk_history_activity):
    rule = risk_history_activity["data"][0]["added_rules"][0]

    summary = ConverterToStix.history_rule_to_exposure_summary(rule)

    assert summary["signature"]["id"] == "sig-001"
    assert summary["signature"]["name"] == "Exposed admin panel"
    assert summary["signature"]["description"] == (
        "An administrative interface is publicly accessible."
    )
    assert summary["signature"]["severity"] == "high"
    assert summary["asset_count"] == 3


def test_build_cleared_incident_uses_cleared_label_and_rule_fields(
    converter, risk_history_activity
):
    rule = risk_history_activity["data"][0]["removed_rules"][0]

    incident = converter.build_cleared_incident(rule).to_stix2_object()

    assert incident.labels == [LABEL_CLEARED]
    assert incident.name == "Open port 22"
    assert incident.external_references[0]["external_id"] == "sig-002"
    assert incident.severity == "medium"


def test_build_cleared_incident_id_matches_prior_added_incident(
    converter, exposures_list_page
):
    exposure = exposures_list_page["data"][1]
    removed_rule = {
        "id": exposure["signature"]["id"],
        "name": exposure["signature"]["name"],
        "classification": exposure["signature"]["severity"],
    }

    added_incident = converter.exposure_to_incident(exposure)
    cleared_incident = converter.build_cleared_incident(removed_rule).to_stix2_object()

    assert cleared_incident.id == added_incident.id


def test_build_exposure_objects_accepts_custom_label(
    converter, exposures_list_page, all_exposure_assets
):
    exposure = exposures_list_page["data"][0]
    assets_without_vulns = {
        "signature": {"vulnerabilities": []},
        "asset_exposures": [],
    }

    sdk_objects = converter.build_exposure_objects(
        exposure,
        assets_without_vulns,
        label=LABEL_CLEARED,
    )

    incident = next(obj for obj in sdk_objects if isinstance(obj, Incident))
    assert incident.labels == [LABEL_CLEARED]


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
        signature["id"],
        EXPOSURE_INCIDENT_ID_ANCHOR,
    )


def test_exposure_to_incident_builds_external_reference(converter, exposures_list_page):
    exposure = exposures_list_page["data"][0]
    signature = exposure["signature"]

    incident = converter.exposure_to_incident(exposure)

    assert len(incident.external_references) == 3
    portal_ref = incident.external_references[0]
    assert portal_ref["source_name"] == SOURCE_NAME
    assert portal_ref["external_id"] == signature["id"]
    assert portal_ref["url"] == "https://portal.example.com/test-project-id/overview"
    api_ref_urls = {ref["url"] for ref in incident.external_references[1:]}
    assert api_ref_urls == set(signature["references"])
    for ref in incident.external_references[1:]:
        assert ref["source_name"] == SOURCE_NAME
        assert "external_id" not in ref


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

    assert len(incident.external_references) == len(exposure["signature"]["references"])
    for external_ref in incident.external_references:
        assert external_ref["source_name"] == SOURCE_NAME
        assert external_ref["url"] in exposure["signature"]["references"]
        assert "external_id" not in external_ref


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


def test_resolve_created_parses_iso_string(converter, exposures_list_page):
    exposure = exposures_list_page["data"][0]

    incident = converter.exposure_to_incident(exposure)

    assert isinstance(incident.created, datetime)
    assert incident.created.tzinfo is not None
    assert incident.created == datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_converter_exposes_author_and_tlp_marking(converter):
    assert converter.author["type"] == "identity"
    assert converter.author["name"] == "Recorded Future ASI"
    assert converter.tlp_marking["type"] == "marking-definition"
    assert converter.tlp_marking["x_opencti_definition"] == "TLP:AMBER+STRICT"


def test_reset_entity_caches_clears_observable_and_vulnerability_caches(converter):
    converter._observable_cache[("ipv4", "1.2.3.4")] = MagicMock()
    converter._vulnerability_cache["CVE-2024-0001"] = MagicMock()

    converter.reset_entity_caches()

    assert converter._observable_cache == {}
    assert converter._vulnerability_cache == {}


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


def test_build_exposure_objects_merges_assets_signature_references(
    converter, exposures_list_page, all_exposure_assets
):
    """Get-assets signature.references are merged when list signature has none."""
    exposure = {
        "signature": {
            "id": "sig-001",
            "name": "Exposed admin panel",
            "description": "An administrative interface is publicly accessible.",
            "severity": "critical",
            "added_at": "2024-06-01T12:00:00Z",
        },
        "asset_count": 3,
    }

    sdk_objects = converter.build_exposure_objects(exposure, all_exposure_assets)
    incident = next(obj for obj in sdk_objects if isinstance(obj, Incident))
    stix_incident = incident.to_stix2_object()

    ref_urls = [ref["url"] for ref in stix_incident.external_references if "url" in ref]
    assert "https://portal.example.com/test-project-id/overview" in ref_urls
    assert "https://cwe.mitre.org/data/definitions/79.html" in ref_urls


def test_build_exposure_objects_deduplicates_merged_references(
    converter, exposures_list_page, all_exposure_assets
):
    exposure = exposures_list_page["data"][0]

    sdk_objects = converter.build_exposure_objects(exposure, all_exposure_assets)
    incident = next(obj for obj in sdk_objects if isinstance(obj, Incident))
    stix_incident = incident.to_stix2_object()

    api_ref_urls = [
        ref["url"]
        for ref in stix_incident.external_references
        if ref.get("url")
        and ref["url"] != "https://portal.example.com/test-project-id/overview"
    ]
    assert api_ref_urls == [
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "https://cwe.mitre.org/data/definitions/79.html",
    ]


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
    assert len(relationships) == 7

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
    related_to = [rel for rel in relationships if rel.type == "related-to"]

    assert len(related_to) == 7

    incident_related_to = [rel for rel in related_to if rel.source.id == incident.id]
    incident_related_targets = {
        relationship.target.id for relationship in incident_related_to
    }
    expected_incident_related_to_target_ids = {
        obj.id for obj in observables + vulnerabilities
    }
    for relationship in incident_related_to:
        assert relationship.target.id in expected_incident_related_to_target_ids
    assert len(incident_related_to) == 4
    assert incident_related_targets == expected_incident_related_to_target_ids

    observable_ids = {obj.id for obj in observables}
    observable_vulnerability_related_to = [
        rel
        for rel in related_to
        if rel.source.id in observable_ids and rel.target == vulnerability
    ]
    assert len(observable_vulnerability_related_to) == 3
    for relationship in observable_vulnerability_related_to:
        assert relationship.source.id in observable_ids
        assert relationship.target == vulnerability
    assert {
        relationship.source.id for relationship in observable_vulnerability_related_to
    } == observable_ids


def test_build_exposure_objects_relationship_stix_refs_are_stable(
    converter, exposures_list_page, all_exposure_assets
):
    exposure = exposures_list_page["data"][0]
    first_objects = converter.build_exposure_objects(exposure, all_exposure_assets)
    second_objects = converter.build_exposure_objects(exposure, all_exposure_assets)

    incident = next(obj for obj in first_objects if isinstance(obj, Incident))
    first_relationships = [
        obj for obj in first_objects if isinstance(obj, Relationship)
    ]
    second_relationships = [
        obj for obj in second_objects if isinstance(obj, Relationship)
    ]

    first_relationship = first_relationships[0]
    second_relationship = second_relationships[0]

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


def test_build_exposure_objects_observable_vulnerability_related_to_stix_refs_are_stable(
    converter, exposures_list_page, all_exposure_assets
):
    exposure = exposures_list_page["data"][0]
    first_objects = converter.build_exposure_objects(exposure, all_exposure_assets)
    second_objects = converter.build_exposure_objects(exposure, all_exposure_assets)

    observable_ids = {
        obj.id
        for obj in first_objects
        if isinstance(obj, (IPV4Address, IPV6Address, DomainName))
    }

    def observable_vulnerability_related_to(objects):
        return [
            obj
            for obj in objects
            if isinstance(obj, Relationship)
            and obj.type == "related-to"
            and obj.source.id in observable_ids
        ]

    first_related_to = observable_vulnerability_related_to(first_objects)
    second_related_to = observable_vulnerability_related_to(second_objects)
    assert len(first_related_to) == 3

    first_relationship = first_related_to[0]
    second_relationship = second_related_to[0]

    first_stix_relationship = first_relationship.to_stix2_object()
    second_stix_relationship = second_relationship.to_stix2_object()

    assert first_stix_relationship.id == second_stix_relationship.id
    assert first_stix_relationship.source_ref == first_relationship.source.id
    assert first_stix_relationship.target_ref == first_relationship.target.id
    assert first_stix_relationship.id == PyctiStixCoreRelationship.generate_id(
        relationship_type="related-to",
        source_ref=first_relationship.source.id,
        target_ref=first_relationship.target.id,
        start_time=None,
        stop_time=None,
    )


def test_build_exposure_objects_skips_observable_vulnerability_related_to_when_no_vulnerabilities(
    converter, exposures_list_page, all_exposure_assets
):
    exposure = exposures_list_page["data"][0]
    assets_without_vulns = {
        "signature": {"vulnerabilities": []},
        "asset_exposures": all_exposure_assets["asset_exposures"],
    }

    sdk_objects = converter.build_exposure_objects(exposure, assets_without_vulns)

    relationships = [obj for obj in sdk_objects if isinstance(obj, Relationship)]
    related_to = [rel for rel in relationships if rel.type == "related-to"]
    observables = [
        obj
        for obj in sdk_objects
        if isinstance(obj, (IPV4Address, IPV6Address, DomainName))
    ]
    observable_ids = {obj.id for obj in observables}
    observable_vulnerability_related_to = [
        rel for rel in related_to if rel.source.id in observable_ids
    ]

    assert len(related_to) == 3
    assert len(observable_vulnerability_related_to) == 0


def test_build_exposure_objects_observable_vulnerability_related_to_scales_with_multiple_cves(
    converter, exposures_list_page, all_exposure_assets
):
    exposure = exposures_list_page["data"][0]
    assets_with_two_cves = {
        "signature": {
            "vulnerabilities": [
                all_exposure_assets["signature"]["vulnerabilities"][0],
                {
                    "name": "CVE-2024-5678",
                    "cvss_v3": {"base_score": 7.5},
                },
            ],
        },
        "asset_exposures": all_exposure_assets["asset_exposures"],
    }

    sdk_objects = converter.build_exposure_objects(exposure, assets_with_two_cves)

    observables = [
        obj
        for obj in sdk_objects
        if isinstance(obj, (IPV4Address, IPV6Address, DomainName))
    ]
    observable_ids = {obj.id for obj in observables}
    observable_vulnerability_related_to = [
        obj
        for obj in sdk_objects
        if isinstance(obj, Relationship)
        and obj.type == "related-to"
        and obj.source.id in observable_ids
    ]

    assert len(observable_vulnerability_related_to) == 6
