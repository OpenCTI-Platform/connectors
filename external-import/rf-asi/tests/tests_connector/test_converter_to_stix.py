from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import (
    INCIDENT_TYPE,
    LABEL_ADDED,
    SOURCE_NAME,
    ConverterToStix,
)
from pycti import Incident as PyctiIncident
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
