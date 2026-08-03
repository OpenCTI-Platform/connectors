from unittest.mock import MagicMock

from connector.converter_to_stix import ConverterToStix
from connector.settings import AssetnoteImportConfig


def _make_converter(status_mapping=None):
    helper = MagicMock()
    config = AssetnoteImportConfig(api_base_url="http://test.com", api_key="test-key")
    return ConverterToStix(helper, config, status_mapping or {})


def test_base_stix_objects_returns_author_and_marking():
    """
    Ensure the base stix objects contain both the Identity and TLP
    as stix objects
    """
    converter = _make_converter()

    objects = converter.base_stix_objects()

    assert [o["type"] for o in objects] == ["identity", "marking-definition"]
    assert objects[0]["name"] == "Assetnote"


def _make_exposure(**overrides):
    # Mimicking the structure of a true exposure
    exposure = {
        "id": "1234",
        "exposureType": "VULNERABILITY",
        "created": "2024-01-01T00:00:00Z",
        "triageState": "UNRESOLVED",
        "severityString": "HIGH",
        "signature": {
            "name": "Test Exposure Name",
            "cve": None,
            "description": "Test exposure description.",
            "recommendations": "Test recommendation.",
        },
        "asset": {
            "id": "asset-1",
            "assetType": "SUBDOMAIN",
            "host": "test-host.invalid",
            "platformUrl": "https://test.invalid/assets/asset-1",
            "onlineLastUpdated": "2024-01-02T00:00:00Z",
        },
        "knownExploitation": None,
        "exposureData": {"edges": []},
    }
    exposure.update(overrides)
    return exposure


def test_convert_exposure_without_software():
    """
    In the case of an Exposure containing no knownExploitation.product, a valid Incident Response,
    Course of Action, Vulnerability and Infrastructure (alongside relationships) should be made (with
    each object linked under the Incident Response) with NO software object present.
    """
    converter = _make_converter()
    exposure = _make_exposure()
    objects = converter.convert_exposure(exposure)
    assert not any(getattr(o, "type", "") == "software" for o in objects)

    # Ensure all objects are still references by the case
    case_incident_object = next(o for o in objects if o["type"] == "case-incident")
    for obj in objects:
        if obj is not case_incident_object:
            assert obj.id in case_incident_object["object_refs"]


def test_convert_exposure_with_software_adds_two_relationships():
    """
    In the case of an Exposure that should have a Software object, the bundle should contain:
        - Infrastructure 'hosts' Software
        - Software 'has' Vulnerability
    """
    converter = _make_converter()
    exposure = _make_exposure(
        knownExploitation={"product": "Test Product", "vendorProject": "Test Vendor"}
    )
    objects = converter.convert_exposure(exposure)
    types = [getattr(o, "type", type(o).__name__) for o in objects]
    # ensure the existence of a single software object
    assert types.count("software") == 1

    infrastructure_object = next(o for o in objects if o["type"] == "infrastructure")
    software_object = next(o for o in objects if o["type"] == "software")
    vulnerability_object = next(o for o in objects if o["type"] == "vulnerability")
    relationships = {
        (r["relationship_type"], r["source_ref"], r["target_ref"])
        for r in objects
        if r["type"] == "relationship"
    }
    assert ("hosts", infrastructure_object.id, software_object.id) in relationships
    assert ("has", software_object.id, vulnerability_object.id) in relationships


def test_convert_exposure_uses_cve_as_vulnerability_name_when_present():
    """
    Exposures all involve a Vulnerability but some are known CVEs and others are not,
    thus when an Exposure has a populated 'cve' field under its signature the Vulnerability
    object should be named according to the CVE as opposed to its signature name
    """
    converter = _make_converter()
    exposure = _make_exposure(
        signature={**_make_exposure()["signature"], "cve": "CVE-2024-1234"}
    )

    objects = converter.convert_exposure(exposure)
    vulnerability_object = next(o for o in objects if o["type"] == "vulnerability")
    assert vulnerability_object.name == "CVE-2024-1234"


def test_convert_exposure_falls_back_to_signature_name_without_cve():
    """
    The Vulnerability object of Exposures with no populated 'cve' field in their signature
    should receive the 'name' field of their signature, since they are not tied to any CVE
    """
    converter = _make_converter()
    exposure = _make_exposure()

    objects = converter.convert_exposure(exposure)
    vulnerability_object = next(o for o in objects if o["type"] == "vulnerability")
    assert vulnerability_object.name == "Test Exposure Name"


def test_convert_exposure_creates_one_note_per_interaction():
    """
    For an Exposure with multiple interactions, ensure each is converted to a note.

    NB: in test data there was only ever a single interaction, though it is implied more can exist
    under this schema
    """

    converter = _make_converter()
    exposure = _make_exposure(
        exposureData={
            "edges": [
                {
                    "node": {
                        "request": "GET /a",
                        "response": "200 OK",
                        "created": "2024-01-01T00:00:00Z",
                    }
                },
                {
                    "node": {
                        "request": "GET /b",
                        "response": "404",
                        "created": "2024-01-02T00:00:00Z",
                    }
                },
            ]
        }
    )
    objects = converter.convert_exposure(exposure)
    notes = [o for o in objects if getattr(o, "type", "") == "note"]

    # ensure the existence of each note and their correct abstract
    assert len(notes) == 2
    assert notes[0]["abstract"].startswith("Interaction 1 at")
    assert notes[1]["abstract"].startswith("Interaction 2 at")
    case_incident_object = next(o for o in objects if o["type"] == "case-incident")
    # ensure each note is linked to the case incident object
    for note in notes:
        assert case_incident_object.id in note["object_refs"]


def test_convert_exposure_sets_workflow_id_when_status_mapped():
    """
    When a Template Status mapping has been provided in the configs matching the
    Exposure's triageState, the Incident Response object should receive the mapped value
    in its x_opencti_workflow_id.

    This is how OpenCTI assigns said status to the object.
    """
    converter = _make_converter(status_mapping={"UNRESOLVED": "status-id-123"})
    exposure = _make_exposure(triageState="UNRESOLVED")

    objects = converter.convert_exposure(exposure)
    case_incident_object = next(o for o in objects if o["type"] == "case-incident")
    assert case_incident_object["x_opencti_workflow_id"] == "status-id-123"


def test_convert_exposure_omits_workflow_id_when_not_mapped():
    """
    When the Exposure's triageState has no matching entry in status_mapping,
    the Case Incident should omit x_opencti_workflow_id rather than setting it
    to None or an invalid status.
    """
    converter = _make_converter(status_mapping={})
    exposure = _make_exposure(triageState="UNRESOLVED")

    objects = converter.convert_exposure(exposure)
    case_incident_object = next(o for o in objects if o["type"] == "case-incident")
    assert "x_opencti_workflow_id" not in case_incident_object
