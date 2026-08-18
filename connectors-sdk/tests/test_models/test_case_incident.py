import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.case_incident import CaseIncident
from pycti import CaseIncident as PyctiCaseIncident
from pycti import CustomObjectCaseIncident
from pydantic import ValidationError


def test_case_incident_is_a_base_identified_entity():
    """Test that CaseIncident is a BaseIdentifiedEntity."""
    # Given the CaseIncident class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(CaseIncident, BaseIdentifiedEntity)


def test_case_incident_class_should_not_accept_invalid_input():
    """Test that CaseIncident class should not accept invalid input."""
    # Given: An invalid input data for CaseIncident
    input_data = {
        "name": "Test case incident",
        "invalid_key": "invalid_value",
    }
    # When validating the case incident
    # Then: It should raise a ValidationError
    with pytest.raises(ValidationError):
        CaseIncident.model_validate(input_data)


def test_case_incident_class_should_require_name():
    """Test that CaseIncident class requires name field."""
    # Given: An input data without name
    input_data = {"description": "Test description"}
    # When validating the case incident
    # Then: It should raise a ValidationError
    with pytest.raises(ValidationError):
        CaseIncident.model_validate(input_data)


def test_case_incident_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that CaseIncident to_stix2_object method returns a valid STIX-like object."""
    # Given: A valid CaseIncident instance
    case_incident = CaseIncident(
        name="Test case incident",
        description="Test description",
        severity="high",
        priority="P1",
        response_types=["ransomware"],
        labels=["test-label"],
        created="2024-01-01T00:00:00Z",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = case_incident.to_stix2_object()
    # Then: A valid CustomObjectCaseIncident is returned with expected properties
    assert isinstance(stix2_obj, CustomObjectCaseIncident)
    assert stix2_obj.id == PyctiCaseIncident.generate_id(
        name="Test case incident", created=case_incident.created
    )
    assert stix2_obj.name == "Test case incident"
    assert stix2_obj.description == "Test description"
    assert stix2_obj.severity == "high"
    assert stix2_obj.priority == "P1"
    assert stix2_obj.response_types == ["ransomware"]
    assert stix2_obj.labels == ["test-label"]
    assert stix2_obj.created_by_ref == fake_valid_organization_author.id
    assert stix2_obj.object_marking_refs == [
        marking.id for marking in fake_valid_tlp_markings
    ]


def test_case_incident_to_stix2_object_with_minimal_fields():
    """Test that CaseIncident to_stix2_object works with only required fields."""
    # Given: A minimal CaseIncident instance
    case_incident = CaseIncident(name="Minimal case incident")
    # When: calling to_stix2_object method
    stix2_obj = case_incident.to_stix2_object()
    # Then: A valid CustomObjectCaseIncident is returned
    assert isinstance(stix2_obj, CustomObjectCaseIncident)
    assert stix2_obj.name == "Minimal case incident"
    assert stix2_obj.id == PyctiCaseIncident.generate_id(
        name="Minimal case incident", created=case_incident.created
    )


def test_case_incident_to_stix2_object_with_objects(
    fake_valid_organization_author,
):
    """Test that CaseIncident to_stix2_object includes object_refs from objects field."""
    # Given: A CaseIncident instance with objects referencing other entities
    from connectors_sdk.models.reference import Reference

    case_incident = CaseIncident(
        name="Test case incident with objects",
        objects=[Reference(id="indicator--38e59ee8-9490-5b09-91b8-cbb60591fb95")],
    )
    # When: calling to_stix2_object method
    stix2_obj = case_incident.to_stix2_object()
    # Then: object_refs should contain the referenced object id
    assert stix2_obj.object_refs == [obj.id for obj in case_incident.objects]
