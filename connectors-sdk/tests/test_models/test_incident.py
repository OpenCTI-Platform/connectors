import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.incident import Incident
from pycti import Incident as PyctiIncident
from pydantic import ValidationError
from stix2.v21 import Incident as Stix2Incident


def test_incident_is_a_base_identified_entity():
    """Test that Incident is a BaseIdentifiedEntity."""
    assert issubclass(Incident, BaseIdentifiedEntity)


def test_incident_class_should_not_accept_invalid_input():
    """Test that Incident class should not accept invalid input."""
    input_data = {
        "name": "Test incident",
        "created": "2024-01-01T00:00:00Z",
        "invalid_key": "invalid_value",
    }
    with pytest.raises(ValidationError):
        Incident.model_validate(input_data)


def test_incident_class_should_require_name_and_created():
    """Test that Incident class requires name and created fields."""
    with pytest.raises(ValidationError):
        Incident.model_validate({"name": "Test incident"})
    with pytest.raises(ValidationError):
        Incident.model_validate({"created": "2024-01-01T00:00:00Z"})


def test_incident_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Incident to_stix2_object method returns a valid STIX2.1 Incident."""
    incident = Incident(
        name="Test incident",
        created="2024-01-01T00:00:00Z",
        description="Test description",
        incident_type="alert",
        severity="high",
        source="Test source",
        first_seen="2023-12-01T00:00:00Z",
        last_seen="2024-01-01T00:00:00Z",
        labels=["test-label"],
        objective="Test objective",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    stix2_obj = incident.to_stix2_object()

    assert isinstance(stix2_obj, Stix2Incident)
    assert stix2_obj.id == PyctiIncident.generate_id(
        name="Test incident", created=incident.created
    )
    assert stix2_obj.name == "Test incident"
    assert stix2_obj.description == "Test description"
    assert stix2_obj.labels == ["test-label"]
    assert stix2_obj.objective == "Test objective"
    assert stix2_obj.source == "Test source"
    assert stix2_obj.severity == incident.severity
    assert stix2_obj.incident_type == incident.incident_type
    assert stix2_obj.first_seen == incident.first_seen
    assert stix2_obj.last_seen == incident.last_seen
    assert stix2_obj.created_by_ref == fake_valid_organization_author.id
    assert stix2_obj.object_marking_refs == [
        marking.id for marking in fake_valid_tlp_markings
    ]


def test_incident_to_stix2_object_with_minimal_fields():
    """Test that Incident to_stix2_object works with only required fields."""
    incident = Incident(
        name="Minimal incident",
        created="2024-06-15T10:00:00Z",
    )
    stix2_obj = incident.to_stix2_object()

    assert isinstance(stix2_obj, Stix2Incident)
    assert stix2_obj.name == "Minimal incident"
    assert stix2_obj.id == PyctiIncident.generate_id(
        name="Minimal incident", created=incident.created
    )
