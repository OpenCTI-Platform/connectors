import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.course_of_action import CourseOfAction
from pycti import CourseOfAction as PyctiCourseOfAction
from pydantic import ValidationError
from stix2.v21 import CourseOfAction as Stix2CourseOfAction


def test_course_of_action_is_a_base_identified_entity():
    """Test that CourseOfAction is a BaseIdentifiedEntity."""
    # Given the CourseOfAction class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(CourseOfAction, BaseIdentifiedEntity)


def test_course_of_action_class_should_not_accept_invalid_input():
    """Test that CourseOfAction class should not accept invalid input."""
    # Given: An invalid input data for CourseOfAction
    input_data = {
        "name": "Test course of action",
        "invalid_key": "invalid_value",
    }
    # When validating the course of action
    # Then: It should raise a ValidationError
    with pytest.raises(ValidationError):
        CourseOfAction.model_validate(input_data)


def test_course_of_action_class_should_require_name():
    """Test that CourseOfAction class requires name field."""
    # Given: An input data without name
    input_data = {"description": "Test description"}
    # When validating the course of action
    # Then: It should raise a ValidationError
    with pytest.raises(ValidationError):
        CourseOfAction.model_validate(input_data)


def test_course_of_action_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that CourseOfAction to_stix2_object method returns a valid STIX2.1 CourseOfAction."""
    # Given: A valid CourseOfAction instance
    course_of_action = CourseOfAction(
        name="Test course of action",
        description="Test description",
        labels=["test-label"],
        aliases=["Test alias"],
        mitre_id="M1234",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = course_of_action.to_stix2_object()
    # Then: A valid STIX2.1 CourseOfAction is returned with expected properties
    assert isinstance(stix2_obj, Stix2CourseOfAction)
    assert stix2_obj.id == PyctiCourseOfAction.generate_id(
        name="Test course of action", x_mitre_id="M1234"
    )
    assert stix2_obj.name == "Test course of action"
    assert stix2_obj.description == "Test description"
    assert stix2_obj.labels == ["test-label"]
    assert stix2_obj.x_opencti_aliases == ["Test alias"]
    assert stix2_obj.x_mitre_id == "M1234"
    assert stix2_obj.created_by_ref == fake_valid_organization_author.id
    assert stix2_obj.object_marking_refs == [
        marking.id for marking in fake_valid_tlp_markings
    ]


def test_course_of_action_to_stix2_object_with_minimal_fields():
    """Test that CourseOfAction to_stix2_object works with only required fields."""
    # Given: A minimal CourseOfAction instance
    course_of_action = CourseOfAction(name="Minimal course of action")
    # When: calling to_stix2_object method
    stix2_obj = course_of_action.to_stix2_object()
    # Then: A valid STIX2.1 CourseOfAction is returned
    assert isinstance(stix2_obj, Stix2CourseOfAction)
    assert stix2_obj.name == "Minimal course of action"
    assert stix2_obj.id == PyctiCourseOfAction.generate_id(
        name="Minimal course of action", x_mitre_id=None
    )
