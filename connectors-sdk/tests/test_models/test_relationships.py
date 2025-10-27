"""Offer tests for OpenCTI relationships."""

from datetime import datetime

import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.octi.relationships import (
    based_on,
    derived_from,
    has,
    indicates,
    located_at,
    related_to,
    targets,
)
from connectors_sdk.models.relationship import Relationship
from pydantic import ValidationError

# Add the newly implemented relationship in this list
IMPLEMENTED_RELATIONSHIPS = [
    Relationship,
    related_to,
    based_on,
    derived_from,
    indicates,
    targets,
    located_at,
    has,
]


### BASE RELATIONSHIP


def test_relationship_is_a_base_identified_entity():
    """Test that Relationship is a BaseIdentifiedEntity."""
    # Given the Relationship class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Relationship, BaseIdentifiedEntity)


def test_relationship_has_required_fields(fake_valid_organization_author):
    """Test that Relationship has the default fields."""
    # Given an implemented Relationship class
    # When creating an instance
    author = fake_valid_organization_author

    relationship = Relationship(
        type="related-to",
        source=author,
        target=author,
        description="This is a test relationship.",
    )
    # Then it should have the default fields
    assert hasattr(relationship, "type")
    assert hasattr(relationship, "source")
    assert hasattr(relationship, "target")
    assert hasattr(relationship, "start_time")
    assert hasattr(relationship, "stop_time")
    assert hasattr(relationship, "description")


def test_relationship_to_stix2_object(fake_valid_organization_author):
    """Test that Relationship can be converted to a STIX2 object."""
    # Given a Relationship instance
    author = fake_valid_organization_author
    relationship = Relationship(
        type="based-on",
        source=author,
        target=author,
        description="This is a test relationship.",
    )
    # When converting it to a STIX2 object
    stix_object = relationship.to_stix2_object()
    # Then it should be a valid STIX2 Relationship object
    assert stix_object.get("relationship_type") == "based-on"
    assert stix_object.get("source_ref") == author.id
    assert stix_object.get("target_ref") == author.id


def test_relationship_should_not_accept_invalid_input():
    """Test that Relationship class should not accept invalid input."""
    # Given: An invalid input data for Relationship
    input_data = {
        "type": "indicates",
        "invalid_key": "invalid_value",
    }
    # When validating the ipv4 address
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Relationship.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_relationship_should_not_accept_incoherent_dates(
    fake_valid_organization_author,
):
    """Test that Relationship should not accept incoherent dates."""
    # Given an invalid input data for Relationship with start_time after stop_time
    author = fake_valid_organization_author

    input_data = {
        "type": "derived-from",
        "source": author,
        "target": author,
        "start_time": datetime.fromisoformat("2024-01-01T00:00:00+00:00"),
        "stop_time": datetime.fromisoformat("2023-01-01T00:00:00+00:00"),
    }
    # When validating the relationship
    # Then It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        _ = Relationship.model_validate(input_data)
        assert all(
            w in str(error.value.errors()[0]) for w in ("'stop_time'", "'start_time'")
        )


### PIPE SYNTAX


@pytest.mark.parametrize(
    "relationship_type,relationship_builder",
    [
        ("related-to", related_to),
        ("based-on", based_on),
        ("derived-from", derived_from),
        ("indicates", indicates),
        ("targets", targets),
        ("located-at", located_at),
        ("has", has),
    ],
)
def test_relationship_can_use_pipe_syntax(
    relationship_type, relationship_builder, fake_valid_organization_author
):
    """Test that RelatedTo can use pipe syntax."""
    # Given the RelatedTo relationship class and a valid BaseIdentifiedEntity instance
    author = fake_valid_organization_author
    # When using the pipe syntax to create a relationship
    relationship = author | relationship_builder | author
    # Then it should return an instance of RelatedTo with the correct source and target
    assert isinstance(relationship, Relationship)
    assert relationship.type == relationship_type
    assert relationship.source == author
    assert relationship.target == author
