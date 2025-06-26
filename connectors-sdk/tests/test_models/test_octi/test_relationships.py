"""Offer tests for OpenCTI relationships."""

import pytest
import stix2
from connectors_sdk.models.octi._common import BaseIdentifiedEntity
from connectors_sdk.models.octi.activities.observations import Indicator, Observable
from connectors_sdk.models.octi.relationships import (
    BasedOn,
    DerivedFrom,
    Indicates,
    LocatedAt,
    RelatedTo,
    Relationship,
    Targets,
    based_on,
    related_to,
)
from pydantic import create_model

# Add the newly implemented relationship in this list
IMPLEMENTED_RELATIONSHIPS = [
    BasedOn,
    DerivedFrom,
    LocatedAt,
    Indicates,
    RelatedTo,
    Targets,
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

    relationship = create_model(
        "DummyRelationship",
        source=author.__class__,
        target=author.__class__,
        _relationship_type=(str, "me-myself-and-i"),
        __base__=Relationship,
    )(
        source=author,
        target=author,
    )
    # Then it should have the default fields
    assert hasattr(relationship, "source")
    assert hasattr(relationship, "target")
    assert hasattr(relationship, "start_time")
    assert hasattr(relationship, "stop_time")
    assert hasattr(relationship, "description")


def test_relationship_to_stix2_object(fake_valid_organization_author):
    """Test that Relationship can be converted to a STIX2 object."""
    # Given a Relationship instance
    author = fake_valid_organization_author
    rel = create_model(
        "DummyRelationship",
        source=author.__class__,
        target=author.__class__,
        _relationship_type=(str, "me-myself-and-i"),
        __base__=Relationship,
    )(source=author, target=author)
    # When converting it to a STIX2 object
    stix_object = rel.to_stix2_object()
    # Then it should be a valid STIX2 Relationship object
    assert stix_object.get("relationship_type") == "me-myself-and-i"
    assert stix_object.get("source_ref") == author.id
    assert stix_object.get("target_ref") == author.id


def test_relationship_cannot_be_instantiated_directly(fake_valid_organization_author):
    """Test that Relationship cannot be instantiated directly."""
    # Given the Relationship class and a valid BaseIdentifiedEntity instance (here an OrganizationAuthor for simplicity)
    author = fake_valid_organization_author
    # When trying to create an instance
    # Then it should raise a TypeError
    with pytest.raises(TypeError):
        _ = Relationship(source=author, target=author)


### IMPLEMENTED RELATIONSHIPS


@pytest.mark.parametrize("relationship_cls", IMPLEMENTED_RELATIONSHIPS)
def test_implemented_relationship_is_a_subclass_of_relationship(relationship_cls):
    """Test that implemented relationship is subclass of Relationship."""
    # Given an implemented relationship class
    # When checking its type
    # Then it should be a subclass of Relationship
    assert issubclass(relationship_cls, Relationship)


### SPECIAL CASE


def test_any_related_to_any_can_use_pipe_syntax(fake_valid_organization_author):
    """Test that RelatedTo can use pipe syntax."""
    # Given the RelatedTo relationship class and a valid BaseIdentifiedEntity instance
    author = fake_valid_organization_author
    # When using the pipe syntax to create a relationship
    relationship = author | related_to | author
    # Then it should return an instance of RelatedTo with the correct source and target
    assert isinstance(relationship, RelatedTo)
    assert relationship.source == author
    assert relationship.target == author


def test_based_on_can_use_pipe_syntax():
    """Test that BasedOn can use pipe syntax."""
    # Given the BasedOn relationship class and a Indicator and a valid Observable instance
    ind = create_model(
        "DummyIndicator",
        __base__=Indicator,
    )(
        name="dummy_indicator",
        pattern="[ipv4-addr:value = '127.0.0.1']",
        pattern_type="stix",
    )

    class DummyObservable(Observable):
        """Dummy Observable for testing."""

        def to_stix2_object(self):
            """Dummy method to satisfy the interface."""
            return stix2.v21.IPv4Address(value="127.0.0.1")

    obs = DummyObservable()
    # When using the pipe syntax to create a relationship
    relationship = ind | based_on | obs
    # Then it should return an instance of BasedOn with the correct source and target
    assert isinstance(relationship, BasedOn)
    assert relationship.source == ind
    assert relationship.target == obs
