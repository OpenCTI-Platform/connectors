"""Define Relationships handled by OpenCTI platform."""

from typing import Literal

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.relationship import Relationship


class _RelationshipBuilder:
    """Builder class to enable pipe syntax for relationship creation.

    Notes:
     - We implement pipe syntax rather than greater or bitwise operators because of the simplier order of operations.

    """

    def __init__(
        self,
        relationship_type: str,
    ):
        """Initialize the RelationshipBuilder with a relationship class."""
        self.relationship_type = relationship_type

    def __ror__(self, source: "BaseIdentifiedEntity") -> "_PendingRelationship":
        """Handle source | relationship_builder."""
        return _PendingRelationship(
            source=source,
            relationship_type=self.relationship_type,
        )


class _PendingRelationship:
    """Intermediate object that has source and relationship type but no target."""

    def __init__(
        self,
        source: "BaseIdentifiedEntity",
        relationship_type: str,
    ):
        """Initialize the PendingRelationship with a source entity and relationship class."""
        self.source = source
        self.relationship_type = relationship_type

    def __or__(self, target: "BaseIdentifiedEntity") -> "Relationship":
        """Handle pending_relationship | target."""
        return Relationship(
            type=self.relationship_type,
            source=self.source,
            target=target,
        )


def relationship_builder(
    relationship_type: Literal[
        "related-to",
        "based-on",
        "derived-from",
        "indicates",
        "targets",
        "located-at",
        "has",
    ],
) -> _RelationshipBuilder:
    """Create a relationship builder for the specified type."""
    return _RelationshipBuilder(relationship_type)


related_to = relationship_builder("related-to")
based_on = relationship_builder("based-on")
derived_from = relationship_builder("derived-from")
indicates = relationship_builder("indicates")
targets = relationship_builder("targets")
located_at = relationship_builder("located-at")
has = relationship_builder("has")


if __name__ == "__main__":  # pragma: no cover # do not run coverage on doctests
    import doctest

    doctest.testmod()
