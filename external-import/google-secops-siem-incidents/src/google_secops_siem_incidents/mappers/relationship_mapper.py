"""Map an incident and its observables to Relationship objects."""

from typing import Any

from connectors_sdk.models import Relationship
from connectors_sdk.models.enums import RelationshipType


def map_relationships(
    incident: Any,
    observables: list,
    *,
    author: Any,
    tlp_marking: Any,
) -> list[Relationship]:
    """Create related-to Relationship objects from an incident to each observable.

    Args:
        incident: Source incident model instance.
        observables: Target observable model instances.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        List of Relationship objects, one per observable.
    """
    return [
        Relationship(
            type=RelationshipType.RELATED_TO,
            source=incident,
            target=observable,
            author=author,
            markings=[tlp_marking],
        )
        for observable in observables
    ]
