"""Offer OpenCTI models."""

import stix2  # type: ignore[import-untyped]  # stix2 does not provide stubs
from connectors_sdk.models.octi._common import (
    MODEL_REGISTRY,
    AssociatedFile,
    Author,
    BaseEntity,
    ExternalReference,
    TLPMarking,
)
from connectors_sdk.models.octi.activities.observations import (
    Indicator,
    IPV4Address,
)
from connectors_sdk.models.octi.knowledge.entities import Organization, Sector
from connectors_sdk.models.octi.knowledge.locations import Country
from connectors_sdk.models.octi.knowledge.threats import IntrusionSet
from connectors_sdk.models.octi.relationships import (
    BasedOn,
    DerivedFrom,
    LocatedAt,
    RelatedTo,
    Targets,
    based_on,
    located_at,
    related_to,
    targets,
)
from connectors_sdk.models.octi.settings.taxonomies import KillChainPhase

__all__ = [
    # Models flat list
    "AssociatedFile",
    "BasedOn",
    "Country",
    "DerivedFrom",
    "ExternalReference",
    "Indicator",
    "IntrusionSet",
    "IPV4Address",
    "KillChainPhase",
    "LocatedAt",
    "Organization",
    "OrganizationAuthor",
    "RelatedTo",
    "Sector",
    "Targets",
    "TLPMarking",
    # Relationship builders
    "based_on",
    "located_at",
    "related_to",
    "targets",
    # Typing purpose
    "BaseEntity",
]


@MODEL_REGISTRY.register
class OrganizationAuthor(Author, Organization):
    """Represent an organization author.

    This class extends the Organization class to include author-specific fields that will be
    widely used for all other entities a connector processes.

    Examples:
        >>> my_author = OrganizationAuthor(name="Company providing SIEM")
        >>> org = Organization(name="Example Corp", author=my_author)
        >>> entity = org.to_stix2_object()

    """

    def to_stix2_object(self) -> stix2.v21.Identity:
        """Make stix object."""
        return Organization.to_stix2_object(self)


MODEL_REGISTRY.rebuild_all()
