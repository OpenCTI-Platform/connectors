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
from connectors_sdk.models.octi.knowledge.entities import Organization
from connectors_sdk.models.octi.relationships import (
    AnyRelatedToAny,
    IndicatorBasedOnObservable,
    IndicatorDerivedFromIndicator,
    based_on,
    related_to,
)
from connectors_sdk.models.octi.settings.taxonomies import KillChainPhase

__all__ = [
    "AnyRelatedToAny",
    "AssociatedFile",
    "BaseEntity",  # for typing purpose.
    "ExternalReference",
    "Indicator",
    "IndicatorBasedOnObservable",
    "IndicatorDerivedFromIndicator",
    "IPV4Address",
    "KillChainPhase",
    "Organization",
    "OrganizationAuthor",
    "TLPMarking",
    "related_to",
    "based_on",
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
