"""Define Relationships handled by OpenCTI platform."""

from abc import ABC
from typing import Any, Literal, Optional, Unpack

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped]  # stix2 does not provide stubs
from connectors_sdk.models.octi._common import (
    MODEL_REGISTRY,
    BaseIdentifiedEntity,
)
from connectors_sdk.models.octi.activities.observations import (
    Indicator,
    Observable,
)
from connectors_sdk.models.octi.knowledge.entities import Organization, Sector
from connectors_sdk.models.octi.knowledge.locations import Country
from connectors_sdk.models.octi.knowledge.threats import IntrusionSet
from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    PrivateAttr,
    create_model,
    model_validator,
)


class _RelationshipBuilder:
    """Builder class to enable pipe syntax for relationship creation.

    Notes:
     - We implement pipe syntax rather than greater or bitwise operators becuase of the simplier order of operations.

    """

    def __init__(self, relationship_class: type["Relationship"]):
        """Initialize the RelationshipBuilder with a relationship class."""
        self.relationship_class = relationship_class

    def __ror__(self, source: "BaseIdentifiedEntity") -> "_PendingRelationship":
        """Handle source | relationship_builder."""
        return _PendingRelationship(
            source=source, relationship_class=self.relationship_class
        )


class _PendingRelationship:
    """Intermediate object that has source and relationship type but no target."""

    def __init__(
        self, source: "BaseIdentifiedEntity", relationship_class: type["Relationship"]
    ):
        """Initialize the PendingRelationship with a source entity and relationship class."""
        self.source = source
        self.relationship_class = relationship_class

    def __or__(self, target: "BaseIdentifiedEntity") -> "Relationship":
        """Handle pending_relationship | target."""
        return self.relationship_class(source=self.source, target=target)


@MODEL_REGISTRY.register
class Relationship(ABC, BaseIdentifiedEntity):
    """Base class for OpenCTI relationships."""

    _relationship_type: str = PrivateAttr("")
    _builder: Optional[_RelationshipBuilder] = PrivateAttr(None)

    source: BaseIdentifiedEntity = Field(
        ...,
        description="The source entity of the relationship.",
    )
    target: BaseIdentifiedEntity = Field(
        ...,
        description="The target entity of the relationship.",
    )
    description: Optional[str] = Field(
        None,
        description="Description of the relationship.",
    )
    start_time: Optional[AwareDatetime] = Field(
        None,
        description="Start time of the relationship in ISO 8601 format.",
    )
    stop_time: Optional[AwareDatetime] = Field(
        None,
        description="End time of the relationship in ISO 8601 format.",
    )

    def to_stix2_object(self) -> stix2.v21.Relationship:
        """Make stix object."""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type=self._relationship_type,
                source_ref=self.source.id,
                target_ref=self.target.id,
                start_time=self.start_time,
                stop_time=self.stop_time,
            ),
            relationship_type=self._relationship_type,
            **self._common_stix2_args(),
        )

    def _common_stix2_args(self) -> dict[str, Any]:
        """Factorize custom params."""
        return dict(  # noqa: C408 # No literal dict for maintainability
            source_ref=self.source.id,
            target_ref=self.target.id,
            description=self.description,
            start_time=self.start_time,
            stop_time=self.stop_time,
            created_by_ref=self.author.id if self.author else None,
            object_marking_refs=[marking.id for marking in self.markings or []],
            external_references=[
                ref.to_stix2_object() for ref in self.external_references or []
            ],
            # unused
            created=None,
            modified=None,
        )

    @model_validator(mode="before")
    @classmethod
    def _prevent_direct_instantiation(cls, data: Any) -> Any:
        """Prevent direct instantiation of the Relationship class as there is no @abstract_method."""
        if cls is Relationship:
            raise TypeError("Cannot instantiate abstract class Relationship directly")
        return data

    def __init_subclass__(cls, **kwargs: Unpack[ConfigDict]) -> None:
        """Ceate a builder for each subclass."""
        super().__init_subclass__(**kwargs)
        cls._builder = _RelationshipBuilder(cls)


@MODEL_REGISTRY.register
class RelatedTo(Relationship):
    """Represent a relationship indicating that an entity is related to another entity.

    This is a generic relationship that can be used for any two entities.
    It is not specific to any type of entity.

    Examples:
        >>> from connectors_sdk.models.octi.knowledge.entities import Organization
        >>> from connectors_sdk.models.octi.activities.observations import IPV4Address
        >>> organization = Organization(name="Example Corp")
        >>> ip = IPV4Address(value="127.0.0.1")
        >>> relationship = RelatedTo(source=ip, target=organization)
    """

    _relationship_type: Literal["related-to"] = "related-to"


related_to = RelatedTo._builder


@MODEL_REGISTRY.register
class BasedOn(Relationship):
    """Represent a relationship indicating that an indicator is based on an observable.

    Notes:
        This relationship creation can be delegated to the OpenCTI platform for simple cases.
        To do so you can create the indicator and set its `create_observables` attribute to True
        or create the Observable and set its create_indcator atribute to True.

    Examples:
        >>> from connectors_sdk.models.octi.activities.observations import Indicator, IPV4Address
        >>> indicator = Indicator(name="Test Indicator", pattern="[ipv4-addr:value = '127.0.0.1']", pattern_type="stix")
        >>> observable = IPV4Address(value="127.0.0.1")
        >>> relationship = BasedOn(source=indicator, target=observable)

    """

    _relationship_type: Literal["based-on"] = "based-on"

    source: Indicator = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an Indicator.",
    )
    target: Observable = Field(
        ...,
        description="Reference to the target entity of the relationship. Here an Observable.",
    )


based_on = BasedOn._builder


# Demonstrate how to dynamically create a Relationship
DerivedFrom = create_model(
    "DerivedFrom",
    __base__=Relationship,
    source=Indicator,
    target=Indicator,
    _relationship_type=(Literal["derived_from"], "derived-from"),
    # extra
    __doc__="""Represent a relationship indicating that an indicator is derived from another indicator.

    Notes:
        - Derived-from is not as permissive in OpenCTI platform as it is in STIX: not all SCO/SDO can be linked together.

    Examples:
        >>> from connectors_sdk.models.octi.activities.observations import Indicator
        >>> url = Indicator(name="Url", pattern="[url:value = 'http://example.com/test']", pattern_type="stix")
        >>> domain = Indicator(name="Domain", pattern="[domain-name:value = 'example.com']", pattern_type="stix")
        >>> relationship = DerivedFrom(source=domain, target=url)
    """,
)
MODEL_REGISTRY.register(DerivedFrom)


@MODEL_REGISTRY.register
class Indicates(Relationship):
    """Represent a relationship indicating that an indicator can detect evidence of an
    attack pattern, campaign, infrastructure, intrusion set, malware, threat actor, or tool.

    Examples:
        >>> from connectors_sdk.models.octi.activities.observations import Indicator
        >>> from connectors_sdk.models.octi.activities.knowledge import IntrusionSet
        >>> indicator = Indicator(name="Test Indicator", pattern="[ipv4-addr:value = '127.0.0.1']", pattern_type="stix")
        >>> intrusion_set = IntrusionSet(name="Test IntrusionSet")
        >>> relationship = Indicates(source=indicator, target=intrusion_set)

    """

    _relationship_type: Literal["indicates"] = "indicates"

    source: Indicator = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an Indicator.",
    )
    target: IntrusionSet = Field(
        ...,
        description="Reference to the target entity of the relationship. Here an IntrusionSet.",
    )


indicates = Indicates._builder


@MODEL_REGISTRY.register
class Targets(Relationship):
    """Represent a relationship indicating that an IntrusionSet targets a Country or an Organization.

    Examples:
        >>> from connectors_sdk.models.octi.knowledge.locations import Country
        >>> from connectors_sdk.models.octi.knowledge.threats import IntrusionSet
        >>> intrusion_set = IntrusionSet(name="Test IntrusionSet")
        >>> country = Country(name="France")
        >>> relationship = Targets(source=intrusion_set, target=country)

    """

    _relationship_type: Literal["targets"] = "targets"

    source: IntrusionSet = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an Intrusion Set.",
    )
    target: Country | Organization = Field(
        ...,
        description="Reference to the target entity of the relationship. Here a Country or an Organization.",
    )


targets = Targets._builder


@MODEL_REGISTRY.register
class LocatedAt(Relationship):
    """Represent a relationship indicating that a Sector or an Orgnization is located at a Country.

    Examples:
        >>> from connectors_sdk.models.octi.knowledge.entities import Sector
        >>> from connectors_sdk.models.octi.knowledge.locations import Country
        >>> sector = Sector(name="Test Sector")
        >>> country = Country(name="France")
        >>> relationship = LocatedAt(source=sector, target=country)

    """

    _relationship_type: Literal["located-at"] = "located-at"

    source: Organization | Sector = Field(
        ...,
        description="Reference to the source entity of the relationship. Here a Sector.",
    )
    target: Country = Field(
        ...,
        description="Reference to the target entity of the relationship. Here a Country.",
    )


located_at = LocatedAt._builder


MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover # do not run coverage on doctests
    import doctest

    doctest.testmod()
