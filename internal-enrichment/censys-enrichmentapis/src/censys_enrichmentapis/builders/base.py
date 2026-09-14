from connectors_sdk.models import (
    BaseObject,
    OrganizationAuthor,
    Reference,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import RelationshipType, TLPLevel


class StixBuildContext:
    """Shared bundle state and metadata used by all area builders."""

    def __init__(self) -> None:
        self.author = OrganizationAuthor(name="Censys EnrichmentAPIs Connector")
        self.marking = TLPMarking(level=TLPLevel.CLEAR)
        self.common_props = {"author": self.author, "markings": [self.marking]}
        self.bundle: list[BaseObject] = []

    def reset(self) -> None:
        # Replace rather than clear so bundles already returned to callers remain stable.
        self.bundle = []

    def add_author_and_marking(self) -> None:
        self.bundle.extend([self.author, self.marking])

    def add_relationship(
        self,
        source: Reference,
        target: Reference,
        relationship_type: RelationshipType,
    ) -> None:
        self.bundle.append(
            Relationship(
                source=source,
                target=target,
                type=relationship_type,
                **self.common_props,
            )
        )


class AreaStixBuilder:
    """Base class providing area builders access to shared build state."""

    def __init__(self, context: StixBuildContext) -> None:
        self._context = context

    @property
    def bundle(self) -> list[BaseObject]:
        return self._context.bundle

    @property
    def common_props(self) -> dict[str, object]:
        return self._context.common_props

    def add_relationship(
        self,
        source: Reference,
        target: Reference,
        relationship_type: RelationshipType,
    ) -> None:
        self._context.add_relationship(source, target, relationship_type)
