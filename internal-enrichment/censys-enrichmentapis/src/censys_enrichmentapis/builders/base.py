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
        self.bundle: list[BaseObject] = []
        self.markings: list[TLPMarking | Reference] = []
        self._metadata_added = False
        self._set_markings()

    def _set_markings(self, marking_refs: list[str] | None = None) -> None:
        self._uses_default_marking = not marking_refs
        self.markings = (
            [Reference(id=marking_ref) for marking_ref in marking_refs]
            if marking_refs
            else [self.marking]
        )
        self.common_props = {"author": self.author, "markings": self.markings}

    def reset(self, marking_refs: list[str] | None = None) -> None:
        # Replace rather than clear so bundles already returned to callers remain stable.
        self.bundle = []
        self._metadata_added = False
        self._set_markings(marking_refs)

    def add_author_and_marking(self) -> None:
        if self._metadata_added:
            return
        self.bundle.append(self.author)
        if self._uses_default_marking:
            self.bundle.append(self.marking)
        self._metadata_added = True

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
                author=self.author,
                markings=self.markings,
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
