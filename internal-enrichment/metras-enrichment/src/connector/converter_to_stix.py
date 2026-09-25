"""STIX conversion for the Metras Enrichment connector (INTERNAL_ENRICHMENT).

Per-observable outputs: a context Note (fleet hit summary), an optional System
identity (matched fleet endpoint, an internal asset — not an IOC) and a related-to
Relationship linking them. No Sightings or Infrastructure objects are emitted.
"""

import stix2
from pycti import Identity, Note, OpenCTIConnectorHelper, StixCoreRelationship


class ConverterToStix:
    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        self.helper = helper
        self.author = self._create_author()
        self._confidence = getattr(helper, "connect_confidence_level", None) or 50

    @staticmethod
    def _create_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(name="Metras", identity_class="organization"),
            name="Metras",
            identity_class="organization",
            description="Metras endpoint detection & response (EDR) platform.",
            allow_custom=True,
        )

    def author_object(self) -> stix2.Identity:
        return self.author

    def create_note(
        self,
        observable_id: str,
        abstract: str,
        content: str,
        labels: list | None = None,
    ) -> stix2.Note:
        return stix2.Note(
            id=Note.generate_id(created=None, content=content, abstract=abstract),
            abstract=abstract,
            content=content,
            object_refs=[observable_id],
            created_by_ref=self.author["id"],
            labels=labels or [],
            confidence=self._confidence,
            allow_custom=True,
        )

    def create_system(
        self, name: str | None, description: str | None = None
    ) -> stix2.Identity | None:
        """A fleet endpoint/host as a System identity (internal asset, not an IOC)."""
        if not name:
            return None
        return stix2.Identity(
            id=Identity.generate_id(name=name, identity_class="system"),
            name=name,
            identity_class="system",
            description=description,
            created_by_ref=self.author["id"],
            confidence=self._confidence,
            allow_custom=True,
        )

    def create_relationship(
        self, source_id: str, rel_type: str, target_id: str
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            relationship_type=rel_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author["id"],
            confidence=self._confidence,
            allow_custom=True,
        )
