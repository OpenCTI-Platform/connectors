"""Conversion of parsed attribution into STIX 2.1 objects."""

from typing import Any

import pycti
import stix2

INDICATES_RELATIONSHIP = "indicates"


class ConverterToStix:
    """Builds the Intrusion Sets and relationships implied by ``apt:`` labels.

    Every id is generated with ``pycti``'s deterministic helpers, so replaying
    the same stream event produces byte-identical objects. That is what makes
    the connector safe to restart: OpenCTI sees an upsert rather than a
    duplicate.
    """

    def __init__(self, author_name: str, author_description: str | None = None):
        """
        :param author_name: Organization credited with the derived objects.
            Defaults to the feed's own author so derived attribution merges with
            the ingested data instead of appearing as a separate source.
        :param author_description: Optional description for that organization.
        """
        self.author = stix2.Identity(
            id=pycti.Identity.generate_id(author_name, "organization"),
            name=author_name,
            description=author_description,
            identity_class="organization",
        )

    def create_intrusion_set(
        self,
        name: str,
        confidence: int | None = None,
        object_marking_refs: list[str] | None = None,
    ) -> stix2.IntrusionSet:
        """Build the Intrusion Set for a threat actor.

        :param name: Actor name taken from the ``apt:`` label.
        :param confidence: Confidence inherited from the triggering Indicator.
        :param object_marking_refs: Markings inherited from the triggering
            Indicator, so derived objects are never less restricted than their
            source.
        :return: A STIX 2.1 Intrusion Set with a deterministic id.
        """
        return stix2.IntrusionSet(
            id=pycti.IntrusionSet.generate_id(name),
            name=name,
            created_by_ref=self.author.id,
            confidence=confidence,
            object_marking_refs=object_marking_refs or None,
            allow_custom=True,
        )

    def create_indicates_relationship(
        self,
        indicator_id: str,
        intrusion_set_id: str,
        confidence: int | None = None,
        object_marking_refs: list[str] | None = None,
    ) -> stix2.Relationship:
        """Link an Indicator to the actor it attributes.

        Direction matters and is fixed: Indicator -> Intrusion Set, matching the
        ``indicates`` relationships Malanta already emits towards its own
        infrastructure clusters.

        :param indicator_id: STIX id of the source Indicator.
        :param intrusion_set_id: STIX id of the target Intrusion Set.
        :param confidence: Confidence inherited from the Indicator.
        :param object_marking_refs: Markings inherited from the Indicator.
        :return: A STIX 2.1 Relationship with a deterministic id.
        """
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                INDICATES_RELATIONSHIP, indicator_id, intrusion_set_id
            ),
            relationship_type=INDICATES_RELATIONSHIP,
            source_ref=indicator_id,
            target_ref=intrusion_set_id,
            created_by_ref=self.author.id,
            confidence=confidence,
            object_marking_refs=object_marking_refs or None,
            allow_custom=True,
        )

    def build_attribution_objects(
        self,
        indicator: dict[str, Any],
        actors: list[str],
        create_intrusion_sets: bool = True,
    ) -> list[Any]:
        """Build every object implied by one Indicator's attribution labels.

        :param indicator: The Indicator payload from the stream event.
        :param actors: Actor names parsed from its ``apt:`` labels.
        :param create_intrusion_sets: When ``False``, emit only the
            relationships and rely on the Intrusion Sets already existing.
        :return: Author, Intrusion Sets and relationships, ready to bundle.
            Empty when there is nothing to attribute.
        """
        if not actors:
            return []

        indicator_id = indicator.get("id")
        if not indicator_id:
            return []

        confidence = indicator.get("confidence")
        markings = indicator.get("object_marking_refs") or None

        objects: list[Any] = [self.author]
        for actor in actors:
            intrusion_set = self.create_intrusion_set(
                name=actor,
                confidence=confidence,
                object_marking_refs=markings,
            )
            if create_intrusion_sets:
                objects.append(intrusion_set)
            objects.append(
                self.create_indicates_relationship(
                    indicator_id=indicator_id,
                    intrusion_set_id=intrusion_set.id,
                    confidence=confidence,
                    object_marking_refs=markings,
                )
            )
        return objects
