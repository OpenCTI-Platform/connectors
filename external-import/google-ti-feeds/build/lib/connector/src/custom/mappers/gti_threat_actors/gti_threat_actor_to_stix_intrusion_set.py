"""Converts a GTI threat actor to a STIX intrusion set object."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.models.gti.gti_threat_actor_model import (
    GTIThreatActorData,
    ThreatActorModel,
)
from connector.src.stix.octi.models.intrusion_set_model import OctiIntrusionSetModel
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.v21.models.cdts.external_reference_model import (
    ExternalReferenceModel,
)
from connector.src.stix.v21.models.ovs.attack_motivation_ov_enums import (
    AttackMotivationOV,
)
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from stix2.v21 import IntrusionSet  # type: ignore


class GTIThreatActorToSTIXIntrusionSet(BaseMapper):
    """Converts a GTI threat actor to a STIX intrusion set object."""

    @staticmethod
    def create_relationship(
        src_entity: Any, relation_type: str, target_entity: Any
    ) -> Any:
        """Create a relationship between an intrusion set and target entity.

        Args:
            src_entity: The source entity
            relation_type: The relationship type
            target_entity: The target entity

        Returns:
            OctiRelationshipModel: The relationship object

        """
        if not any(
            "IntrusionSet" in str(type(entity).__name__)
            for entity in [src_entity, target_entity]
        ):
            return None

        return OctiRelationshipModel.create(
            relationship_type=relation_type,
            source_ref=src_entity.id,
            target_ref=target_entity.id,
            organization_id=src_entity.created_by_ref,
            marking_ids=src_entity.object_marking_refs,
            created=datetime.now(tz=timezone.utc),
            modified=datetime.now(tz=timezone.utc),
            description=f"{type(src_entity).__name__} {relation_type} {type(target_entity).__name__}",
        )

    def __init__(
        self,
        threat_actor: GTIThreatActorData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
        enable_threat_actor_aliases: bool = False,
    ) -> None:
        """Initialize the GTIThreatActorToSTIXIntrusionSet object.

        Args:
            threat_actor (GTIThreatActorData): The GTI threat actor data to convert.
            organization (OrganizationAuthor): The organization identity object.
            tlp_marking (TLPMarking): The TLP marking definition.
            enable_threat_actor_aliases (bool): Whether to enable importing threat actor aliases.

        """
        self.threat_actor = threat_actor
        self.organization = organization
        self.tlp_marking = tlp_marking
        self.enable_threat_actor_aliases = enable_threat_actor_aliases

    def to_stix(self) -> IntrusionSet:
        """Convert the GTI threat actor to a STIX intrusion set object.

        Returns:
            IntrusionSet: The STIX intrusion set object.

        """
        if (
            not hasattr(self.threat_actor, "attributes")
            or not self.threat_actor.attributes
        ):
            raise ValueError("Invalid GTI threat actor data")

        attributes = self.threat_actor.attributes

        created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        modified = datetime.fromtimestamp(
            attributes.last_modification_date, tz=timezone.utc
        )

        aliases = (
            self._extract_aliases(attributes)
            if self.enable_threat_actor_aliases
            else None
        )

        first_seen, last_seen = self._extract_seen_dates(attributes)

        primary_motivation, secondary_motivations = self._extract_motivations(
            attributes
        )

        external_references = self._build_external_references()

        name = attributes.name
        description = attributes.description

        labels = self._extract_labels(attributes)

        intrusion_set_model = OctiIntrusionSetModel.create(
            name=name,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            description=description,
            aliases=aliases,
            first_seen=first_seen,
            last_seen=last_seen,
            primary_motivation=primary_motivation,
            secondary_motivations=secondary_motivations,
            labels=labels,
            created=created,
            modified=modified,
            external_references=[
                ref.model_dump(exclude_none=True) for ref in external_references
            ],
        )

        return intrusion_set_model

    @staticmethod
    def _extract_aliases(attributes: ThreatActorModel) -> list[str] | None:
        """Extract aliases from threat actor attributes.

        Args:
            attributes: The threat actor attributes

        Returns:
            list[str] | None: Extracted aliases or None if no aliases exist

        """
        if (
            not hasattr(attributes, "alt_names_details")
            or not attributes.alt_names_details
        ):
            return None

        aliases = []
        for alt_name in attributes.alt_names_details:
            if hasattr(alt_name, "value") and alt_name.value:
                aliases.append(alt_name.value)

        return aliases if aliases else None

    @staticmethod
    def _extract_seen_dates(
        attributes: ThreatActorModel,
    ) -> tuple[datetime | None, datetime | None]:
        """Extract first_seen and last_seen dates from threat actor attributes.

        Args:
            attributes: The threat actor attributes

        Returns:
            tuple: (first_seen, last_seen) datetime objects or None if dates don't exist

        """
        first_seen = None
        if (
            hasattr(attributes, "first_seen_details")
            and attributes.first_seen_details
            and len(attributes.first_seen_details) > 0
            and hasattr(attributes.first_seen_details[0], "value")
            and attributes.first_seen_details[0].value
        ):
            try:
                first_seen_str = attributes.first_seen_details[0].value
                first_seen = datetime.strptime(
                    first_seen_str, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                first_seen = None

        last_seen = None
        if (
            hasattr(attributes, "last_seen_details")
            and attributes.last_seen_details
            and len(attributes.last_seen_details) > 0
            and hasattr(attributes.last_seen_details[0], "value")
            and attributes.last_seen_details[0].value
        ):
            try:
                last_seen_str = attributes.last_seen_details[0].value
                last_seen = datetime.strptime(
                    last_seen_str, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                last_seen = None

        return first_seen, last_seen

    def _extract_motivations(
        self, attributes: ThreatActorModel
    ) -> tuple[str | None, list[str] | None]:
        """Extract primary and secondary motivations from threat actor attributes.

        Args:
            attributes: The threat actor attributes

        Returns:
            tuple: (primary_motivation, secondary_motivations) or (None, None) if motivations don't exist

        """
        if not hasattr(attributes, "motivations") or not attributes.motivations:
            return None, None

        motivations = []
        for motivation in attributes.motivations:
            if hasattr(motivation, "value") and motivation.value:
                mapped_motivation = self._map_gti_motivation_to_stix_motivation(
                    motivation.value
                )
                if mapped_motivation:
                    motivations.append(mapped_motivation)
                else:
                    motivations.append(AttackMotivationOV.UNPREDICTABLE)

        if not motivations:
            return None, None

        primary_motivation = motivations[0]
        secondary_motivations = motivations[1:] if len(motivations) > 1 else None

        return primary_motivation, secondary_motivations

    @staticmethod
    def _map_gti_motivation_to_stix_motivation(motivation: str) -> str | None:
        """Map GTI motivation to STIX attack motivation.

        Args:
            motivation: The GTI motivation

        Returns:
            str | None: Mapped STIX attack motivation or None if no mapping exists

        """
        return AttackMotivationOV(motivation)

    @staticmethod
    def _extract_labels(attributes: ThreatActorModel) -> list[str] | None:
        """Extract labels from threat actor tag details.

        Args:
            attributes: The threat actor attributes

        Returns:
            list[str] | None: Extracted labels from tag details or None if no tags exist

        """
        if not hasattr(attributes, "tags_details") or not attributes.tags_details:
            return None

        labels = []
        for tag_detail in attributes.tags_details:
            if hasattr(tag_detail, "value") and tag_detail.value:
                labels.append(tag_detail.value)

        return labels if labels else None

    def _build_external_references(self) -> list[ExternalReferenceModel]:
        """Build external references from Threat Actor attributes.

        Returns:
            list: External references

        """
        external_references = []
        if self.threat_actor.id and self.threat_actor.attributes:
            if (
                hasattr(self.threat_actor.attributes, "name")
                and self.threat_actor.attributes.name
            ):
                external_reference = ExternalReferenceModel(
                    source_name=f"[GTI] Threat Actor {self.threat_actor.attributes.name}",
                    description="Google Threat Intelligence Threat Actor Link",
                    url=f"https://www.virustotal.com/gui/collection/{self.threat_actor.id}",
                )
            external_references.append(external_reference)
        return external_references
