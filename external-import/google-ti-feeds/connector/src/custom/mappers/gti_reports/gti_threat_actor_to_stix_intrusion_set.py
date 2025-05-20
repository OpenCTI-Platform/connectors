"""Converts a GTI threat actor to a STIX intrusion set object."""

from datetime import datetime
from typing import List, Optional

from stix2.v21 import Identity, IntrusionSet, MarkingDefinition  # type: ignore

from connector.src.custom.models.gti_reports.gti_threat_actor_model import (
    GTIThreatActorData,
    ThreatActorModel,
)
from connector.src.stix.octi.models.intrusion_set_model import OctiIntrusionSetModel
from connector.src.stix.v21.models.ovs.attack_motivation_ov_enums import (
    AttackMotivationOV,
)


class GTIThreatActorToSTIXIntrusionSet:
    """Converts a GTI threat actor to a STIX intrusion set object."""

    def __init__(
        self,
        threat_actor: GTIThreatActorData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
    ) -> None:
        """Initialize the GTIThreatActorToSTIXIntrusionSet object.

        Args:
            threat_actor (GTIThreatActorData): The GTI threat actor data to convert.
            organization (Identity): The organization identity object.
            tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.threat_actor = threat_actor
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> IntrusionSet:
        """Convert the GTI threat actor to a STIX intrusion set object.

        Returns:
            IntrusionSet: The STIX intrusion set object.

        """
        attributes = self.threat_actor.attributes

        created = datetime.fromtimestamp(attributes.creation_date)
        modified = datetime.fromtimestamp(attributes.last_modification_date)

        aliases = self._extract_aliases(attributes)

        first_seen, last_seen = self._extract_seen_dates(attributes)

        labels = self._extract_labels(attributes)

        goals = self._extract_goals(attributes)

        primary_motivation, secondary_motivations = self._extract_motivations(attributes)

        resource_level = self._extract_resource_level(attributes)

        intrusion_set_model = OctiIntrusionSetModel.create(
            name=attributes.name,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            description=attributes.description,
            aliases=aliases,
            first_seen=first_seen,
            last_seen=last_seen,
            goals=goals,
            resource_level=resource_level,
            primary_motivation=primary_motivation,
            secondary_motivations=secondary_motivations,
            labels=labels,
            created=created,
            modified=modified,
        )

        return intrusion_set_model.to_stix2_object()

    def _extract_aliases(self, attributes: ThreatActorModel) -> Optional[List[str]]:
        """Extract aliases from threat actor attributes.

        Args:
            attributes: The threat actor attributes

        Returns:
            Optional[List[str]]: Extracted aliases or None if no aliases exist

        """
        if not hasattr(attributes, "alt_names_details") or not attributes.alt_names_details:
            return None

        aliases = []
        for alt_name in attributes.alt_names_details:
            if hasattr(alt_name, "value") and alt_name.value:
                aliases.append(alt_name.value)

        return aliases if aliases else None

    def _extract_seen_dates(
        self, attributes: ThreatActorModel
    ) -> tuple[Optional[datetime], Optional[datetime]]:
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
                first_seen = datetime.strptime(first_seen_str, "%Y-%m-%dT%H:%M:%SZ")
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
                last_seen = datetime.strptime(last_seen_str, "%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, TypeError):
                last_seen = None

        return first_seen, last_seen

    def _extract_labels(self, attributes: ThreatActorModel) -> Optional[List[str]]:
        """Extract labels from threat actor attributes.

        Args:
            attributes: The threat actor attributes

        Returns:
            Optional[List[str]]: Extracted labels or None if no labels exist

        """
        if not hasattr(attributes, "tags_details") or not attributes.tags_details:
            return None

        labels = []
        for tag in attributes.tags_details:
            if hasattr(tag, "value") and tag.value:
                labels.append(tag.value)

        return labels if labels else None

    def _extract_goals(self, attributes: ThreatActorModel) -> Optional[List[str]]:
        """Extract goals from threat actor attributes.

        Args:
            attributes: The threat actor attributes

        Returns:
            Optional[List[str]]: Extracted goals or None if no goals exist

        """
        if (
            not hasattr(attributes, "targeted_industries_tree")
            or not attributes.targeted_industries_tree
        ):
            return None

        goals = []
        for industry in attributes.targeted_industries_tree:
            if hasattr(industry, "industry_group") and industry.industry_group:
                goal = f"Target {industry.industry_group} industry"
                goals.append(goal)

        return goals if goals else None

    def _extract_motivations(
        self, attributes: ThreatActorModel
    ) -> tuple[Optional[str], Optional[List[str]]]:
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
                mapped_motivation = self._map_gti_motivation_to_stix_motivation(motivation.value)
                if mapped_motivation:
                    motivations.append(mapped_motivation)
                else:
                    motivations.append(AttackMotivationOV.UNPREDICTABLE)

        if not motivations:
            return None, None

        primary_motivation = motivations[0]
        secondary_motivations = motivations[1:] if len(motivations) > 1 else None

        return primary_motivation, secondary_motivations

    def _map_gti_motivation_to_stix_motivation(self, motivation: str) -> Optional[str]:
        """Map GTI motivation to STIX attack motivation.

        Args:
            motivation: The GTI motivation

        Returns:
            Optional[str]: Mapped STIX attack motivation or None if no mapping exists

        """
        motivation_map = {
            "Accidental": AttackMotivationOV.ACCIDENTAL,
            "Coercion": AttackMotivationOV.COERCION,
            "Control": AttackMotivationOV.DOMINANCE,
            "Dominance": AttackMotivationOV.DOMINANCE,
            "Ideology": AttackMotivationOV.IDEOLOGY,
            "Political": AttackMotivationOV.IDEOLOGY,
            "Religious": AttackMotivationOV.IDEOLOGY,
            "Notoriety": AttackMotivationOV.NOTORIETY,
            "Fame": AttackMotivationOV.NOTORIETY,
            "Corporate Espionage": AttackMotivationOV.ORGANIZATIONAL_GAIN,
            "Economic": AttackMotivationOV.ORGANIZATIONAL_GAIN,
            "Organizational Gain": AttackMotivationOV.ORGANIZATIONAL_GAIN,
            "Financial": AttackMotivationOV.PERSONAL_GAIN,
            "Personal Gain": AttackMotivationOV.PERSONAL_GAIN,
            "Entertainment": AttackMotivationOV.PERSONAL_SATISFACTION,
            "Personal Satisfaction": AttackMotivationOV.PERSONAL_SATISFACTION,
            "Revenge": AttackMotivationOV.REVENGE,
            "Unpredictable": AttackMotivationOV.UNPREDICTABLE,
        }

        return motivation_map.get(motivation)

    def _extract_resource_level(self, attributes: ThreatActorModel) -> Optional[str]:
        """Extract resource level from threat actor attributes.

        Args:
            attributes: The threat actor attributes

        Returns:
            Optional[str]: Extracted resource level or None if resource level doesn't exist

        """
        return None
