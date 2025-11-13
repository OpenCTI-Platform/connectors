"""Converts a GTI attack technique to a STIX attack pattern object."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.models.gti.gti_attack_technique_model import (
    AttackTechniqueModel,
    GTIAttackTechniqueData,
)
from connector.src.stix.octi.models.attack_pattern_model import OctiAttackPatternModel
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from stix2.v21 import AttackPattern  # type: ignore


class GTIAttackTechniqueToSTIXAttackPattern(BaseMapper):
    """Converts a GTI attack technique to a STIX attack pattern object."""

    @staticmethod
    def create_relationship(
        src_entity: Any, relation_type: str, target_entity: Any
    ) -> Any:
        """Create a relationship between an intrusion set and attack pattern.

        Args:
            src_entity: The source entity
            relation_type: The relationship type
            target_entity: The target entity

        Returns:
            OctiRelationshipModel: The relationship object

        """
        if not any(
            "AttackPattern" in str(type(entity).__name__)
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
        attack_technique: GTIAttackTechniqueData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the GTIAttackTechniqueToSTIXAttackPattern object.

        Args:
            attack_technique (GTIAttackTechniqueData): The GTI attack technique data to convert.
            organization (OrganizationAuthor): The organization author object.
            tlp_marking (TLPMarking): The TLP marking definition.

        """
        self.attack_technique = attack_technique
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> AttackPattern:
        """Convert the GTI attack technique to a STIX attack pattern object.

        Returns:
            AttackPattern: The STIX attack pattern object.

        """
        if not self.attack_technique or not self.attack_technique.attributes:
            raise ValueError("Attack technique attributes are missing")

        attributes = self.attack_technique.attributes

        created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        modified = datetime.fromtimestamp(
            attributes.last_modification_date, tz=timezone.utc
        )

        aliases = self._extract_aliases(attributes)
        kill_chain_phases = self._extract_kill_chain_phases(attributes)
        first_seen, last_seen = None, None
        external_references = self._create_external_references(attributes)

        attack_pattern_model = OctiAttackPatternModel.create(
            name=attributes.name,
            mitre_id=self.attack_technique.id,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            description=attributes.description,
            aliases=aliases,
            first_seen=first_seen,
            last_seen=last_seen,
            kill_chain_phases=kill_chain_phases,
            external_references=external_references,
            created=created,
            modified=modified,
        )

        return attack_pattern_model

    @staticmethod
    def _extract_aliases(attributes: AttackTechniqueModel) -> list[str] | None:
        """Extract aliases from attack technique attributes.

        Args:
            attributes: The attack technique attributes

        Returns:
            list[str] | None: Extracted aliases or None if no aliases exist

        """
        if not attributes:
            return None
        return None

    @staticmethod
    def _extract_kill_chain_phases(
        attributes: AttackTechniqueModel,
    ) -> list[KillChainPhaseModel] | None:
        """Extract kill chain phases from attack technique attributes.

        Args:
            attributes: The attack technique attributes

        Returns:
                list[KillChainPhaseModel] | None: Extracted kill chain phases or None if no phases exist

        """
        if not attributes:
            return None
        return None

    @staticmethod
    def _normalize_tactic_name(tactic_name: str) -> str:
        """Normalize tactic name to match MITRE ATT&CK format.

        Args:
            tactic_name: The tactic name to normalize

        Returns:
            str: Normalized tactic name

        """
        normalized = tactic_name.lower().replace(" ", "-")
        return normalized

    def _create_external_references(
        self, attributes: AttackTechniqueModel
    ) -> list[dict[str, str]] | None:
        """Create external references from attack technique attributes.

        Args:
            attributes: The attack technique attributes

        Returns:
                list[dict[str, str]] | None: Created external references or None if no references exist

        """
        if not attributes:
            return None
        external_references = []

        technique_id = self.attack_technique.id

        if technique_id:
            mitre_reference = {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id}/",
            }
            external_references.append(mitre_reference)

        if hasattr(attributes, "link") and attributes.link:
            link_reference = {
                "source_name": "mitre-attack",
                "url": attributes.link,
            }
            if not any(
                ref.get("url") == attributes.link for ref in external_references
            ):
                external_references.append(link_reference)

        if hasattr(attributes, "stix_id") and attributes.stix_id:
            stix_reference = {
                "source_name": "stix",
                "external_id": attributes.stix_id,
            }
            external_references.append(stix_reference)

        return external_references if external_references else None
