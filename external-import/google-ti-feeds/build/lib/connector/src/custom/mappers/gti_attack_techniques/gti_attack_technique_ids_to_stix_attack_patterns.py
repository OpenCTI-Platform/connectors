"""Converts a list of GTI attack technique IDs to minimal STIX attack pattern objects.

This is a simplified version of the attack technique mapper that only uses technique IDs
to create minimal STIX attack patterns. This approach is used for quota optimization
when we want to avoid making detailed API calls for attack technique data.

Example usage:
    mapper = GTIAttackTechniqueIDsToSTIXAttackPatterns(
        attack_technique_ids=GTIAttackTechniqueIDData.from_id_list(["T1055", "T1078"]),
        organization=organization_obj,
        tlp_marking=tlp_marking_obj
    )
    attack_patterns = mapper.to_stix()
"""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.models.gti.gti_attack_technique_id_model import (
    GTIAttackTechniqueIDData,
)
from connector.src.stix.octi.models.attack_pattern_model import OctiAttackPatternModel
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from stix2.v21 import AttackPattern  # type: ignore


class GTIAttackTechniqueIDsToSTIXAttackPatterns(BaseMapper):
    """Converts a list of GTI attack technique IDs to minimal STIX attack pattern objects."""

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
        attack_technique_ids: GTIAttackTechniqueIDData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the GTIAttackTechniqueIDsToSTIXAttackPatterns object.

        Args:
            attack_technique_ids (GTIAttackTechniqueIDData): The GTI attack technique IDs to convert.
            organization (OrganizationAuthor): The organization author object.
            tlp_marking (TLPMarking): The TLP marking definition.

        """
        self.attack_technique_ids = attack_technique_ids
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> list[AttackPattern]:
        """Convert the GTI attack technique IDs to minimal STIX attack pattern objects.

        Returns:
            list[AttackPattern]: list of minimal STIX attack pattern objects.

        """
        if not self.attack_technique_ids or not self.attack_technique_ids.ids:
            return []

        attack_patterns = []
        current_time = datetime.now(tz=timezone.utc)

        for technique_id in self.attack_technique_ids.ids:
            if not technique_id:
                continue

            name = technique_id

            external_references = self._create_minimal_external_references(technique_id)

            attack_pattern_model = OctiAttackPatternModel.create(
                name=name,
                mitre_id=technique_id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                description=f"Attack technique {technique_id} (minimal representation)",
                aliases=None,
                first_seen=None,
                last_seen=None,
                kill_chain_phases=None,
                external_references=external_references,
                created=current_time,
                modified=current_time,
            )

            attack_patterns.append(attack_pattern_model)

        return attack_patterns

    def _create_minimal_external_references(
        self, technique_id: str
    ) -> list[dict[str, str]] | None:
        """Create minimal external references with only MITRE reference.

        Args:
            technique_id: The attack technique ID

        Returns:
            list[dict[str, str]] | None: Minimal external references with MITRE reference

        """
        if not technique_id:
            return None

        mitre_reference = {
            "source_name": "mitre-attack",
            "external_id": technique_id,
            "url": f"https://attack.mitre.org/techniques/{technique_id}/",
        }

        return [mitre_reference]
