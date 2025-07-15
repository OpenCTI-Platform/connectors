"""Converts a GTI attack technique to a STIX attack pattern object."""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from connector.src.custom.models.gti_reports.gti_attack_technique_model import (
    AttackTechniqueModel,
    GTIAttackTechniqueData,
)
from connector.src.stix.octi.models.attack_pattern_model import OctiAttackPatternModel
from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import AttackPattern, Identity, MarkingDefinition  # type: ignore


class GTIAttackTechniqueToSTIXAttackPattern(BaseMapper):
    """Converts a GTI attack technique to a STIX attack pattern object."""

    def __init__(
        self,
        attack_technique: GTIAttackTechniqueData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
    ) -> None:
        """Initialize the GTIAttackTechniqueToSTIXAttackPattern object.

        Args:
            attack_technique (GTIAttackTechniqueData): The GTI attack technique data to convert.
            organization (Identity): The organization identity object.
            tlp_marking (MarkingDefinition): The TLP marking definition.

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
    def _extract_aliases(attributes: AttackTechniqueModel) -> Optional[List[str]]:
        """Extract aliases from attack technique attributes.

        Args:
            attributes: The attack technique attributes

        Returns:
            Optional[List[str]]: Extracted aliases or None if no aliases exist

        """
        if not attributes:
            return None
        return None

    @staticmethod
    def _extract_kill_chain_phases(
        attributes: AttackTechniqueModel,
    ) -> Optional[List[KillChainPhaseModel]]:
        """Extract kill chain phases from attack technique attributes.

        Args:
            attributes: The attack technique attributes

        Returns:
            Optional[List[KillChainPhaseModel]]: Extracted kill chain phases or None if no phases exist

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
    ) -> Optional[List[Dict[str, str]]]:
        """Create external references from attack technique attributes.

        Args:
            attributes: The attack technique attributes

        Returns:
            Optional[List[Dict[str, str]]]: Created external references or None if no references exist

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
