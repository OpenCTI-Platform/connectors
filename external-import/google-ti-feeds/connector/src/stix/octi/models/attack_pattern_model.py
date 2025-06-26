"""The module contains the OctiAttackPatternModel class, which represents an OpenCTI Attack Pattern."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.sdos.attack_pattern_model import AttackPatternModel


class OctiAttackPatternModel:
    """Model for creating OpenCTI Attack Pattern objects."""

    @staticmethod
    def create(
        name: str,
        mitre_id: str,
        organization_id: str,
        marking_ids: list[str],
        description: Optional[str] = None,
        aliases: Optional[List[str]] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        kill_chain_phases: Optional[List[KillChainPhaseModel]] = None,
        labels: Optional[List[str]] = None,
        external_references: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> AttackPatternModel:
        """Create an Attack Pattern model.

        Args:
            name: The name of the attack pattern
            mitre_id: MITRE ATT&CK ID for the attack pattern
            organization_id: The ID of the organization that created this attack pattern
            marking_ids: List of marking definition IDs to apply to the attack pattern
            description: Description of the attack pattern
            aliases: Alternative names for the attack pattern
            first_seen: First time the attack pattern was observed
            last_seen: Last time the attack pattern was observed
            kill_chain_phases: Kill chain phases associated with the attack pattern
            labels: Labels to apply to the attack pattern
            external_references: External references related to the attack pattern
            **kwargs: Additional arguments to pass to AttackPatternModel

        Returns:
            AttackPatternModel: The created attack pattern model

        """
        custom_properties = {"x_mitre_id": mitre_id}

        data = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "custom_properties": custom_properties,
            "created": kwargs.pop("created", datetime.now()),
            "modified": kwargs.pop("modified", datetime.now()),
            "name": name,
            "description": description,
            "aliases": aliases,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "kill_chain_phases": kill_chain_phases,
            "labels": labels,
            "external_references": external_references,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            **kwargs,
        }

        return AttackPatternModel(**data)
