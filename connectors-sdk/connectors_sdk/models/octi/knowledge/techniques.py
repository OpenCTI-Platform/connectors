"""Offer techniques OpenCTI entities."""

from typing import Optional


from connectors_sdk.models.octi._common import MODEL_REGISTRY, BaseIdentifiedEntity
from connectors_sdk.models.octi.settings.taxonomies import KillChainPhase
from connectors_sdk.models.octi.enums import Permission, Platform
from pycti import AttackPattern as pycti_AttackPattern
from pydantic import Field
from stix2.v21 import AttackPattern as stix2_AttackPattern


@MODEL_REGISTRY.register
class AttackPattern(BaseIdentifiedEntity):
    """Represents an attack pattern entity on OpenCTI."""

    name: str = Field(
        description="Name of the attack pattern.",
        min_length=1,
    )
    description: Optional[str] = Field(
        description="Description of the attack pattern.",
        default=None,
    )
    labels: Optional[list[str]] = Field(
        description="Labels of the attack pattern.",
        default=None,
    )
    aliases: Optional[list[str]] = Field(
        description="Vulnerability aliases",
        default=None,
    )
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(
        description="Kill chain phases associated with the attack pattern.",
        default=None,
    )
    mitre_id: Optional[str] = Field(
        description="MITRE ATT&CK ID of the attack pattern.",
        default=None,
    )
    mitre_detection: Optional[str] = Field(
        description="MITRE ATT&CK detection of the attack pattern.",
        default=None,
    )
    mitre_platforms: Optional[list[Platform]] = Field(
        description="MITRE ATT&CK platforms of the attack pattern.",
        default=None,
    )
    mitre_required_permissions: Optional[list[Permission]] = Field(
        description="MITRE ATT&CK required permissions of the attack pattern.",
        default=None,
    )

    def to_stix2_object(self) -> stix2_AttackPattern:
        """Make AttackPattern STIX2.1 object."""
        return stix2_AttackPattern(
            id=pycti_AttackPattern.generate_id(
                name=self.name,
                x_mitre_id=self.mitre_id,
            ),
            name=self.name,
            description=self.description,
            labels=self.labels,
            aliases=self.aliases,
            kill_chain_phases=[
                kill_chain_phase.to_stix2_object()
                for kill_chain_phase in self.kill_chain_phases or []
            ],
            created_by_ref=self.author.id if self.author else None,
            object_marking_refs=[marking.id for marking in self.markings or []],
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            allow_custom=True,
            x_mitre_id=self.mitre_id,
            x_mitre_detection=self.mitre_detection,
            x_mitre_platforms=self.mitre_platforms,
            x_mitre_permissions_required=self.mitre_required_permissions,
        )


# See https://docs.pydantic.dev/latest/errors/usage_errors/#class-not-fully-defined (consulted on 2025-06-10)
MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover  # Do not run coverage on doctest
    import doctest

    doctest.testmod()
