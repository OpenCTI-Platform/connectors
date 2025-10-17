"""Offer techniques OpenCTI entities."""

from connectors_sdk.models._model_registry import MODEL_REGISTRY
from connectors_sdk.models.octi._common import BaseIdentifiedEntity
from connectors_sdk.models.octi.enums import Permission, Platform
from connectors_sdk.models.octi.settings.taxonomies import KillChainPhase
from pycti import AttackPattern as PyctiAttackPattern
from pydantic import Field
from stix2.v21 import AttackPattern as Stix2AttackPattern


@MODEL_REGISTRY.register
class AttackPattern(BaseIdentifiedEntity):
    """Represents an attack pattern entity on OpenCTI."""

    name: str = Field(
        description="Name of the attack pattern.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="Description of the attack pattern.",
    )
    labels: list[str] | None = Field(
        default=None,
        description="Labels of the attack pattern.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Vulnerability aliases",
    )
    kill_chain_phases: list[KillChainPhase] | None = Field(
        default=None,
        description="Kill chain phases associated with the attack pattern.",
    )
    mitre_id: str | None = Field(
        default=None,
        description="MITRE ATT&CK ID of the attack pattern.",
    )
    mitre_detection: str | None = Field(
        default=None,
        description="MITRE ATT&CK detection of the attack pattern.",
    )
    mitre_platforms: list[Platform] | None = Field(
        default=None,
        description="MITRE ATT&CK platforms of the attack pattern.",
    )
    mitre_required_permissions: list[Permission] | None = Field(
        default=None,
        description="MITRE ATT&CK required permissions of the attack pattern.",
    )

    def to_stix2_object(self) -> Stix2AttackPattern:
        """Make AttackPattern STIX2.1 object."""
        return Stix2AttackPattern(
            id=PyctiAttackPattern.generate_id(
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
