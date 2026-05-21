"""Infrastructure."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import InfrastructureType
from connectors_sdk.models.kill_chain_phase import KillChainPhase
from pycti import Infrastructure as PyctiInfrastructure
from pydantic import AwareDatetime, Field
from stix2.v21 import Infrastructure as Stix2Infrastructure


class Infrastructure(BaseIdentifiedEntity):
    """Define an Infrastructure on OpenCTI."""

    name: str = Field(
        description="A name used to identify this Infrastructure.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="A description that provides more details and context about the Infrastructure.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Alternative names used to identify this Infrastructure.",
    )
    infrastructure_types: list[InfrastructureType] | None = Field(
        default=None,
        description="A set of terms used to describe this Infrastructure.",
    )
    first_seen: AwareDatetime | None = Field(
        default=None,
        description="The time that this Infrastructure was first seen.",
    )
    last_seen: AwareDatetime | None = Field(
        default=None,
        description="The time that this Infrastructure was last seen.",
    )
    kill_chain_phases: list[KillChainPhase] | None = Field(
        default=None,
        description="Kill chain phases associated with this Infrastructure.",
    )

    def to_stix2_object(self) -> Stix2Infrastructure:
        """Make stix object."""
        return Stix2Infrastructure(
            id=PyctiInfrastructure.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            infrastructure_types=self.infrastructure_types,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            kill_chain_phases=[
                kill_chain_phase.to_stix2_object()
                for kill_chain_phase in self.kill_chain_phases or []
            ],
            **self._common_stix2_properties(),
        )
