"""KillChainPhase."""

import stix2
from connectors_sdk.models.base_object import BaseObject
from pydantic import Field


class KillChainPhase(BaseObject):
    """Represent a kill chain phase.

    Examples:
        >>> phase = KillChainPhase(chain_name="foo", phase_name="pre-attack")
        >>> entity = phase.to_stix2_object()
    """

    chain_name: str = Field(description="Name of the kill chain.")
    phase_name: str = Field(description="Name of the kill chain phase.")

    def to_stix2_object(self) -> stix2.v21.KillChainPhase:
        """Make stix object."""
        return stix2.KillChainPhase(
            kill_chain_name=self.chain_name,
            phase_name=self.phase_name,
        )
