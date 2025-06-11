"""Offers a set of taxonomies entities for the Octi connector."""

import stix2  # type: ignore[import-untyped]  # stix2 does not provide stubs
from connectors_sdk.models.octi._common import MODEL_REGISTRY, BaseEntity
from pydantic import Field


@MODEL_REGISTRY.register
class KillChainPhase(BaseEntity):
    """Represent a kill chain phase.

    Examples:
        >>> phase = KillChainPhase(chain_name="foo", phase_name="pre-attack")
        >>> entity = phase.to_stix2_object()
    """

    chain_name: str = Field(..., description="Name of the kill chain.")
    phase_name: str = Field(..., description="Name of the kill chain phase.")

    def to_stix2_object(self) -> stix2.v21.KillChainPhase:
        """Make stix object."""
        return stix2.KillChainPhase(
            kill_chain_name=self.chain_name,
            phase_name=self.phase_name,
        )


MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover # do not run coverage on doctests
    import doctest

    doctest.testmod()
