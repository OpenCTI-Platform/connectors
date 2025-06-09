"""The module contains the KillChainPhaseModel class, which represents a kill chain phase in STIX 2.1 format."""

from pydantic import BaseModel, Field, model_validator


class KillChainPhaseModel(BaseModel):
    """Model representing a Kill Chain Phase in STIX 2.1 format."""

    kill_chain_name: str = Field(
        ...,
        description="The name of the kill chain. SHOULD be lowercase with hyphens.",
    )
    phase_name: str = Field(
        ...,
        description="The phase name within the kill chain. SHOULD be lowercase with hyphens.",
    )

    @model_validator(mode="after")
    def validate_formatting(self) -> "KillChainPhaseModel":
        """Ensure that kill_chain_name and phase_name are lowercase and use hyphens."""
        for field in ["kill_chain_name", "phase_name"]:
            val = getattr(self, field)
            if not val.islower() or " " in val or "_" in val:
                raise ValueError(
                    f"{field} must be lowercase and use hyphens instead of spaces or underscores: got '{val}'"
                )
        return self
