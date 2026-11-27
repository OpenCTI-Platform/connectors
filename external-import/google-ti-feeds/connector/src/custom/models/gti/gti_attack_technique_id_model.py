"""Simple model for GTI attack technique ID data.

This module defines a simple model for handling attack technique IDs
and their names without requiring detailed API data, used for quota optimization.
"""

from pydantic import BaseModel, Field


class GTIAttackTechniqueIDData(BaseModel):
    """Simple model for GTI attack technique ID data.

    This model is used when we only have attack technique IDs (and their names)
    and want to avoid fetching detailed data for quota optimization.
    """

    ids: list[str] = Field(
        description="list of attack technique IDs (e.g., ['T1055', 'T1078'])"
    )
    names: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Mapping of attack technique ID to technique name "
            "(e.g., {'T1055': 'Process Injection'}). "
            "A technique without a name is not converted."
        ),
    )

    @classmethod
    def from_id_list(
        cls, ids: list[str], names: dict[str, str] | None = None
    ) -> "GTIAttackTechniqueIDData":
        """Create instance from a list of IDs.

        Args:
            ids: list of attack technique IDs
            names: optional mapping of attack technique ID to technique name

        Returns:
            GTIAttackTechniqueIDData instance

        """
        return cls(ids=ids, names=names or {})
