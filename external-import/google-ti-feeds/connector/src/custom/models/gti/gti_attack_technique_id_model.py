"""Simple model for GTI attack technique ID data.

This module defines a simple model for handling attack technique IDs
without requiring detailed API data, used for quota optimization.
"""

from typing import List

from pydantic import BaseModel, Field


class GTIAttackTechniqueIDData(BaseModel):
    """Simple model for GTI attack technique ID data.

    This model is used when we only have attack technique IDs
    and want to avoid fetching detailed data for quota optimization.
    """

    ids: List[str] = Field(
        description="List of attack technique IDs (e.g., ['T1055', 'T1078'])"
    )

    @classmethod
    def from_id_list(cls, ids: List[str]) -> "GTIAttackTechniqueIDData":
        """Create instance from a list of IDs.

        Args:
            ids: List of attack technique IDs

        Returns:
            GTIAttackTechniqueIDData instance

        """
        return cls(ids=ids)
