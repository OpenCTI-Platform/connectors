"""The module contains the GroupingModel class, which represents a STIX 2.1 Grouping object."""

from typing import List, Optional

from connector.src.stix.v21.models.ovs.grouping_context_ov_enums import (
    GroupingContextOV,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import Grouping, _STIXBase21  # type: ignore


class GroupingModel(BaseSDOModel):
    """Model representing a Grouping in STIX 2.1 format."""

    name: Optional[str] = Field(
        default=None, description="A name used to identify the Grouping."
    )
    description: Optional[str] = Field(
        default=None,
        description="A description that provides more details and context about the Grouping, potentially including its purpose and key characteristics.",
    )
    context: GroupingContextOV = Field(
        ...,
        description="Short descriptor of the context shared by the content in this Grouping. SHOULD come from the grouping-context-ov vocabulary.",
    )
    object_refs: List[str] = Field(
        ...,
        description="List of STIX Object identifiers referred to by this Grouping.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Grouping(**self.model_dump(exclude_none=True))
