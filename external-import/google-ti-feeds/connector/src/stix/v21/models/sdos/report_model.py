"""The module defines a ReportModel class that represents a STIX 2.1 Report object."""

from datetime import datetime
from typing import List, Optional

from connector.src.stix.v21.models.ovs.report_type_ov_enums import ReportTypeOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import Report, _STIXBase21  # type: ignore


class ReportModel(BaseSDOModel):
    """Model representing a Report in STIX 2.1 format."""

    name: str = Field(..., description="A name used to identify the Report.")
    description: Optional[str] = Field(
        default=None,
        description="More details and context about the Report—its purpose and key characteristics.",
    )
    report_types: List[ReportTypeOV] = Field(
        ...,
        description="Open vocabulary defining the primary subject(s) of this report. SHOULD use report-type-ov.",
    )
    published: datetime = Field(
        ..., description="The official publication date of this Report."
    )
    object_refs: List[str] = Field(
        ...,
        description="List of STIX Object identifiers referenced in this Report.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Report(**self.model_dump(exclude_none=True))
