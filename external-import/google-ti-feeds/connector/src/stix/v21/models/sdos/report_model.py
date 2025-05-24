"""The module defines a ReportModel class that represents a STIX 2.1 Report object."""

from datetime import datetime
from typing import Any, Dict, List, Optional

import pycti  # type: ignore
from connector.src.stix.v21.models.ovs.report_type_ov_enums import ReportTypeOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
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

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "name" in data:
            name = data.get("name", None)
            published = data.get("published", None)
            data["id"] = pycti.Report.generate_id(name=name, published=published)
        return data

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Report(**self.model_dump(exclude_none=True))
