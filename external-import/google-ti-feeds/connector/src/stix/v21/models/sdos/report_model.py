"""The module defines a ReportModel class that represents a STIX 2.1 Report object."""

from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.ovs.report_type_ov_enums import ReportTypeOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.properties import (  # type: ignore[import-untyped]  # Missing library stubs
    ListProperty,
    ReferenceProperty,
)
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Report,
    _STIXBase21,
)


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
        data["id"] = ReportModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "name" in data:
            name = data.get("name", None)
            published = data.get("published", None)
            data["id"] = pycti.Report.generate_id(name=name, published=published)
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        Report._properties = OrderedDict(Report._properties)

        Report._properties["object_refs"] = ListProperty(
            ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version="2.1"),
            required=False,
        )
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = ReportModel._generate_id(data=data)
        data.pop("id")

        return Report(id=pycti_id, **data)
