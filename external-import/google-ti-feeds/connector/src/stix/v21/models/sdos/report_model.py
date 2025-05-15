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


def test_report_model() -> None:
    """Test function to demonstrate the usage of ReportModel."""
    from datetime import UTC, datetime
    from uuid import uuid4

    now = datetime.now(UTC)

    # === Minimal Report ===
    minimal = ReportModel(
        type="report",
        spec_version="2.1",
        id=f"report--{uuid4()}",
        created=now,
        modified=now,
        name="Observed Malicious Infrastructure - Q2",
        report_types=[ReportTypeOV.ATTACK_PATTERN],
        published=now,
        object_refs=[f"infrastructure--{uuid4()}"],
    )

    print("=== MINIMAL REPORT ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Report ===
    full = ReportModel(
        type="report",
        spec_version="2.1",
        id=f"report--{uuid4()}",
        created=now,
        modified=now,
        name="Operation Hydra Flow: Cross-Border Cyber Espionage",
        description="This report documents coordinated C2 infrastructure and malware deployment attributed to the Hydra intrusion set.",
        report_types=[
            ReportTypeOV.CAMPAIGN,
            ReportTypeOV.MALWARE,
            ReportTypeOV.INTRUSION_SET,
        ],
        published=now,
        object_refs=[
            f"campaign--{uuid4()}",
            f"malware--{uuid4()}",
            f"infrastructure--{uuid4()}",
            f"indicator--{uuid4()}",
            f"note--{uuid4()}",
            f"identity--{uuid4()}",
        ],
        labels=["strategic", "espionage", "report"],
        confidence=90,
        lang="en",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["description", "name"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "intel_level": "strategic",
            }
        },
    )

    print("\n=== FULL REPORT ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_report_model()
