from typing import Annotated, Literal

from models.configs import ConfigBaseSettings
from pydantic import Field, HttpUrl, PlainSerializer

TLPToLower = Annotated[
    Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]


class _ConfigLoaderCISAICS(ConfigBaseSettings):
    """Interface for loading dedicated configuration."""

    feed_url: HttpUrlToString = Field(
        default="https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
        description="The RSS feed CISA publishes for ICS Advisories (ICSA/ICSMA).",
    )
    csaf_org_raw_base: HttpUrlToString = Field(
        default="https://raw.githubusercontent.com/cisagov/CSAF/develop/",
        description=(
            "Base URL used to resolve each advisory's structured CSAF JSON document "
            "(the RSS item description links to a GitHub blob view of this file; the "
            "connector rewrites it to the raw content URL)."
        ),
    )
    max_advisories_per_run: int = Field(
        default=100,
        description="Safety ceiling on how many advisories are processed in a single run.",
    )
    tlp: TLPToLower = Field(
        default="TLP:CLEAR",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI. Possible values: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED.",
    )
