from datetime import timedelta
from typing import Literal, Optional

from connectors_sdk import ListFromString
from pydantic import (
    Field,
    SecretStr,
)
from src.models.configs import ConfigBaseSettings


class _ConfigGoogleDTM(ConfigBaseSettings):
    """Interface for loading dedicated configuration."""

    # ConfigLoader Google DTM
    api_key: SecretStr = Field(
        description="Google DTM API Key",
    )
    tlp: Literal["red", "amber+strict", "amber", "green", "clear"] = Field(
        default="amber+strict",
        description="Default Traffic Light Protocol (TLP) marking for imported data.",
    )
    import_start_date: timedelta = Field(
        default="P10D",
        description="ISO 8601 duration string specifying how far back to import alerts (e.g., P1D for 1 day, P7D for 7 days)",
    )
    alert_type: Optional[ListFromString] = Field(
        default=[],
        description=(
            "Comma-separated list of alert types to ingest. Leave blank to retrieve alerts of all types."
            "Supported values: 'Compromised Credentials', 'Document', 'Domain Discovery', 'Email', 'Forum Post', 'Message', 'Paste', 'Shop Listing', 'Tweet', 'Web Content'"
        ),
    )
    alert_severity: Optional[ListFromString] = Field(
        default=[],
        description=(
            "Comma-separated list of alert severities to ingest. Leave blank to retrieve alerts of all severities."
            "Supported values: 'high', 'medium', 'low'"
        ),
    )
