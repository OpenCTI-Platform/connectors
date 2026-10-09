"""Configuration settings for the CrowdStrike Incidents connector."""

import warnings
from datetime import timedelta
from enum import StrEnum

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr, field_validator

# Alert products the connector knows how to map. Other Alerts API products
# (epp, idp, xdr...) carry a different payload and are not supported yet.
SUPPORTED_PRODUCTS = ["ngsiem"]


class Severity(StrEnum):
    """CrowdStrike alert severity names, ordered from the lowest to the highest."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Position of the severity in the ordered scale."""
        return list(Severity).index(self)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration for CrowdStrike Incidents."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="53e6bf2e-48bb-4ce0-8d2d-537b3343576b",
    )
    name: str = Field(
        description="The name of the connector.",
        default="CrowdStrike Incidents",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["crowdstrike-incidents"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector (e.g. 'PT5M' for 5 minutes).",
        default=timedelta(minutes=5),
    )


class CrowdstrikeIncidentsConfig(BaseConfigModel):
    """CrowdStrike Falcon Alerts API and mapping configuration."""

    api_base_url: HttpUrl = Field(
        description=(
            "Base URL of the CrowdStrike API for the tenant's cloud region "
            "(e.g. 'https://api.us-2.crowdstrike.com', 'https://api.eu-1.crowdstrike.com')."
        ),
        default="https://api.crowdstrike.com",
    )
    client_id: str = Field(
        description="CrowdStrike API client ID. The API client needs the 'Alerts: Read' scope.",
    )
    client_secret: SecretStr = Field(
        description="CrowdStrike API client secret.",
    )
    import_start_date: timedelta = Field(
        description="How far back to look on the first import (e.g. 'P7D' for 7 days, 'P30D' for 30 days).",
        default=timedelta(days=7),
    )
    products: ListFromString = Field(
        description=(
            "Comma-separated list of CrowdStrike alert products to import. "
            "Only 'ngsiem' (Next-Gen SIEM) is supported for now; other values are ignored."
        ),
        default=["ngsiem"],
    )
    severity_min: Severity | None = Field(
        description=(
            "Minimum severity of the alerts to import: 'informational', 'low', 'medium', "
            "'high' or 'critical'. All alerts are imported when unset."
        ),
        default=None,
    )
    include_hidden: bool = Field(
        description="Whether to also import alerts hidden in the Falcon console.",
        default=False,
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking level applied to every created STIX object.",
        default=TLPLevel.AMBER_STRICT,
    )

    @field_validator("products", mode="after")
    @classmethod
    def _keep_supported_products(cls, products: list[str]) -> list[str]:
        """Normalise the products and drop the ones the connector cannot map."""
        normalised = list(
            dict.fromkeys(p.strip().lower() for p in products if p.strip())
        )
        unsupported = [p for p in normalised if p not in SUPPORTED_PRODUCTS]
        if unsupported:
            warnings.warn(
                f"Unsupported CrowdStrike products ignored: {', '.join(unsupported)}. "
                f"Supported products: {', '.join(SUPPORTED_PRODUCTS)}.",
                UserWarning,
                stacklevel=2,
            )
        supported = [p for p in normalised if p in SUPPORTED_PRODUCTS]
        if not supported:
            raise ValueError(
                f"No supported product configured. Supported products: {', '.join(SUPPORTED_PRODUCTS)}."
            )
        return supported


class ConnectorSettings(BaseConnectorSettings):
    """Root settings combining OpenCTI, connector and CrowdStrike Incidents configurations."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    crowdstrike_incidents: CrowdstrikeIncidentsConfig = Field(
        default_factory=CrowdstrikeIncidentsConfig
    )
