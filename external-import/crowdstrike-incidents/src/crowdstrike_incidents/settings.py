"""Configuration settings for the CrowdStrike Incidents connector."""

from datetime import timedelta
from enum import StrEnum
from typing import Annotated, Any

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import BeforeValidator, Field, HttpUrl, SecretStr


# Alert products the connector knows how to map. Other Alerts API products
# (epp, idp, xdr...) carry a different payload and are not supported yet.
# Typed as an enum so that the generated schema (and the XTM Composer form)
# only offers the supported values.
class Product(StrEnum):
    """CrowdStrike alert products supported by the connector."""

    NGSIEM = "ngsiem"


def _parse_products(value: Any) -> Any:
    """Accept a comma-separated string; normalise case, spaces and duplicates."""
    if isinstance(value, str):
        value = value.split(",")
    if isinstance(value, list):
        return list(
            dict.fromkeys(
                str(item).strip().lower() for item in value if str(item).strip()
            )
        )
    return value


SupportedProducts = Annotated[list[Product], BeforeValidator(_parse_products)]


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
    products: SupportedProducts = Field(
        description=(
            "Comma-separated list of CrowdStrike alert products to import. "
            "Only 'ngsiem' (Next-Gen SIEM) is supported for now."
        ),
        default=["ngsiem"],
        min_length=1,
    )
    severity_min: Severity | None = Field(
        description=(
            "Minimum severity of the alerts to import: 'informational', 'low', 'medium', "
            "'high' or 'critical'. All alerts are imported when unset."
        ),
        default=None,
    )
    include_hidden: bool = Field(
        description="Whether to also import the alerts hidden in the Falcon console (show_in_ui: false).",
        default=False,
    )
    enrich_from_events: bool = Field(
        description=(
            "Whether to enrich each Incident with the threat observables (executed file, "
            "hashes, execution context) of the alert's source event in Next-Gen SIEM. "
            "Requires the 'NGSIEM: Write' scope, needed to run LogScale searches."
        ),
        default=False,
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking level applied to every created STIX object.",
        default=TLPLevel.AMBER_STRICT,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Root settings combining OpenCTI, connector and CrowdStrike Incidents configurations."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    crowdstrike_incidents: CrowdstrikeIncidentsConfig = Field(
        default_factory=CrowdstrikeIncidentsConfig
    )
