from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class _ConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    id: str = Field(
        default="censys-enrichment--674403d0-4723-40cd-b03c-42fb959d5469",
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        default="Censys Enrichment",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=["IPv4-Addr", "IPv6-Addr", "X509-Certificate", "Domain-Name"],
        description="The scope of the connector.",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        default="error",
        description="The minimum level of logs to display.",
    )


class _CensysEnrichmentConfig(BaseConfigModel):
    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        default="TLP:AMBER",
        description="The maximum TLP level allowed for enrichment.",
    )

    organisation_id: SecretStr = Field(
        description="Censys organisation ID.",
    )
    token: SecretStr = Field(
        description="Censys API token.",
    )
    nvd_api_key: SecretStr | None = Field(
        default=None,
        description=(
            "Optional NVD API key.  Without a key requests are limited to "
            "5 per 30 seconds; with a key the limit rises to 50 per 30 seconds.  "
            "Register at https://nvd.nist.gov/developers/request-an-api-key."
        ),
    )
    nvd_enabled: bool = Field(
        default=True,
        description=(
            "Set to false to disable NVD CVE enrichment entirely.  Useful when "
            "another connector (e.g. OpenCTI's own CVE connector) already handles "
            "vulnerability data and you want to avoid duplication."
        ),
    )


class ConfigLoader(BaseConnectorSettings):
    connector: _ConnectorConfig = Field(  # type: ignore[assignment]
        default_factory=_ConnectorConfig,
        description="Internal Enrichment Connector configurations.",
    )
    censys_enrichment: _CensysEnrichmentConfig = Field(
        description="Censys Enrichment configurations.",
    )
