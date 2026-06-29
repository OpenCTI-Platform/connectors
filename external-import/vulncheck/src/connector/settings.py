from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, SkipValidation


class VulnCheckConfig(BaseConfigModel):
    api_key: SecretStr = Field(
        description="API key for authenticating with the VulnCheck API.",
    )
    api_base_url: HttpUrl = Field(
        description="Base URL for the VulnCheck API.",
        default=HttpUrl("https://api.vulncheck.com/v3"),
    )
    data_sources: str = Field(
        description=(
            "Comma-separated list of data sources to ingest. "
            "Available: botnets, epss, exploits, initial-access, ipintel, "
            "nist-nvd2, ransomware, snort, suricata, threat-actors, "
            "vulncheck-kev, vulncheck-nvd2."
        ),
        default="vulncheck-kev,nist-nvd2",
    )


class ExternalImportConfig(BaseExternalImportConnectorConfig):
    name: str = Field(
        description="Display name for this connector instance in the OpenCTI platform.",
        default="VulnCheck Connector",
    )
    scope: ListFromString = Field(
        description="Entity types this connector will handle.",
        default=[
            "vulnerability",
            "malware",
            "threat-actor",
            "infrastructure",
            "location",
            "ip-addr",
            "indicator",
            "external-reference",
            "software",
            "report",
        ],
    )
    duration_period: timedelta = Field(
        description="Time interval between consecutive data imports.",
        default=timedelta(hours=1),
    )


class ConnectorSettings(BaseConnectorSettings):
    """Handles connector configuration loading and validation."""

    connector: ExternalImportConfig = Field(default_factory=ExternalImportConfig)
    connector_vulncheck: SkipValidation[VulnCheckConfig] = DeprecatedField(  # type: ignore[assignment]
        deprecated=(
            "Env vars prefixed by 'CONNECTOR_VULNCHECK' is deprecated. "
            "Use 'VULNCHECK' prefix instead. This field is kept for backward "
            "compatibility and will be removed in a future release."
        ),
        new_namespace="vulncheck",
    )
    vulncheck: VulnCheckConfig = Field(default_factory=VulnCheckConfig)
