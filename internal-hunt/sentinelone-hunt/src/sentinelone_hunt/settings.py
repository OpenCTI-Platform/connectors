"""Configuration of the SentinelOne hunt connector."""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class SentinelOneHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the SentinelOne hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="f837aa17-8381-4b3d-b6c2-df10c6d05a64",
    )
    name: str = Field(
        description="The name of the connector.",
        default="SentinelOne Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["sentinelone"],
    )
    security_platform_name: str | None = Field(
        description="Name of the OpenCTI Security Platform the hunts are executed against.",
        default="SentinelOne Singularity",
    )
    security_platform_type: Literal["SIEM", "EDR", "XDR", "SOAR", "NDR", "ISPM"] = (
        Field(
            description="Type of the OpenCTI Security Platform the hunts are executed against "
            "('XDR' when the Singularity Data Lake also holds third-party data you hunt).",
            default="EDR",
        )
    )
    max_concurrent_runs: int | None = Field(
        description="Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time "
        "(a run holds one query on the platform at a time). The platform budget is the minimum of its own "
        "setting and this value. Defaults to 3: SentinelOne throttles query launches and does not document "
        "the concurrent query budget of an account.",
        default=3,
        ge=1,
    )


class SentinelOneHuntConfig(BaseConfigModel):
    """SentinelOne Singularity Data Lake settings of the hunt connector."""

    api_url: HttpUrl = Field(
        description="URL of the SentinelOne management console of your tenant, e.g. "
        "'https://your-tenant.sentinelone.net'.",
    )
    api_token: SecretStr = Field(
        description="API token of a SentinelOne service user with a read-only role that can search "
        "events (e.g. Viewer) on the accounts or sites to hunt.",
    )
    account_ids: ListFromString = Field(
        description="Account IDs the hunts search, comma-separated. Empty searches every account "
        "the token can reach.",
        default=[],
    )
    edr_only: bool = Field(
        description="Restrict translated Sigma rules and indicator lookups to the SentinelOne EDR "
        "telemetry (dataSource.name='SentinelOne' dataSource.category='security') and check their "
        "field names against the EDR schema, so that a misspelled field fails the run instead of "
        "matching nothing. Set to false to also search the third-party data of the Singularity "
        "Data Lake.",
        default=True,
    )
    verify_ssl: bool = Field(
        description="Whether to verify the TLS certificate of the console.",
        default=True,
    )
    sigma_pipeline: str = Field(
        description="pySigma pipeline translating Sigma rules: 'sentinelone_pq' (the field mapping "
        "of the SentinelOne EDR telemetry) or 'none' (rules already written with SentinelOne "
        "field names).",
        default="sentinelone_pq",
    )
    poll_interval: float = Field(
        description="Seconds between two status checks of a query. SentinelOne drops a query "
        "that is not polled for 30 seconds.",
        default=1.0,
        gt=0,
        le=10,
    )

    @field_validator("api_token")
    @classmethod
    def _token_not_blank(cls, value: SecretStr) -> SecretStr:
        """Reject a blank API token."""
        if not value.get_secret_value().strip():
            raise ValueError("must not be blank.")
        return value


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the SentinelOne hunt connector."""

    connector: SentinelOneHuntConnectorConfig = Field(
        default_factory=SentinelOneHuntConnectorConfig
    )
    sentinelone_hunt: SentinelOneHuntConfig = Field(
        default_factory=SentinelOneHuntConfig
    )
