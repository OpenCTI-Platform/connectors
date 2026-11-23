"""OpenCTI Vulmatch connector settings module."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class VulmatchConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the Vulmatch connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="bb033198-4bc8-4349-aed9-9c090a8a4a9b",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Vulmatch",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["vulmatch"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=1),
    )


class VulmatchConfig(BaseConfigModel):
    """Settings specific to the Vulmatch connector."""

    base_url: HttpUrl = Field(
        description="The Vulmatch API base URL.",
        default=HttpUrl("https://api.vulmatch.com/"),
    )
    api_key: SecretStr = Field(
        description="The Vulmatch API key used for authentication.",
    )
    sbom_only: bool = Field(
        description=(
            "Only ingest vulnerabilities related to products in your Vulmatch SBoM "
            "(`true`), or every vulnerability that matches the filters (`false`)."
        ),
        default=False,
    )
    cvss_v2_score_min: int = Field(
        description=(
            "The minimum CVSS v2 base score of the vulnerabilities to ingest, "
            "as an integer between 1 and 10. Set to -1 to disable this filter."
        ),
        default=-1,
    )
    cvss_v3_score_min: int = Field(
        description=(
            "The minimum CVSS v3 base score of the vulnerabilities to ingest, "
            "as an integer between 1 and 10. Set to -1 to disable this filter."
        ),
        default=-1,
    )
    cvss_v4_score_min: int = Field(
        description=(
            "The minimum CVSS v4 base score of the vulnerabilities to ingest, "
            "as an integer between 1 and 10. Set to -1 to disable this filter."
        ),
        default=-1,
    )
    epss_score_min: float = Field(
        description=(
            "The minimum EPSS score of the vulnerabilities to ingest, between 0 and 1. "
            "Set to -1 to disable this filter."
        ),
        default=-1,
    )
    days_to_backfill: int = Field(
        description=(
            "The number of days of historical data to import on the first run "
            "(capped at 365)."
        ),
        default=90,
    )
    interval_days: int | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda days: timedelta(days=int(days)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Vulmatch connector."""

    connector: VulmatchConnectorConfig = Field(default_factory=VulmatchConnectorConfig)
    vulmatch: VulmatchConfig = Field(default_factory=VulmatchConfig)
