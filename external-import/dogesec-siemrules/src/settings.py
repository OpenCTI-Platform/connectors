"""OpenCTI SIEM Rules connector settings module."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class SiemrulesConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the SIEM Rules connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="1e0cf3de-6f90-488e-9af1-be4fee322f48",
    )
    name: str = Field(
        description="The name of the connector.",
        default="SIEM Rules",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["siemrules"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class SiemrulesConfig(BaseConfigModel):
    """Settings specific to the SIEM Rules connector."""

    base_url: HttpUrl = Field(
        description="The base URL of the SIEM Rules API.",
        default=HttpUrl("https://api.siemrules.com/"),
    )
    api_key: SecretStr = Field(
        description="The API key used to authenticate to SIEM Rules Web.",
    )
    detection_packs: ListFromString = Field(
        description=(
            "A comma-separated list of SIEM Rules Detection Pack IDs to import. "
            "At least one is required: the connector stops when the list is empty."
        ),
        default=[],
    )
    interval_hours: int | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda hours: timedelta(hours=int(hours)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the SIEM Rules connector."""

    connector: SiemrulesConnectorConfig = Field(
        default_factory=SiemrulesConnectorConfig
    )
    siemrules: SiemrulesConfig = Field(default_factory=SiemrulesConfig)
