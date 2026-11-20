from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="d601481f-81dc-4146-995b-15af01187c02",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["CTM360-CyberBlindSpot"],
    )
    name: str = Field(default="CTM360-CyberBlindSpot")
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=24),
        gt=timedelta(0),
    )


class CTM360CbsConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default="https://cbs.ctm360.com",
        description="CyberBlindSpot API base URL.",
    )
    api_key: SecretStr = Field(description="API key for CyberBlindSpot authentication.")
    import_interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(seconds=int(x)),
        description="Interval in seconds between imports.",
    )
    import_incidents: bool = Field(
        default=True,
        description="Enable importing incidents.",
    )
    import_malware_logs: bool = Field(
        default=True,
        description="Enable importing malware logs.",
    )
    import_breached_credentials: bool = Field(
        default=True,
        description="Enable importing breached credentials.",
    )
    import_card_leaks: bool = Field(
        default=True,
        description="Enable importing card leaks.",
    )
    import_domain_protection: bool = Field(
        default=True,
        description="Enable importing domain protection findings.",
    )
    status_poll_interval: int = Field(
        default=3600,
        gt=0,
        description="Interval in seconds between status polling cycles (default: 1h).",
    )
    enable_status_tracking: bool = Field(
        default=True,
        description="Enable background polling for incident status changes.",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    ctm360_cbs: CTM360CbsConfig = Field(default_factory=CTM360CbsConfig)
