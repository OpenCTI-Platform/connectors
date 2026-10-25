from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Configuration for connectors of type EXTERNAL_IMPORT."""

    id: str = Field(
        description="The UUID or unique identifier of the connector.",
        default="dectrax-external-import-connector",
    )
    name: str = Field(
        description="The name of the connector.",
        default="DECTRAX Autonomous Deception",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["dectrax", "ipv4-addr", "indicator"],
    )


class DectraxConfig(BaseConfigModel):
    """Configuration specific to the DECTRAX Connector."""

    api_url: HttpUrl = Field(
        description="The base URL of the DECTRAX API instance.",
        default="http://localhost:8000",
    )
    api_key: SecretStr = Field(
        description="The DECTRAX API key for authentication.",
        default="",
    )
    edl_endpoint: str = Field(
        description="Path to the external dynamic list endpoint.",
        default="/api/v1/edl/firewall.txt",
    )
    telemetry_endpoint: str = Field(
        description="Path to the threat telemetry endpoint.",
        default="/api/v1/telemetry/threats",
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = Field(
        description="Default TLP marking level for ingested indicators.",
        default="clear",
    )
    create_indicators: bool = Field(
        description="Whether to generate STIX 2.1 Indicators.",
        default=True,
    )
    create_observables: bool = Field(
        description="Whether to generate STIX 2.1 Observables.",
        default=True,
    )
    sync_modbus: bool = Field(
        description="Synchronize industrial Modbus SCADA deception events.",
        default=True,
    )
    sync_ldap: bool = Field(
        description="Synchronize Active Directory / LDAP deception events.",
        default=True,
    )
    sync_rdp: bool = Field(
        description="Synchronize Remote Desktop Protocol (RDP) deception events.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Complete connector settings combining OpenCTI, connector, and DECTRAX configs."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    dectrax: DectraxConfig = Field(default_factory=DectraxConfig)
