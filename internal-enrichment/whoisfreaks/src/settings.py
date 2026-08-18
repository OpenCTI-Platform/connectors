from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add defaults
    for the WhoisFreaks connector.
    """

    name: str = Field(
        description="The name of the connector.",
        default="WhoisFreaks",
    )
    scope: str = Field(
        description="The scope of the connector (comma-separated observable types).",
        default="Domain-Name,IPv4-Addr,IPv6-Addr",
    )
    log_level: str = Field(
        description="The logging level for the connector.",
        default="error",
    )


class WhoisFreaksConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the
    WhoisFreaks connector.
    """

    api_key: SecretStr = Field(
        description="API key used to authenticate against the WhoisFreaks API.",
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="TLP marking applied to created STIX entities.",
            default="amber+strict",
        )
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig`
    and `WhoisFreaksConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig,
    )
    whoisfreaks: WhoisFreaksConfig = Field(
        default_factory=WhoisFreaksConfig,
    )
