from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="The UUID of the connector.",
        default="c384ed87-1b09-439c-9a45-c2b5942e4c5c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Spur Enrichment",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["IPv4-Addr", "IPv6-Addr"],
    )


class SpurConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the Spur enrichment connector.
    """

    api_base_url: HttpUrl = Field(
        description="Spur Context API base URL.",
        default="https://api.spur.us",
    )
    api_key: SecretStr = Field(description="Spur API token (Context API access).")
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="TLP marking applied to the objects created by the connector.",
            default="amber",
        )
    )
    default_score: int = Field(
        description=(
            "Base OpenCTI score of an IP that Spur flags with offensive risks "
            "(AD_FRAUD, CALLBACK_PROXY, LOGIN_BRUTEFORCE, WEB_SCRAPING). The final score "
            "is `default_score + 5 x number of offensive risks`, capped at 100. "
            "An IP without offensive risk keeps its current score."
        ),
        default=70,
        ge=0,
        le=100,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `SpurConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    spur: SpurConfig = Field(default_factory=SpurConfig)
