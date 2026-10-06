from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class EsetConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="a4df8389-6ba4-4e2c-b09e-f8014f0d0af1",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ESET ETI Report Enrichment Connector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["report"],
    )


class EsetConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `EsetConnector`.
    """

    api_key: SecretStr = Field(
        description="ESET Threat Intelligence API key.",
    )
    api_secret: SecretStr = Field(
        description="ESET Threat Intelligence API secret.",
    )
    api_host: HttpUrl = Field(
        description="ESET Threat Intelligence API base URL.",
        default=HttpUrl("https://eti.eset.com/"),
    )
    max_tlp: (
        Literal[
            "TLP:CLEAR",
            "TLP:WHITE",
            "TLP:GREEN",
            "TLP:AMBER",
            "TLP:AMBER+STRICT",
            "TLP:RED",
        ]
        | None
    ) = Field(
        description=(
            "Max TLP level of the reports to enrich. "
            "If not set, reports are enriched whatever their TLP."
        ),
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `EsetConnectorConfig` and `EsetConfig`.
    """

    connector: EsetConnectorConfig = Field(default_factory=EsetConnectorConfig)
    eset: EsetConfig = Field(default_factory=EsetConfig)
