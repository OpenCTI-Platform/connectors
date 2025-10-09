import os
from typing import Literal

from censys_enrichment.base_config import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentsConnectorConfig,
)
from connectors_sdk.core.pydantic import ListFromString
from pydantic import Field

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class _ConnectorConfig(BaseInternalEnrichmentsConnectorConfig):
    id: str = Field(
        default="censys-enrichment--674403d0-4723-40cd-b03c-42fb959d5469",
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        default="Censys Enrichment",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=[],
        description="The scope of the connector.",
    )
    log_level: Literal["debug", "info", "warning", "error"] = Field(
        default="error",
        description="Determines the verbosity of the logs.",
    )
    auto: bool = Field(
        default=True,
        description="Enables or disables automatic enrichment of observables for OpenCTI.",
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


class Config(BaseConnectorSettings):
    connector: _ConnectorConfig = Field(
        default_factory=_ConnectorConfig,
        description="Internal Enrichment Connector configurations.",
    )
    censys_enrichment: _CensysEnrichmentConfig = Field(
        default_factory=_CensysEnrichmentConfig,
        description="Censys Enrichment configurations.",
    )
