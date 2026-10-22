from datetime import timedelta
from typing import Literal, Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="8dd7bd2f-e08d-486e-8cce-74889327f7f6",
    )
    name: str = Field(
        description="The name of the connector.",
        default="DDoSIA",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["withaname"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class WithanameConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `WithanameConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="API base URL.",
        default=HttpUrl("https://witha.name"),
    )
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="green",
    )
    import_start_timestamp: Optional[float] = Field(
        description="Optional timestamp from which to retrieve targets on the first run (0 for all history, null for only the latest).",
        default=None,
    )
    create_notes: bool = Field(
        description="Whether to create STIX Note objects for each domain with raw targets data.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `WithanameConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    withaname: WithanameConfig = Field(default_factory=WithanameConfig)
