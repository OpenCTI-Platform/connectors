from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="DomainToolsFeedsConnector",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class DomainToolsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DomainToolsFeedsConnector`.
    """

    api_base_url: HttpUrl = Field(description="API base URL.")
    api_key: str = Field(description="API key for authentication.")
    feed_type: Literal["domainhotlist", "domainrisk", "nod", "nad", "noh", "domaindiscovery"] = Field(description="Name of the feed.")
    session_id: str = Field(description="A unique identifier for the session, used for resuming data retrieval from the last point.")
    domain: str | None = Field(description="Filter for an exact domain or a domain substring by prefixing or suffixing your string with *.", default=None)
    top: int | None = Field(description="Limits the number of results in the response payload. Primarily intended for testing.", default=None)
    tlp_level: Literal["clear","white","green","amber","amber+strict","red",] = Field(
        description="Default TLP level of the imported entities.",
        default="clear",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `TemplateConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    domaintools: DomainToolsConfig = Field(default_factory=DomainToolsConfig)
