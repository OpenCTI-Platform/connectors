from datetime import datetime, timedelta, timezone

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="AssetnoteImportConnector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Assetnote"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class AssetnoteImportConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `AssetnoteImportConnector`.
    """

    api_base_url: HttpUrl = Field(description="API base URL.")
    api_key: SecretStr = Field(description="API key for authentication.")

    tlp_level: TLPLevel = Field(
        description="Default TLP level of the imported entities.",
        default=TLPLevel.CLEAR,
    )

    unresolved_status_name: str | None = Field(
        description="Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote UNRESOLVED exposures.",
        default=None,
    )
    triaged_status_name: str | None = Field(
        description="Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote TRIAGED exposures.",
        default=None,
    )
    resolved_status_name: str | None = Field(
        description="Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote RESOLVED exposures.",
        default=None,
    )
    ignored_status_name: str | None = Field(
        description="Name of the OpenCTI Case-Incident workflow status template mapped to Assetnote IGNORED exposures.",
        default=None,
    )
    first_run_retrieval_datetime: datetime = Field(
        description="ISO 8601 datetime indicating the earliest point in time from which assets and exposures should be retrieved from the Assetnote API. Used only on the connector's first run (i.e. before any state has been persisted). Defaults to the epoch (i.e. the full Assetnote catalogue) so existing deployments that never set this variable continue to start.",
        default=datetime(1970, 1, 1, tzinfo=timezone.utc),
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `AssetnoteImportConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    assetnote_import: AssetnoteImportConfig = Field(
        default_factory=AssetnoteImportConfig
    )
