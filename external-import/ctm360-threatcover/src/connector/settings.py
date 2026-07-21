from datetime import timedelta
from typing import Literal, Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="CTM360 ThreatCover",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        default=[],
    )


class Ctm360ThreatcoverConfig(BaseConfigModel):
    """
    Configuration specific to the `Ctm360ThreatcoverConnector`.

    Modeled on the generic OpenCTI ``taxii2`` connector: the feed is consumed through
    TAXII 2.1 server discovery, with the same token / API-key / basic authentication
    options.
    """

    discovery_url: HttpUrl = Field(
        description="CTM360 ThreatCover TAXII discovery URL (e.g. https://<tenant>.ctm360.com/taxii2/).",
    )
    collection: str = Field(
        description="TAXII collection to poll (the ThreatCover 'Observables' collection id or title).",
    )
    v21: bool = Field(
        description="Use TAXII 2.1 (set to false for a TAXII 2.0 server).",
        default=True,
    )
    use_token: bool = Field(
        description="Authenticate with a token (Authorization header). Default for CTM360 ThreatCover.",
        default=True,
    )
    token: Optional[SecretStr] = Field(
        description="CTM360 ThreatCover API token (used when use_token is true).",
        default=None,
    )
    use_apikey: bool = Field(
        description="Authenticate with a custom API-key header instead of a token.",
        default=False,
    )
    apikey_key: Optional[str] = Field(
        description="Header name to use when use_apikey is true.",
        default=None,
    )
    apikey_value: Optional[SecretStr] = Field(
        description="Header value to use when use_apikey is true.",
        default=None,
    )
    username: Optional[str] = Field(
        description="Username for HTTP basic authentication (when neither token nor apikey is used).",
        default=None,
    )
    password: Optional[SecretStr] = Field(
        description="Password for HTTP basic authentication.",
        default=None,
    )
    cert_path: Optional[str] = Field(
        description="Optional path to a client certificate for mutual TLS.",
        default=None,
    )
    verify_ssl: bool = Field(
        description="Whether to verify the TAXII server TLS certificate.",
        default=True,
    )
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP marking applied to the imported entities.",
        default="amber",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and
    `Ctm360ThreatcoverConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    ctm360_threatcover: Ctm360ThreatcoverConfig = Field(
        default_factory=Ctm360ThreatcoverConfig
    )
