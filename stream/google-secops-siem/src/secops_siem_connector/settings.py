from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="GoogleSecOpsSIEM",
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        default=["google-secops-siem"],
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
    )


class SecOpsSIEMConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SecOpsSIEMConnector`.
    """

    project_id: str = Field(
        description="Google Cloud project ID for the SecOps SIEM instance.",
    )
    project_instance: str = Field(
        description="Google SecOps SIEM project instance identifier.",
    )
    project_region: str = Field(
        description="Google SecOps SIEM project region (e.g. 'us', 'eu', 'apac').",
        default="us",
    )
    private_key_id: str = Field(
        description="Service account private key ID.",
    )
    private_key: SecretStr = Field(
        description="Service account private key (PEM format).",
    )
    client_email: str = Field(
        description="Service account client email.",
    )
    client_id: str = Field(
        description="Service account client ID.",
    )
    auth_uri: str = Field(
        description="OAuth2 authorization URI.",
        default="https://accounts.google.com/o/oauth2/auth",
    )
    token_uri: str = Field(
        description="OAuth2 token URI.",
        default="https://oauth2.googleapis.com/token",
    )
    auth_provider_cert: str = Field(
        description="Auth provider x509 certificate URL.",
        default="https://www.googleapis.com/oauth2/v1/certs",
    )
    client_cert_url: str = Field(
        description="Client x509 certificate URL.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `SecOpsSIEMConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    secops_siem: SecOpsSIEMConfig = Field(default_factory=SecOpsSIEMConfig)
