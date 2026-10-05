from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    DeploymentConfig,
    HitsConfig,
    ListFromString,
    SecurityPlatformConfig,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="GoogleSecOpsSIEM",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="9257254e-b4ef-4592-ab11-6d37d4aa321f",
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        default=["google-secops-siem"],
    )
    live_stream_id: str = Field(
        description="ID of the live stream to connect to (created in the OpenCTI UI).",
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
    auth_uri: HttpUrl = Field(
        description="OAuth2 authorization URI.",
        default=HttpUrl("https://accounts.google.com/o/oauth2/auth"),
    )
    token_uri: HttpUrl = Field(
        description="OAuth2 token URI.",
        default=HttpUrl("https://oauth2.googleapis.com/token"),
    )
    auth_provider_cert: HttpUrl = Field(
        description="Auth provider x509 certificate URL.",
        default=HttpUrl("https://www.googleapis.com/oauth2/v1/certs"),
    )
    client_cert_url: HttpUrl = Field(
        description="Client x509 certificate URL.",
    )

    @field_validator("private_key", mode="before")
    @classmethod
    def normalize_private_key(cls, value: SecretStr) -> SecretStr:
        raw_value = (
            value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        )

        normalized_value = raw_value.replace("\\r\\n", "\n").replace("\\n", "\n")
        return SecretStr(normalized_value)


class SecOpsSecurityPlatformConfig(SecurityPlatformConfig):
    """
    Define the Security Platform entity representing Google SecOps SIEM in OpenCTI (deployment write-back).
    """

    name: str = Field(
        default="Google SecOps SIEM",
        min_length=2,
        description="Name of the Security Platform entity representing Google SecOps SIEM in OpenCTI (created if it does not exist).",
    )
    type: str | None = Field(
        default="SIEM",
        description="Type of the Security Platform entity (open vocabulary security_platform_type_ov).",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig`, `SecOpsSIEMConfig`
    and the deployment write-back namespaces (`deployment`, `hits`, `security_platform`).
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    secops_siem: SecOpsSIEMConfig = Field(default_factory=SecOpsSIEMConfig)
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
    hits: HitsConfig = Field(default_factory=HitsConfig)
    security_platform: SecOpsSecurityPlatformConfig = Field(
        default_factory=SecOpsSecurityPlatformConfig
    )
