from typing import ClassVar, Literal, Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator, model_validator


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
    auth_method: Literal["service_account", "adc"] = Field(
        description=(
            "Authentication method: 'service_account' (JSON key fields below) or "
            "'adc' (Application Default Credentials / Workload Identity). "
            "The service account key fields are only required for 'service_account'."
        ),
        default="service_account",
    )
    private_key_id: Optional[str] = Field(
        description="Service account private key ID. Required when auth_method is 'service_account'.",
        default=None,
    )
    private_key: Optional[SecretStr] = Field(
        description="Service account private key (PEM format). Required when auth_method is 'service_account'.",
        default=None,
    )
    client_email: Optional[str] = Field(
        description="Service account client email. Required when auth_method is 'service_account'.",
        default=None,
    )
    client_id: Optional[str] = Field(
        description="Service account client ID. Required when auth_method is 'service_account'.",
        default=None,
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
    client_cert_url: Optional[HttpUrl] = Field(
        description="Client x509 certificate URL. Required when auth_method is 'service_account'.",
        default=None,
    )

    # In ADC mode the service account key fields are irrelevant; drop them before
    # typed validation so leftover placeholders (e.g. a non-URL client_cert_url)
    # cannot fail construction before google.auth.default() is ever reached.
    _SERVICE_ACCOUNT_FIELDS: ClassVar[tuple[str, ...]] = (
        "private_key",
        "private_key_id",
        "client_email",
        "client_id",
        "client_cert_url",
    )

    @model_validator(mode="before")
    @classmethod
    def _drop_service_account_fields_for_adc(cls, data: object) -> object:
        if isinstance(data, dict) and data.get("auth_method") == "adc":
            data = {
                key: value
                for key, value in data.items()
                if key not in cls._SERVICE_ACCOUNT_FIELDS
            }
        return data

    @field_validator("private_key", mode="before")
    @classmethod
    def normalize_private_key(cls, value: Optional[SecretStr]) -> Optional[SecretStr]:
        if value is None:
            return None

        raw_value = (
            value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        )

        normalized_value = raw_value.replace("\\r\\n", "\n").replace("\\n", "\n")
        return SecretStr(normalized_value)

    @model_validator(mode="after")
    def _require_service_account_fields(self) -> "SecOpsSIEMConfig":
        if self.auth_method == "service_account":
            missing = [
                name
                for name in self._SERVICE_ACCOUNT_FIELDS
                if getattr(self, name) is None
            ]
            if missing:
                raise ValueError(
                    "auth_method='service_account' requires: " + ", ".join(missing)
                )
        return self


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `SecOpsSIEMConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    secops_siem: SecOpsSIEMConfig = Field(default_factory=SecOpsSIEMConfig)
