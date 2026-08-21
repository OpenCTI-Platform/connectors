from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="27a0802c-2a6d-4ecc-ac22-151e74d5cd18",
    )
    name: str = Field(
        description="The name of the connector.",
        default="TAXII POST",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["taxii"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )


class TaxiiConfig(BaseConfigModel):
    """Config fields specific to the TAXII POST connector (`TAXII_*` env vars)."""

    url: HttpUrl = Field(
        description="The URL of the TAXII server.",
    )
    ssl_verify: bool = Field(
        description="Whether to verify SSL certificates.",
        default=True,
    )
    api_root: str = Field(
        description="The TAXII API root path segment.",
        default="root",
    )
    collection_id: str = Field(
        description="The target TAXII collection ID.",
    )
    token: SecretStr | None = Field(
        description="Bearer token for authentication. Takes precedence over basic auth.",
        default=None,
    )
    login: str | None = Field(
        description="Username for basic auth.",
        default=None,
    )
    password: SecretStr | None = Field(
        description="Password for basic auth.",
        default=None,
    )
    version: str = Field(
        description="TAXII protocol version.",
        default="2.1",
    )
    stix_version: str = Field(
        description="STIX output version.",
        default="2.1",
    )
    delete_created_by_ref: bool = Field(
        description="Strip created_by_ref from objects before posting.",
        default=True,
    )
    delete_marking_definition: bool = Field(
        description="Strip object_marking_refs from objects before posting.",
        default=True,
    )

    @model_validator(mode="after")
    def _check_auth(self) -> "TaxiiConfig":
        if not self.token and not (self.login and self.password):
            raise ValueError(
                "Either `token` or both `login` and `password` must be set."
            )
        return self


class ConnectorSettings(BaseConnectorSettings):
    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    taxii: TaxiiConfig = Field(default_factory=TaxiiConfig)
