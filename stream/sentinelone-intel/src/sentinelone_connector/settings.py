from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
)
from connectors_sdk.core.pydantic import ListFromString
from pydantic import (
    AliasChoices,
    Field,
    HttpUrl,
    SecretStr,
    field_validator,
    model_validator,
)


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="SentinelOne Intel Stream Connector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'sentinelone'.",
        default="sentinelone",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
        default="live",  # listen the global stream (not filtered)
    )


class SentinelOneIntelSettings(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SentinelOne Intel Stream Connector`.
    """

    api_url: HttpUrl = Field(
        description="The base URL of your SentinelOne management console",
        validation_alias=AliasChoices(
            "api_url",
            "url",  # accept old key
        ),
        serialization_alias="api_url",
    )

    api_key: SecretStr = Field(
        description="The API key for your SentinelOne management console",
    )

    @field_validator("api_key", mode="after")
    @classmethod
    def normalize_api_key(cls, v: SecretStr) -> SecretStr:
        """
        Normalize the API key by stripping the "APIToken " prefix if present.
        Users commonly input "APIToken eyj..." or just "eyj.." as such we strip
        "APIToken " for consistency.
        """
        secret_value = v.get_secret_value()
        if secret_value.startswith("APIToken "):
            v = SecretStr(secret_value[9:])
        return v

    # SentinelOne API Filtering Parameters:

    account_id: int | None = Field(
        description="The Account ID for your SentinelOne management console",
        default=None,
    )
    site_id: int | None = Field(
        description="The Site ID for your SentinelOne management console",
        default=None,
    )
    group_id: int | None = Field(
        description="The Group ID for your SentinelOne management console",
        default=None,
    )

    @field_validator("account_id", "site_id", "group_id", mode="before")
    @classmethod
    def normalize_ids(cls, v: int | str | None) -> int | None:
        """
        Normalize ids by converting empty strings to None.
        Accepts int, None, or empty string.
        """
        if v == "" or v is None:
            return None

        if isinstance(v, str):
            # Try to convert non-empty string to int
            return int(v)

        return v

    @model_validator(mode="after")
    def validate_ids(self) -> "SentinelOneIntelSettings":
        """
        Validate that at least one ID is provided and that account_id and site_id
        are not both set simultaneously.
        """
        # At least one of the three IDs are required to interface with the API
        if self.account_id is None and self.group_id is None and self.site_id is None:
            raise ValueError(
                "Missing required ID configuration: need at least one of account_id, group_id, or site_id"
            )

        # API requests cannot use both an account and site ID
        if self.account_id is not None and self.site_id is not None:
            raise ValueError(
                "Invalid configuration: cannot use both account_id and site_id simultaneously"
            )

        return self


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `TemplateConfig`.
    """

    connector: Annotated[
        StreamConnectorConfig, Field(default_factory=StreamConnectorConfig)
    ]
    sentinelone_intel: Annotated[
        SentinelOneIntelSettings,
        Field(
            default_factory=SentinelOneIntelSettings,
            validation_alias=AliasChoices(
                "sentinelone_intel",
                "sentinelone-intel",  # accept old key
            ),
            serialization_alias="sentinelone_intel",  # always output new key
        ),
    ]
