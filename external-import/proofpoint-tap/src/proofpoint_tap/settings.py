from datetime import timedelta
from typing import Literal, Self

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator
from pydantic.json_schema import SkipJsonSchema


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A unique UUIDv4 identifier for this connector instance.",
        default="c2635ebc-67f7-43a4-9caa-0d10cdc95b85",
        min_length=1,
    )
    name: str = Field(
        description="The name of the connector.",
        default="ProofPointTAP",
    )
    scope: ListFromString = Field(
        description="The type of data the connector is importing, i.e. the type of Stix Objects (for information only).",
        default=["report"],
        min_length=1,
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=12),
    )


class ProofpointTapConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `ProofpointTapConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="Proofpoint API base URL.",
        default=HttpUrl("https://tap-api-v2.proofpoint.com"),
    )
    api_principal_key: SecretStr = Field(
        description="Proofpoint API principal key for authentication."
    )
    api_secret_key: SecretStr = Field(
        description="Proofpoint API secret key for authentication."
    )
    api_timeout: timedelta = Field(
        description="Timeout duration for API requests.",
        default=timedelta(seconds=30),
    )
    api_backoff: timedelta = Field(
        description="Backoff duration for API requests.",
        default=timedelta(seconds=5),
    )
    api_retries: int = Field(
        description="Number of retries for API requests.",
        default=3,
    )
    marking_definition: Literal[
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="amber+strict",
    )
    export_campaigns: bool = Field(
        description="Whether to export Proofpoint campaigns and import them into OpenCTI.",
        default=True,
    )
    export_events: bool = Field(
        description="Whether to export Proofpoint events and import them into OpenCTI.",
        default=False,
    )
    events_type: Literal[
        "all",
        "issues",
        "messages_blocked",
        "messages_delivered",
        "clicks_blocked",
        "clicks_permitted",
    ] = Field(
        description="The type of events to export (`PROOFPOINT_TAP_EXPORT_EVENTS` must be enabled).",
        default="issues",
    )

    # Handle deprecation of mispelled env vars
    # These fields will are excluded from the connector's config JSON schema to reduce noise
    api_principal: SkipJsonSchema[SecretStr] = DeprecatedField(
        new_namespaced_var="api_principal_key",
        removal_date="2026-08-27",
    )
    api_secret: SkipJsonSchema[SecretStr] = DeprecatedField(
        new_namespaced_var="api_secret_key",
        removal_date="2026-08-27",
    )

    @model_validator(mode="after")
    def _validate_export_flags(self) -> Self:
        """Validate that at least one of the export flags is enabled."""
        if not self.export_campaigns and not self.export_events:
            raise ValueError(
                "At least one of `PROOFPOINT_TAP_EXPORT_CAMPAIGNS` or `PROOFPOINT_TAP_EXPORT_EVENTS` must be set to `True`"
            )

        return self


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `ProofpointTapConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    proofpoint_tap: ProofpointTapConfig = Field(default_factory=ProofpointTapConfig)

    # Handle deprecation of `tap` namespace in favor of `proofpoint_tap` in config.yml
    # and `TAP_` prefix in favor of `PROOFPOINT_TAP_` prefix in environment variables.
    # It maintains backward compatibility while migrating to the new namespace.
    tap: ProofpointTapConfig = DeprecatedField(
        new_namespace="proofpoint_tap",
        removal_date="2026-08-27",
    )
