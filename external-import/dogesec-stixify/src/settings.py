"""OpenCTI Stixify connector settings module."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class StixifyConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the Stixify connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="773ede4d-ae39-4bbb-a656-f67951f2fcee",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Stixify",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["stixify"],
    )
    duration_period: timedelta = Field(
        description=(
            "The period of time to await between two runs of the connector "
            "(ISO-8601 duration, e.g. 'PT1H')."
        ),
        default=timedelta(hours=1),
    )


class StixifyConfig(BaseConfigModel):
    """Settings specific to the Stixify connector."""

    base_url: HttpUrl = Field(
        description="The URL of the Stixify API.",
        default=HttpUrl("https://api.stixify.com/"),
    )
    api_key: SecretStr = Field(
        description="The Stixify API key used for authentication.",
    )
    dossier_ids: ListFromString = Field(
        description=(
            "Comma-separated list of Stixify Dossier IDs. The Reports (and the "
            "objects extracted from them) in these Dossiers are imported into "
            "OpenCTI. The Dossiers must be visible to the team of the API key. "
            "At least one Dossier ID is needed: the connector stops at startup "
            "when none is set."
        ),
        default=[],
    )
    interval_hours: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda hours: timedelta(hours=int(hours)),
        description="Polling interval in hours.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Stixify connector."""

    connector: StixifyConnectorConfig = Field(default_factory=StixifyConnectorConfig)
    stixify: StixifyConfig = Field(default_factory=StixifyConfig)
