from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr


class EsetConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration for the ESET connector.

    Provides a default for the SDK's ``duration_period`` field, which drives the
    sleep between two runs of the connector's own loop.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="d7e41182-96c6-4b56-8d7e-38d06399d010",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ESET Cyber Threat Intelligence",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["eset"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class EsetConfig(BaseConfigModel):
    """Config fields specific to the ESET connector.

    Mirrors the connector's existing configuration variables one-to-one.
    """

    api_url: str = Field(
        description="Hostname of the ESET Threat Intelligence TAXII service.",
        default="eti.eset.com",
    )
    username: str = Field(description="ESET Threat Intelligence username.")
    password: SecretStr = Field(description="ESET Threat Intelligence password.")
    collections: ListFromString | None = Field(
        description=(
            "Comma-separated list of ESET TAXII collections to import. "
            "When unset (null), no collection is imported and only the APT reports are."
        ),
        default=None,
    )
    import_apt_reports: bool = Field(
        description="Whether to import ESET APT reports.",
        default=True,
    )
    import_start_date: DatetimeFromIsoString = Field(
        description=(
            "Start date (ISO 8601) from which data is imported on the first run. "
            "Either absolute (e.g. '2022-04-01') or relative (e.g. 'P30D' for 30 days ago)."
        ),
        default="P30D",
    )
    create_observables: bool = Field(
        description="Whether to create observables from imported indicators.",
        default=False,
    )
    interval: int | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda minutes: timedelta(minutes=int(minutes)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the ESET connector."""

    connector: EsetConnectorConfig = Field(default_factory=EsetConnectorConfig)
    eset: EsetConfig = Field(default_factory=EsetConfig)
