from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class EsetConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration for the ESET connector.

    Provides a default for the SDK's structural ``duration_period`` field. The
    connector keeps its own ``eset.interval`` scheduling loop, so this value is
    only used to satisfy the manager-supported contract.
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
    update_existing_data: bool = Field(
        description="Whether to update data already present in OpenCTI.",
        default=False,
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
    collections: ListFromString = Field(
        description="Comma-separated list of ESET TAXII collections to import.",
        default=["ei.misp", "ei.cc", "ei.urls"],
    )
    import_apt_reports: bool = Field(
        description="Whether to import ESET APT reports.",
        default=True,
    )
    import_start_date: str = Field(
        description="Date from which data is imported on the first run (e.g. 2022-04-01).",
        default="2022-04-01",
    )
    create_observables: bool = Field(
        description="Whether to create observables from imported indicators.",
        default=True,
    )
    interval: int = Field(
        description="Interval, in minutes, between two runs of the connector.",
        default=60,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the ESET connector."""

    connector: EsetConnectorConfig = Field(default_factory=EsetConnectorConfig)
    eset: EsetConfig = Field(default_factory=EsetConfig)
