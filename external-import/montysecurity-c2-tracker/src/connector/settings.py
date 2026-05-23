from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="MontysecurityC2TrackerConnector",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="359a9fed-89e7-4baa-a5a7-fb0ce3a923cb",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(weeks=1),
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'flashpoint'.",
        default=["montysecurity-c2-tracker"],
    )


class MontysecurityC2TrackerConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MontysecurityC2TrackerConnector`.
    """

    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="clear",
    )

    malware_list_url: HttpUrl = Field(
        description="The URL to the malware list page of the imported entities.",
        default=HttpUrl("https://github.com/montysecurity/C2-Tracker/tree/main/data"),
    )

    malware_ips_base_url: HttpUrl = Field(
        description="The base URL used to fetch malware ips.",
        default=HttpUrl(
            "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/"
        ),
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MontysecurityC2TrackerConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    montysecurity_c2_tracker: MontysecurityC2TrackerConfig = Field(
        default_factory=MontysecurityC2TrackerConfig
    )
