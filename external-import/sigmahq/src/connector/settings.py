from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="SigmaHQ",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector. (Default: 1 day)",
        default=timedelta(days=1),
    )
    scope: ListFromString = Field(
        description="The scope of the connector", default=["sigmahq"]
    )


class SigmaHQConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SigmaHQConnector`.
    """

    rule_package: Literal[
        "sigma_all_rules",
        "sigma_core++",
        "sigma_core+",
        "sigma_core",
        "sigma_emerging_threats_addon",
    ] = Field(
        description="Rule package to import",
        default="sigma_all_rules",
    )
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


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `SigmaHQConnector`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    sigmahq: SigmaHQConfig = Field(default_factory=SigmaHQConfig)
