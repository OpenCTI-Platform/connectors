from datetime import timedelta

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
        default="MITRE Fight Fraud (F3)",
    )
    scope: ListFromString = Field(
        description="The scope of the connector. Only these object types will be imported on OpenCTI.",
        default=[
            "attack-pattern",
            "identity",
            "marking-definition",
            "relationship",
            "x-mitre-matrix",
            "x-mitre-tactic",
            "x-mitre-collection",
        ],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class MitreFraudConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the MITRE Fraud connector.
    """

    remove_statement_marking: bool = Field(
        description="Remove statement marking definitions from the bundle.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MitreFraudConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    mitre_fraud: MitreFraudConfig = Field(default_factory=MitreFraudConfig)
