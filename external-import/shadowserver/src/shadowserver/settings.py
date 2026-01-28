import warnings
from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="c7a581e5-d83e-440c-b88e-80528809e798",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Shadowserver",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["stix2"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=1),
    )

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_run_every(cls, data: dict) -> dict:
        if run_every := data.pop("run_every", "").upper():
            warnings.warn(
                "Env var `CONNECTOR_RUN_EVERY` is deprecated. Use `CONNECTOR_DURATION_PERIOD` instead."
            )
            if data.get("duration_period"):
                warnings.warn(
                    "Both 'CONNECTOR_RUN_EVERY' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            elif run_every[-1] in ["H", "M", "S"]:
                data["duration_period"] = (
                    f"PT{int(float(run_every[:-1]))}{run_every[-1]}"
                )
            else:
                data["duration_period"] = (
                    f"P{int(float(run_every[:-1]))}{run_every[-1]}"
                )
        return data


class ShadowserverConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `ShadowserverConnector`.
    """

    api_key: SecretStr = Field(
        description="Shadowserver API key.",
    )
    api_secret: SecretStr = Field(
        description="Shadowserver API secret.",
    )
    marking: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="TLP marking: `TLP:CLEAR`, `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, `TLP:RED`.",
        default="TLP:WHITE",
    )
    create_incident: bool = Field(
        description="Create Case Incident from reports.",
        default=False,
    )
    incident_severity: str = Field(
        description="Default incident severity.",
        default="low",
    )
    incident_priority: str = Field(
        description="Default incident priority.",
        default="P4",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `ShadowserverConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    shadowserver: ShadowserverConfig = Field(default_factory=ShadowserverConfig)
