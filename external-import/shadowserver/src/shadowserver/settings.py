from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr, SkipValidation


def _run_every_to_duration_period(run_every: str) -> str:
    run_every = run_every.upper()
    if run_every[-1] in ["H", "M", "S"]:
        return f"PT{int(float(run_every[:-1]))}{run_every[-1]}"
    return f"P{int(float(run_every[:-1]))}{run_every[-1]}"


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
    run_every: SkipValidation[str] = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' instead.",
        new_namespaced_var="duration_period",
        new_value_factory=_run_every_to_duration_period,
    )


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
    report_types: ListFromString = Field(
        description="List of report types to retrieve. If empty, all report types will be retrieved.",
        default=[],
    )
    initial_lookback: int = Field(
        description="Number of days to look back for reports during the first run.",
        default=30,
    )
    lookback: int = Field(
        description="Number of days to look back for reports during subsequent runs.",
        default=3,
    )
    max_threads: int = Field(
        description="Maximum number of threads used to download and transform reports in parallel.",
        default=8,
        ge=1,
        le=32,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `ShadowserverConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    shadowserver: ShadowserverConfig = Field(default_factory=ShadowserverConfig)
