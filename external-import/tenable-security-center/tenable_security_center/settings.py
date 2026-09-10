# isort: skip_file
# isort is removing the type ignore untyped import comment conflicting with mypy
"""Define the Pydantic settings of the Tenable Security Center connector.

Those settings mirror the connector's historical configuration variables and are the
single source of truth used by the OpenCTI connector manager (manager-supported mode).

Classes:
    ExternalImportConnectorConfig: `connector` configuration section.
    TenableSecurityCenterConfig: `tsc` configuration section.
    ConnectorSettings: Aggregation of all the configuration sections.

"""

from datetime import timedelta
from typing import Literal

import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from pydantic import Field, SecretStr

_TLP_MARKINGS = {
    # "TLP:CLEAR" and "TLP:WHITE" map to the same marking definition
    "TLP:CLEAR": stix2.TLP_WHITE,
    "TLP:WHITE": stix2.TLP_WHITE,
    "TLP:GREEN": stix2.TLP_GREEN,
    "TLP:AMBER": stix2.TLP_AMBER,
    "TLP:RED": stix2.TLP_RED,
}


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Override `BaseExternalImportConnectorConfig` with this connector's own defaults."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="a9e6fb3a-6b33-4a1e-a526-54e9d001f184",
        min_length=1,
    )
    name: str = Field(
        description="The name of the connector.",
        default="Tenable Security Center",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the type of STIX objects it imports.",
        default=["vulnerability"],
        min_length=1,
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=12),
    )


class TenableSecurityCenterConfig(BaseConfigModel):
    """Define the configuration specific to the Tenable Security Center connector."""

    api_base_url: str = Field(
        description="Base URL of the Tenable Security Center API instance.",
    )
    api_access_key: SecretStr = Field(
        description="Access key used to authenticate against the Tenable Security Center API.",
    )
    api_secret_key: SecretStr = Field(
        description="Secret key used to authenticate against the Tenable Security Center API.",
    )
    api_timeout: int = Field(
        description="Timeout, in seconds, of the Tenable Security Center API requests.",
        default=30,
        ge=1,
    )
    api_backoff: int = Field(
        description="Backoff duration, in seconds, between two Tenable Security Center API retries.",
        default=5,
        ge=0,
    )
    api_retries: int = Field(
        description="Number of retries of the Tenable Security Center API requests.",
        default=3,
        ge=0,
    )
    export_since: DatetimeFromIsoString = Field(
        description=(
            "Datetime (ISO-8601) used as the starting point of the very first data retrieval. "
            "It is overwritten by the connector state after the first successful run."
        ),
    )
    severity_min_level: Literal["info", "low", "medium", "high", "critical"] = Field(
        description="Minimum severity level of the findings to import.",
        default="high",
    )
    process_systems_without_vulnerabilities: bool = Field(
        description="Whether to import the systems that have no vulnerability attached.",
        default=False,
    )
    marking_definition: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:RED",
    ] = Field(
        description="TLP marking definition applied to all the imported entities.",
        default="TLP:CLEAR",
    )
    number_threads: int = Field(
        description="Number of threads used to retrieve data from Tenable Security Center.",
        default=1,
        ge=1,
    )

    @property
    def tlp_marking(self) -> stix2.TLPMarking:
        """Get the STIX TLP marking definition matching `marking_definition`."""
        return _TLP_MARKINGS[self.marking_definition]


class ConnectorSettings(BaseConnectorSettings):
    """Override `BaseConnectorSettings` with this connector's configuration sections."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    tsc: TenableSecurityCenterConfig = Field(
        default_factory=TenableSecurityCenterConfig  # type: ignore[arg-type] # required fields have no default
    )
