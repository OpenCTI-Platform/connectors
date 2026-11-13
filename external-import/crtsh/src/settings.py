import re
from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field

RUN_EVERY_UNITS = {"d": "days", "h": "hours", "m": "minutes", "s": "seconds"}


def run_every_to_timedelta(run_every: str) -> timedelta:
    """Convert a legacy `CONNECTOR_RUN_EVERY` value (e.g. '7d', '12h', '10m', '30s')."""
    match = re.fullmatch(r"(\d+)([dhms])", str(run_every).strip().lower())
    if match is None:
        raise ValueError(
            f"Invalid CONNECTOR_RUN_EVERY value '{run_every}': it SHOULD be a number "
            "followed by a unit among 'd', 'h', 'm', 's' (e.g. '7d', '12h', '10m', '30s')."
        )
    value, unit = match.groups()
    return timedelta(**{RUN_EVERY_UNITS[unit]: int(value)})


class CrtshConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.

    Mirrors the existing `CONNECTOR_*` variables consumed by the crt.sh connector.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="342ecd95-7d1d-41d7-a2d7-595803bce18c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="crt.sh",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["crtsh"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )
    run_every: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' instead.",
        new_namespaced_var="duration_period",
        new_value_factory=run_every_to_timedelta,
    )


class CrtshConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CrtshConnector`.

    Mirrors the existing `CRTSH_*` variables.
    """

    domain: str = Field(
        description="Domain to search certificates for (e.g. 'google.com').",
    )
    labels: ListFromString = Field(
        description="Comma-separated list of labels to add to the imported objects (e.g. 'crtsh,osint').",
        default=["crtsh", "osint"],
    )
    marking_refs: Literal["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"] | None = (
        Field(
            description=(
                "TLP marking to apply to the imported objects. "
                "If not set, no marking is applied."
            ),
            default=None,
        )
    )
    is_expired: bool = Field(
        description="Whether to exclude expired certificates from the search.",
        default=False,
    )
    is_wildcard: bool = Field(
        description="Whether to apply a wildcard expression to the domain (search its subdomains).",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `CrtshConnectorConfig` and `CrtshConfig`.
    """

    connector: CrtshConnectorConfig = Field(default_factory=CrtshConnectorConfig)
    crtsh: CrtshConfig = Field(default_factory=CrtshConfig)
