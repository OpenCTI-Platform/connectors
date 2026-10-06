from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field
from pydantic.json_schema import SkipJsonSchema


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
    # Override `BaseExternalImportConnectorConfig.duration_period` as the connector
    # still relies on its own scheduling loop driven by `run_every`.
    duration_period: SkipJsonSchema[None] = Field(
        description="Do not use. Not implemented in the connector yet, use `run_every` instead.",
        default=None,
    )
    run_every: str = Field(
        description=(
            "The period of time to await between two runs of the connector. "
            "Format: a number followed by a unit among 'd', 'h', 'm', 's' "
            "(e.g. '7d', '12h', '10m', '30s')."
        ),
        default="1h",
        pattern=r"^\d+[dhmsDHMS]$",
    )
    update_existing_data: bool = Field(
        description="Whether to update existing data in OpenCTI.",
        default=False,
    )


class CrtshConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CrtshConnector`.

    Mirrors the existing `CRTSH_*` variables.
    """

    domain: str = Field(
        description="Domain to search certificates for (e.g. 'google.com').",
    )
    labels: str = Field(
        description="Comma-separated list of labels to add to the imported objects (e.g. 'crtsh,osint').",
        default="crtsh,osint",
    )
    marking_refs: Literal["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"] = Field(
        description="TLP marking to apply to the imported objects.",
        default="TLP:WHITE",
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
