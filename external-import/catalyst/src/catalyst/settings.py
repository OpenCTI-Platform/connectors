"""Pydantic settings for the CATALYST connector (manager-supported mode).

This module mirrors the connector's existing configuration variables as validated
Pydantic settings so the connector becomes manager-supported. The historical
attribute names consumed by the rest of the connector are still exposed by
``catalyst.config_loader.ConfigConnector``, which now reads its values from these
settings instead of parsing ``config.yml`` / environment variables by hand.
"""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class CatalystConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector section configuration (mirror of the existing ``CONNECTOR_*`` vars)."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="d2107025-9f07-40c0-ae3d-373e01643256",
    )
    name: str = Field(
        description="The name of the connector.",
        default="CATALYST",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["catalyst"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector "
        "(ISO-8601 duration format).",
        default=timedelta(minutes=60),  # PT60M
    )


class CatalystConfig(BaseConfigModel):
    """CATALYST section configuration (mirror of the existing ``CATALYST_*`` vars)."""

    base_url: str = Field(
        description="The base URL of the CATALYST API.",
        default="https://prod.blindspot.prodaft.com/api",
    )
    api_key: SecretStr | None = Field(
        description="The CATALYST API key. If not provided, the public endpoint is used.",
        default=None,
    )
    tlp_level: str = Field(
        description="Default TLP marking applied to the imported data.",
        default="white",
    )
    tlp_filter: str | None = Field(
        description="Comma-separated list of TLP levels to fetch "
        "(options: CLEAR, GREEN, AMBER, RED, ALL).",
        default="ALL",
    )
    category_filter: str | None = Field(
        description="Comma-separated list of categories to fetch "
        "(options: DISCOVERY, ATTRIBUTION, RESEARCH, FLASH_ALERT, ALL).",
        default="ALL",
    )
    sync_days_back: int = Field(
        description="Number of days to go back when no last run is present in the connector state.",
        default=730,
    )
    create_observables: bool = Field(
        description="Whether to create observables from the fetched data.",
        default=True,
    )
    create_indicators: bool = Field(
        description="Whether to create indicators from the fetched data.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings of the CATALYST connector."""

    connector: CatalystConnectorConfig = Field(
        default_factory=CatalystConnectorConfig,
    )
    catalyst: CatalystConfig = Field(
        default_factory=CatalystConfig,
    )
