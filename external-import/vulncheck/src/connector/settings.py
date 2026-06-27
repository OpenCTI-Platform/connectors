"""Connector configuration models built on ``connectors-sdk`` (pydantic-settings).

Replaces the hand-rolled ``config_variables.ConfigConnector`` / ``pycti.get_config_variable``
approach. Configuration is loaded with the same precedence as before
(ENV var -> config.yml/.env -> default) and is fully typed and testable.

Environment variable namespaces:
    OPENCTI_*     -> opencti
    CONNECTOR_*   -> connector
    VULNCHECK_*   -> vulncheck

The legacy ``CONNECTOR_VULNCHECK_*`` names are still accepted via deprecated
aliases (see ``ConnectorConfig``) and migrated to the ``vulncheck`` namespace
with a deprecation warning.
"""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl


class VulnCheckConfig(BaseConfigModel):
    """VulnCheck-specific configuration (env prefix: ``VULNCHECK_``)."""

    api_key: str = Field(
        description="The API key used to authenticate against the VulnCheck API.",
    )
    api_base_url: HttpUrl = Field(
        default=HttpUrl("https://api.vulncheck.com/v3"),
        description="The base URL of the VulnCheck API.",
    )
    data_sources: ListFromString = Field(
        default=["vulncheck-kev", "nist-nvd2"],
        description="Comma-separated list of VulnCheck data sources to ingest.",
    )
    # --- NVD2 incremental-ingestion controls (nist-nvd2 / vulncheck-nvd2) ---
    nvd2_pull_history: bool = Field(
        default=False,
        description=(
            "First run only: when true, pull the full NVD2 history (no date "
            "filter). When false, the first run is bounded by nvd2_max_date_range."
        ),
    )
    nvd2_max_date_range: int = Field(
        default=120,
        description=(
            "First run only: how many days back (last-modified) to pull when not "
            "pulling full history."
        ),
    )
    nvd2_last_mod_start_date: str | None = Field(
        default=None,
        description="Optional YYYY-MM-DD override for a manual NVD2 backfill (start).",
    )
    nvd2_last_mod_end_date: str | None = Field(
        default=None,
        description="Optional YYYY-MM-DD override for a manual NVD2 backfill (end).",
    )


class ConnectorConfig(BaseExternalImportConnectorConfig):
    """Base connector config with VulnCheck defaults plus legacy env aliases.

    The ``vulncheck_*`` fields below exist only to migrate the deprecated
    ``CONNECTOR_VULNCHECK_*`` environment variables (which pydantic-settings parses
    into the ``connector`` namespace) over to the new ``vulncheck`` namespace.
    """

    name: str = Field(default="VulnCheck", description="The name of the connector.")
    duration_period: timedelta = Field(
        default=timedelta(hours=1),
        description="The period of time to await between two runs of the connector.",
    )

    # --- Deprecated CONNECTOR_VULNCHECK_* aliases -> VULNCHECK_* (vulncheck namespace) ---
    vulncheck_api_key: str | None = DeprecatedField(
        deprecated="Use VULNCHECK_API_KEY instead of CONNECTOR_VULNCHECK_API_KEY.",
        new_namespace="vulncheck",
        new_namespaced_var="api_key",
    )
    vulncheck_api_base_url: str | None = DeprecatedField(
        deprecated="Use VULNCHECK_API_BASE_URL instead of CONNECTOR_VULNCHECK_API_BASE_URL.",
        new_namespace="vulncheck",
        new_namespaced_var="api_base_url",
    )
    vulncheck_data_sources: str | None = DeprecatedField(
        deprecated="Use VULNCHECK_DATA_SOURCES instead of CONNECTOR_VULNCHECK_DATA_SOURCES.",
        new_namespace="vulncheck",
        new_namespaced_var="data_sources",
    )
    vulncheck_nvd2_pull_history: str | None = DeprecatedField(
        deprecated="Use VULNCHECK_NVD2_PULL_HISTORY instead of CONNECTOR_VULNCHECK_NVD2_PULL_HISTORY.",
        new_namespace="vulncheck",
        new_namespaced_var="nvd2_pull_history",
    )
    vulncheck_nvd2_max_date_range: str | None = DeprecatedField(
        deprecated="Use VULNCHECK_NVD2_MAX_DATE_RANGE instead of CONNECTOR_VULNCHECK_NVD2_MAX_DATE_RANGE.",
        new_namespace="vulncheck",
        new_namespaced_var="nvd2_max_date_range",
    )
    vulncheck_nvd2_last_mod_start_date: str | None = DeprecatedField(
        deprecated="Use VULNCHECK_NVD2_LAST_MOD_START_DATE instead of CONNECTOR_VULNCHECK_NVD2_LAST_MOD_START_DATE.",
        new_namespace="vulncheck",
        new_namespaced_var="nvd2_last_mod_start_date",
    )
    vulncheck_nvd2_last_mod_end_date: str | None = DeprecatedField(
        deprecated="Use VULNCHECK_NVD2_LAST_MOD_END_DATE instead of CONNECTOR_VULNCHECK_NVD2_LAST_MOD_END_DATE.",
        new_namespace="vulncheck",
        new_namespaced_var="nvd2_last_mod_end_date",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Top-level settings: OpenCTI + connector + VulnCheck configuration."""

    connector: ConnectorConfig = Field(default_factory=ConnectorConfig)
    vulncheck: VulnCheckConfig = Field(default_factory=VulnCheckConfig)
