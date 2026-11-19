"""Connector configuration models.

This module defines every configuration option the Darkmoon connector
accepts, in two groups:

    - ``ExternalImportConnectorConfig``: options common to every connector
      of type ``EXTERNAL_IMPORT`` (inherited from ``connectors-sdk``), with
      defaults specific to this connector.
    - ``DarkmoonConfig``: options specific to this connector (the on-disk
      path to the Darkmoon findings export, feature flags, TLP marking).

Configuration values are read from environment variables or ``config.yml``
(see ``config.yml.sample`` and the README's "Configuration variables"
section). Pydantic validates and coerces them automatically.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration, common to every ``EXTERNAL_IMPORT`` connector."""

    id: str = Field(
        description="The unique identifier of the connector.",
        default="21477b98-740b-4005-a20e-54bd47682090",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Darkmoon",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the type of entities it imports.",
        default=["Vulnerability", "Note", "Report", "Attack-Pattern"],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, "
        "as an ISO 8601 duration (e.g. `PT1H` for one hour).",
        default=timedelta(hours=1),
    )


class DarkmoonConfig(BaseConfigModel):
    """Configuration specific to the Darkmoon connector.

    The connector reads the JSON findings store that the Darkmoon OSS engine
    writes to its data directory during a campaign (the same files from which
    the OSS Markdown report is generated). It does NOT call any Darkmoon
    web dashboard or HTTP API.
    """

    # --- Source of the findings (on-disk JSON export) ---
    export_path: Path = Field(
        description="Absolute path, inside the connector container, to the Darkmoon OSS "
        "data directory. This is the host directory the Darkmoon stack mounts at "
        "`/root/.local/share/opencode` (named `darkmoon-settings` in the reference "
        "docker-compose). It must contain the `campaigns/`, `vulnerabilities/` "
        "subdirectories and, optionally, a `targets.json` file.",
        examples=["/opt/darkmoon-data"],
    )

    # --- Fetching filters ---
    import_since: DatetimeFromIsoString = Field(
        description="The start date (ISO 8601) for importing campaigns. "
        "Can be absolute (e.g. '2026-01-01T00:00:00Z') or relative "
        "(e.g. 'P30D' meaning '30 days ago'). Used as the initial checkpoint on "
        "the connector's first run; subsequent runs resume from the connector state.",
        default_factory=lambda: (datetime.now(timezone.utc) - timedelta(days=30)),
    )
    import_findings: bool = Field(
        description="Enable/disable the import of findings (vulnerabilities + evidence notes).",
        default=True,
    )
    import_attack_patterns: bool = Field(
        description="Create an Attack Pattern (and a relationship to the vulnerability) "
        "for each finding that carries a MITRE ATT&CK technique id.",
        default=True,
    )

    # --- Default / arbitrary attributes for ingested data ---
    tlp_level: TLPLevel = Field(
        description="Default TLP (Traffic Light Protocol) marking applied to every "
        "object this connector creates. Darkmoon findings describe your own "
        "infrastructure, so a restrictive marking is recommended.",
        default=TLPLevel.RED,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Aggregates all configuration objects the connector needs."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    darkmoon: DarkmoonConfig = Field(
        default_factory=DarkmoonConfig,
    )
