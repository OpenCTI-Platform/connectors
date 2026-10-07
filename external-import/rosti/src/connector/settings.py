"""Connector configuration models.

Values are read from environment variables (e.g. ``ROSTI_API_KEY``) or from
``config.yml`` (section ``rosti:``). Pydantic validates them at startup.
"""

from datetime import datetime, timedelta, timezone

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, SecretStr, field_validator
from rosti_client.models import IOC_TYPES


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration, common to every EXTERNAL_IMPORT connector."""

    id: str = Field(
        description="The unique identifier of the connector (a UUIDv4).",
        default="33ee3586-f57e-43c4-87a9-f1b387f8589c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Rösti",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the entity types it imports.",
        default=[
            "Report",
            "Indicator",
            "Stix-Cyber-Observable",
            "Attack-Pattern",
            "Intrusion-Set",
            "Malware",
            "Tool",
            "Campaign",
            "Course-Of-Action",
            "Vulnerability",
        ],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, "
        "as an ISO 8601 duration (e.g. `PT1H` for one hour).",
        default=timedelta(hours=1),
    )


class RostiConfig(BaseConfigModel):
    """Configuration specific to the Rösti connector."""

    # --- API connection ---
    api_key: SecretStr = Field(
        description="Rösti API key (get one at https://rosti.dev/api).",
    )
    api_base_url: str = Field(
        description="Base URL of the Rösti API v2.",
        default="https://api.rosti.dev/v2",
    )

    # --- What to import ---
    import_since: DatetimeFromIsoString = Field(
        description="Where to start on the first run. Either an absolute date "
        "(e.g. '2026-01-01T00:00:00Z') or a duration relative to now (e.g. 'P30D'). "
        "Later runs resume from the connector state.",
        default_factory=lambda: (datetime.now(timezone.utc) - timedelta(days=30)),
    )
    import_iocs: bool = Field(
        description="Import IOCs as indicators and observables.",
        default=True,
    )
    import_yara: bool = Field(
        description="Import YARA rules as indicators (pattern type `yara`).",
        default=True,
    )
    import_mitre: bool = Field(
        description="Link MITRE ATT&CK techniques, groups, software, campaigns "
        "and mitigations to reports.",
        default=True,
    )
    import_cve: bool = Field(
        description="Import CVEs referenced by reports as vulnerabilities.",
        default=True,
    )
    ioc_types: ListFromString = Field(
        description="Comma-separated list of Rösti IOC types to import. "
        "Empty means all supported types.",
        default=[],
    )
    ids_only: bool = Field(
        description="Only import IOCs flagged as suitable for detection (`ids: true`).",
        default=False,
    )
    max_risk_level: int = Field(
        description="Skip IOCs whose false-positive risk level is above this value "
        "(0 = nothing found ... 5 = very high). 5 imports everything.",
        default=5,
        ge=0,
        le=5,
    )
    default_score: int = Field(
        description="Score given to IOCs that have no false-positive risk information.",
        default=50,
        ge=0,
        le=100,
    )

    # --- Markings ---
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to every object this connector creates.",
        default=TLPLevel.CLEAR,
    )

    @field_validator("ioc_types")
    @classmethod
    def _check_ioc_types(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(IOC_TYPES))
        if unknown:
            raise ValueError(
                f"Unknown Rösti IOC type(s): {', '.join(unknown)}. "
                f"Valid types: {', '.join(IOC_TYPES)}"
            )
        return value


class ConnectorSettings(BaseConnectorSettings):
    """All configuration objects the connector needs."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    rosti: RostiConfig = Field(default_factory=RostiConfig)
