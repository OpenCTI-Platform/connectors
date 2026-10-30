"""Connector configuration models.

Configuration values are read from environment variables or `config.yml`
(see `config.yml.sample` and the README's "Configuration variables" section).
"""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl

# Lower bound of the CVSS "Critical" severity rating (v3.x and v4.0).
CRITICAL_SCORE = 9.0


class ConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration, common to every `EXTERNAL_IMPORT` connector."""

    id: str = Field(
        description="The unique identifier of the connector.",
        default="cd55d2d1-cdd9-4880-9e76-afa1f4c1d0cb",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ENISA EUVD",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the entity types it imports.",
        default=["vulnerability"],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, "
        "as an ISO 8601 duration (e.g. `P1D` for one day).",
        default=timedelta(days=1),
    )


class EnisaEuvdConfig(BaseConfigModel):
    """Configuration specific to the ENISA EUVD API (env prefix: `ENISA_EUVD_`)."""

    api_base_url: HttpUrl = Field(
        default=HttpUrl("https://euvdservices.enisa.europa.eu/api"),
        description="The base URL of the ENISA EUVD API.",
    )
    import_start_date: DatetimeFromIsoString = Field(
        default="P90D",
        description="First run only: oldest last-update date to import. Can be "
        "absolute (e.g. '2026-01-01T00:00:00Z') or relative (e.g. 'P90D' for "
        "90 days ago). Subsequent runs resume from the connector's persisted state.",
    )
    tlp_level: TLPLevel = Field(
        default=TLPLevel.CLEAR,
        description="Default TLP (Traffic Light Protocol) marking applied to "
        "every object this connector creates in OpenCTI.",
    )
    min_score: float | None = Field(
        default=None,
        ge=0,
        le=10,
        description="Only import vulnerabilities with a base score greater than "
        "or equal to this value (0 to 10). Vulnerabilities without a score are "
        "then excluded. Leave empty to import every vulnerability.",
    )
    exploited_only: bool = Field(
        default=False,
        description="Only import vulnerabilities with a known exploitation.",
    )
    critical_only: bool = Field(
        default=False,
        description="Only import vulnerabilities of critical severity "
        f"(base score of {CRITICAL_SCORE} or more). Combined with `min_score`, "
        "the higher of the two thresholds applies.",
    )
    ingest_software: bool = Field(
        default=False,
        description="Enable/disable the import of Software observables and their "
        "'has' relationship to each vulnerability. Off by default: a single "
        "vulnerability can reference many affected products, which increases "
        "the volume of objects created per run.",
    )

    @property
    def effective_min_score(self) -> float | None:
        """The score threshold to apply, combining `min_score` and `critical_only`."""
        if self.critical_only:
            return max(self.min_score or 0.0, CRITICAL_SCORE)
        return self.min_score


class ConnectorSettings(BaseConnectorSettings):
    """Aggregates all configuration objects the connector needs."""

    connector: ConnectorConfig = Field(default_factory=ConnectorConfig)
    enisa_euvd: EnisaEuvdConfig = Field(default_factory=EnisaEuvdConfig)
