"""Connector configuration models.

Values are read from environment variables or ``config.yml`` and validated by
pydantic through ``connectors-sdk``'s ``BaseExternalImportConnectorSettings``.
"""

from datetime import timedelta, timezone

from connectors_sdk import (
    BaseConfigModel,
    BaseExternalImportConnectorConfig,
    BaseExternalImportConnectorSettings,
    ConfigurationInvalidError,
    DatetimeFromIsoString,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration, common to every ``EXTERNAL_IMPORT`` connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="d251fc99-1dfa-4f38-886c-8d72f3fff019",
    )
    name: str = Field(
        description="The name of the connector.",
        default="AbuseIPDB TAXII",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["abuseipdb-taxii"],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, "
        "as an ISO 8601 duration (e.g. `PT1H` for one hour).",
        default=timedelta(hours=1),
    )


class AbuseIPDBTaxiiConfig(BaseConfigModel):
    """Configuration specific to the AbuseIPDB TAXII feed."""

    url: HttpUrl = Field(
        description="Base URL of the AbuseIPDB TAXII 2.1 API root.",
        default=HttpUrl("https://taxii.abuseipdb.com/taxii2/abuseipdb-taxii2/"),
    )
    username: str = Field(
        description="AbuseIPDB account email, used as the HTTP Basic authentication username for the TAXII API.",
    )
    password: SecretStr = Field(
        description="An AbuseIPDB API key (not the account password), used as the HTTP Basic authentication password for the TAXII API.",
    )
    collection_id: str | None = Field(
        description="Collection ID of the AbuseIPDB TAXII feed to import, as shown on "
        "the account's My TAXII Feeds page. Only needed when the account has more "
        "than one feed.",
        default=None,
    )
    import_since: DatetimeFromIsoString = Field(
        description="Start of the import window on the connector's first run, "
        "as an ISO 8601 duration relative to now (e.g. 'P30D' for 30 days ago) "
        "or an absolute ISO 8601 datetime. Later runs resume from the connector "
        "state. Feeds whose position is kept by AbuseIPDB ignore it.",
        default="P30D",
    )
    page_size: int = Field(
        description="Number of STIX objects requested per TAXII page. "
        "This does not limit the total number of objects retrieved per run.",
        default=1000,
        ge=10,
        le=1000,
    )
    verify_ssl: bool = Field(
        description="Whether to verify the TAXII server's TLS certificate.",
        default=True,
    )
    request_timeout_seconds: float = Field(
        description="Timeout, in seconds, applied to each TAXII HTTP request.",
        default=60.0,
        gt=0,
    )

    @field_validator("url")
    @classmethod
    def _require_https(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https":
            raise ConfigurationInvalidError("ABUSEIPDB_TAXII_URL must be an HTTPS URL")
        return value

    @field_validator("collection_id")
    @classmethod
    def _blank_collection_id_is_unset(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @property
    def api_root(self) -> str:
        """TAXII API root URL, always ending with a slash."""
        return str(self.url).rstrip("/") + "/"

    @property
    def import_since_iso(self) -> str:
        """Import window start as the TAXII ``added_after`` timestamp string."""
        return (
            self.import_since.astimezone(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )


class ConnectorSettings(BaseExternalImportConnectorSettings):
    """Aggregates all configuration objects the connector needs."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    abuseipdb_taxii: AbuseIPDBTaxiiConfig = Field(default_factory=AbuseIPDBTaxiiConfig)
