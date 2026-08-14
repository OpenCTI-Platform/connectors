"""Connector configuration models.

This module defines every configuration option the connector accepts, in
two groups:

    - `ExternalImportConnectorConfig`: options common to every connector
      of type `EXTERNAL_IMPORT` (inherited from `connectors-sdk`), with
      defaults specific to this template.
    - `TemplateConfig`: options specific to *this* connector (API
      credentials, feature flags, etc.). Rename this class (and the
      `template` attribute on `ConnectorSettings` below) to match your
      connector's name.

Configuration values are read from environment variables or `config.yml`
(see `config.yml.sample` and the README's "Configuration variables"
section). Pydantic validates and coerces them automatically: an invalid
value raises a clear error at startup instead of failing later, mid-run.

References:
    See `connectors-sdk`'s `BaseConnectorSettings` for how these
    values are validated, merged from environment variables/`config.yml`,
    and exposed to `pycti`'s `OpenCTIConnectorHelper`.
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
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration, common to every `EXTERNAL_IMPORT` connector.

    Overrides `BaseExternalImportConnectorConfig` (from `connectors-sdk`)
    to set defaults specific to this connector.

    TODO:
        - [ ] Replace the `id` default with a valid, unique `UUIDv4`.
        - [ ] Replace `name` default with your connector's display name.
        - [ ] Replace `scope` default with the actual entity types you import.
        - [ ] Adjust `duration_period` default to a sensible polling frequency
            for your external API (avoid values that could exceed the source API's rate limits).
    """

    id: str = Field(
        description="The unique identifier of the connector.",
        default="template-connector-uuid",  # replace with a valid UUIDv4
    )
    name: str = Field(
        description="The name of the connector.",
        default="TemplateConnector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector e.g., the type of entities the connector imports.",
        default=[],  # replace with accurate values e.g., `['Indicator', 'Report']`
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, "
        "as an ISO 8601 duration (e.g. `PT1H` for one hour)",
        default=timedelta(hours=1),  # adjust to the use case and/or API's rate limits
    )


class TemplateConfig(BaseConfigModel):
    """Configuration specific to this connector (the "template" connector).

    Rename this class, and the `template` attribute it is exposed under on
    `ConnectorSettings` below, to something specific to your connector
    (e.g. `CyberThreatFeedConfig` / `cyber_threat_feed`).

    TODO:
        - [ ] Rename this class and the `template` attribute on `ConnectorSettings`
            to something specific to your connector (e.g. `CyberThreatFeedConfig` / `cyber_threat_feed`).
        - [ ] Replace `api_key` with whatever credentials your external API requires
            (API key, OAuth client id/secret, basic auth, etc.). Always use `SecretStr` type
            for sensitive values so they cannot leak into logs by accident.
        - [ ] Add / update / remove any other option to fit your API/processors needs
            (e.g. a configurable base URL, a proxy URL, a list of tags to filter on, a page size, etc.).
    """

    # --- API connection management ---
    api_key: SecretStr = Field(
        description="API key used to authenticate against the external API."
    )

    # --- Fetching filters ---
    import_since: DatetimeFromIsoString = Field(
        description="The start date (ISO 8601 format) for importing data. "
        "Can be either absolute e.g., a given date like '2023-01-01T00:00:00Z' or "
        "relative e.g., a given period of time like 'PT30D' (meaning '30 days ago'). "
        "Used as the initial checkpoint on connector first run; subsequent runs resume from connector state.",
        default_factory=lambda: (datetime.now(timezone.utc) - timedelta(days=30)),
    )
    import_vulnerabilities: bool = Field(
        description="Enable/disable the import of vulnerabilities.",
        default=True,
    )
    import_reports: bool = Field(
        description="Enable/disable the import of reports.",
        default=True,
    )

    # --- Default / arbitrary attributes for ingested data ---
    tlp_level: TLPLevel = Field(
        description="Default TLP (Traffic Light Protocol) marking applied "
        "to every object this connector creates in OpenCTI.",
        default=TLPLevel.CLEAR,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Aggregates all configuration objects the connector needs.

    Overrides `BaseConnectorSettings` (from `connectors-sdk`) to plug in
    `ExternalImportConnectorConfig` and `TemplateConfig` defined above.

    TODO:
        - [ ] Rename `template` attribute to match the connector's directory name
            in lowercase camel case (e.g. `cyber_threat_feed` for a `CyberThreatFeedConfig` class).
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    template: TemplateConfig = Field(
        default_factory=TemplateConfig,
    )
