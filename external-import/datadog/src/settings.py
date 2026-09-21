"""Pydantic settings for the DataDog external-import connector.

The models below mirror — one to one — the configuration variables the
connector already consumed through ``pycti.get_config_variable``:

* the standard ``OPENCTI_*`` / ``CONNECTOR_*`` variables are handled by
  ``connectors_sdk.BaseConnectorSettings`` / ``BaseExternalImportConnectorConfig``,
* the connector-specific ``DATADOG_*`` variables live in :class:`DataDogConfig`.

Values are resolved (in precedence order) from environment variables, a
``.env`` file, or ``config.yml`` — the loading is entirely handled by the SDK,
so the connector no longer parses ``config.yml`` itself.
"""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class DataDogConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector section configuration.

    Mirrors the ``CONNECTOR_*`` variables documented by this connector and
    provides the defaults required to deploy it from the OpenCTI catalog.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="ac3f08df-af45-4669-aec6-25b0e6487094",
    )
    name: str = Field(
        description="The name of the connector.",
        default="DataDog",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["stix2"],
    )
    duration_period: timedelta = Field(
        description=(
            "The period of time to await between two runs of the connector. "
            "This connector drives its own polling loop from "
            "'DATADOG_IMPORT_INTERVAL', so this value is only used to satisfy "
            "the manager-supported contract."
        ),
        default=timedelta(hours=1),
    )


class DataDogConfig(BaseConfigModel):
    """Config fields specific to the DataDog connector.

    Mirrors the connector's existing ``DATADOG_*`` variables one to one.
    """

    token: SecretStr = Field(
        description="The DataDog API key used to authenticate against the DataDog API.",
    )
    app_key: SecretStr = Field(
        description=(
            "The DataDog Application key. Required by the Security Monitoring "
            "v2 API, which rejects calls missing it with a 403."
        ),
    )
    api_base_url: str = Field(
        description="The base URL of the DataDog API (site-dependent).",
        default="https://api.datadoghq.com",
    )
    app_base_url: str = Field(
        description=(
            "The base URL of the DataDog web application, used to build the "
            "external references pointing back to each signal."
        ),
        default="https://app.datadoghq.com",
    )
    import_interval: int = Field(
        description="The interval, in minutes, between two runs of the connector.",
        default=60,
    )
    import_start_date: str | None = Field(
        description=(
            "The ISO 8601 date to start importing signals from on the very "
            "first run (e.g. '2024-01-01T00:00:00Z'). Defaults to 24 hours ago."
        ),
        default=None,
    )
    max_tlp: str = Field(
        description=(
            "The TLP marking applied to every emitted STIX object. Available "
            "values are: TLP:CLEAR, TLP:WHITE, TLP:GREEN, TLP:AMBER, "
            "TLP:AMBER+STRICT, TLP:RED."
        ),
        default="TLP:AMBER",
    )
    batch_size: int = Field(
        description=(
            "The page size used when paginating the DataDog Security "
            "Monitoring API (DataDog caps this at 1000)."
        ),
        default=100,
    )
    import_alerts: bool = Field(
        description="Whether to import DataDog security signals (alerts).",
        default=True,
    )
    create_incident_response_cases: bool = Field(
        description=(
            "Whether to create a Case-Incident response object for each "
            "imported security signal."
        ),
        default=False,
    )
    alert_priorities: ListFromString = Field(
        description=(
            "Comma-separated list of signal priorities to import "
            "(e.g. 'P1,P2'). Defaults to every priority."
        ),
        default=["P1", "P2", "P3", "P4"],
    )
    alert_tags_filter: ListFromString = Field(
        description=(
            "Comma-separated list of DataDog tags used to filter the imported "
            "signals (e.g. 'env:prod,team:secops'). Empty means no filtering."
        ),
        default=[],
    )
    extract_observables_from_alerts: bool = Field(
        description=(
            "Whether to extract the observables (IP addresses, domains, URLs, "
            "user-agents, email addresses) embedded in the signal payload."
        ),
        default=True,
    )
    include_alert_context: bool = Field(
        description=(
            "Whether to emit an explanatory Note carrying the DataDog tags, "
            "monitor query and assignee context of each signal."
        ),
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the DataDog connector."""

    connector: DataDogConnectorConfig = Field(
        default_factory=DataDogConnectorConfig,
    )
    datadog: DataDogConfig = Field(default_factory=DataDogConfig)
