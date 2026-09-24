"""Connector configuration.

Two groups of options: the ones every EXTERNAL_IMPORT connector has
(`ExternalImportConnectorConfig`, inherited from connectors-sdk with defaults
for this connector), and the ones specific to HoneyLabs (`HoneyLabsConfig`).
Values come from environment variables (`HONEYLABS_*`) or `config.yml`.
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

COLLECTIONS = ("attackers", "exploiters", "cve-probers", "malware-infrastructure")


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        description="The unique identifier of the connector.",
        default="aacfcb8e-5bf7-4c09-80d0-31d520476c3c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="HoneyLabs",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the entity types it imports.",
        default=["Indicator", "IPv4-Addr", "Url"],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, as an ISO 8601 "
        "duration (e.g. `PT1H` for one hour). The feeds refresh every 15 minutes; "
        "hourly is the sensible floor.",
        default=timedelta(hours=1),
    )


class HoneyLabsConfig(BaseConfigModel):
    """Options specific to the HoneyLabs connector."""

    api_key: SecretStr = Field(
        description="A HoneyLabs API key. Free keys are created at "
        "https://honeylabs.net/dashboard. It is sent as the HTTP Basic password "
        "on the TAXII server, with the fixed username `taxii`.",
    )
    api_root: str = Field(
        description="The TAXII 2.1 API root of the HoneyLabs server.",
        default="https://honeylabs.net/taxii2/api/",
    )
    collections: ListFromString = Field(
        description="Which HoneyLabs collections to import, by alias. `attackers` is "
        "the union of `exploiters` (addresses that ran exploit or loader commands "
        "against the sensors) and, on paid plans, `cve-probers` (addresses that probed "
        "a specific CVE's exploit path, labelled with the CVE ids). "
        "`malware-infrastructure` is the loader and C2 URLs pulled out of captured "
        "payloads.",
        default=["attackers", "malware-infrastructure"],
    )
    import_since: DatetimeFromIsoString = Field(
        description="Start date for the first import (ISO 8601, absolute like "
        "'2026-01-01T00:00:00Z' or relative like 'P7D'). Later runs resume from the "
        "connector state. The free plan serves 7 days of history, paid plans 30.",
        default_factory=lambda: (datetime.now(timezone.utc) - timedelta(days=7)),
    )
    page_size: int = Field(
        description="Objects requested per TAXII page.",
        default=500,
        ge=1,
        le=1000,
    )
    create_observables: bool = Field(
        description="Create the IPv4 address and URL observables behind each indicator, "
        "with a `based-on` relationship.",
        default=True,
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to every object this connector creates.",
        default=TLPLevel.CLEAR,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    honeylabs: HoneyLabsConfig = Field(default_factory=HoneyLabsConfig)
