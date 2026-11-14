import re

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr, field_validator


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="The unique identifier of the connector.",
        default="6697b01e-aa4c-45f3-9996-4a040b3df037",
    )
    name: str = Field(
        description="The name of the connector.",
        default="MISP Enrichment",
    )
    scope: ListFromString = Field(
        description="The OpenCTI entity types the connector enriches.",
        default=[
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "Url",
            "StixFile",
            "Email-Addr",
            "Indicator",
        ],
    )
    max_tlp: TLPLevel = Field(
        description=(
            "The highest TLP of the entities the connector is allowed to enrich. "
            "Entities marked with a higher TLP are skipped and never sent to the external source."
        ),
        default=TLPLevel.AMBER_STRICT,
    )


class MispConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MispEnrichmentConnector`.
    """

    url: HttpUrl = Field(description="Base URL of the MISP instance.")
    api_key: SecretStr = Field(description="MISP automation API key.")
    ssl_verify: bool = Field(
        description="Verify the SSL certificate of the MISP instance.",
        default=True,
    )
    import_attribute_tags_as_labels: bool = Field(
        description="Apply the tags of the matched MISP attributes as labels on the enriched entity.",
        default=True,
    )
    import_associated_events_tags_as_labels: bool = Field(
        description="Apply the tags of the matched MISP events as labels on the enriched entity.",
        default=False,
    )
    event_filter_creator_orgs: ListFromString = Field(
        description=(
            "Creator organisations (Event.Orgc, name or UUID) to include. "
            "If set, only events created by one of these organisations are considered."
        ),
        default=[],
    )
    event_filter_creator_orgs_not: ListFromString = Field(
        description="Creator organisations (Event.Orgc, name or UUID) to exclude.",
        default=[],
    )
    event_filter_owner_orgs: ListFromString = Field(
        description=(
            "Owner organisations (Event.Org, name or UUID) to include. "
            "If set, only events owned by one of these organisations are considered."
        ),
        default=[],
    )
    event_filter_owner_orgs_not: ListFromString = Field(
        description="Owner organisations (Event.Org, name or UUID) to exclude.",
        default=[],
    )
    event_filter_name_regex: str | None = Field(
        description="Regex searched in the event name (Event.info). Only events whose name matches are considered.",
        default=None,
    )
    attribute_comment_filter_regex: str | None = Field(
        description=(
            "Regex searched in the attribute comment. The comment of a matched attribute "
            "is written in the Note only if it matches."
        ),
        default=None,
    )
    import_events: bool = Field(
        description="Create one OpenCTI Report per matched MISP event, containing the enriched entity.",
        default=False,
    )

    @field_validator("event_filter_name_regex", "attribute_comment_filter_regex")
    @classmethod
    def _validate_regex(cls, value: str | None) -> str | None:
        if value:
            try:
                re.compile(value)
            except re.error as err:
                raise ValueError(f"Invalid regex: {err}") from err
        return value or None


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `MispConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    misp: MispConfig = Field(default_factory=MispConfig)
