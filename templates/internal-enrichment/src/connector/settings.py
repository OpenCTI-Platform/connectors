"""Connector configuration models.

This module defines all the options the connector accepts, in two groups:

    - `InternalEnrichmentConnectorConfig`: the options common to every
      `INTERNAL_ENRICHMENT` connector. `connectors-sdk` defines them; this
      class only changes some of their default values.
    - `TemplateConfig`: the options specific to this connector (API URL,
      credentials, etc.). Rename this class, and the `template` attribute
      of `ConnectorSettings` below, to match your connector's name.

The values are read from environment variables or from `config.yml` (see
`config.yml.sample`). Pydantic validates them when the connector starts: an
invalid value stops the connector with a clear error, before it handles any
message.
"""

from connectors_sdk import (
    BaseConfigModel,
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalEnrichmentConnectorSettings,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Options common to every `INTERNAL_ENRICHMENT` connector.

    Overrides `BaseInternalEnrichmentConnectorConfig` (from `connectors-sdk`)
    to set the default values of this connector. The options that are not
    overridden here (`auto`, `log_level`...) keep the SDK defaults.

    TODO:
        - [ ] Replace the `id` default with a valid, unique UUIDv4.
        - [ ] Replace the `name` default with your connector's display name.
        - [ ] Set the `scope` default to the entity types your processors
            handle. The connector refuses to start if a scope type is
            handled by no processor.
        - [ ] Set the `max_tlp` default for your source, or remove the field
            to keep the SDK default (`amber`).
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
        description="The OpenCTI entity types the connector enriches.",
        default=["IPv4-Addr"],  # the entity types of your processors
    )
    max_tlp: TLPLevel = Field(
        description="The highest TLP of the entities the connector is allowed to enrich. "
        "Entities marked with a higher TLP are skipped and never sent to the external source.",
        default=TLPLevel.GREEN,
    )


class TemplateConfig(BaseConfigModel):
    """Options specific to this connector.

    TODO:
        - [ ] Rename this class and the `template` attribute of `ConnectorSettings`
            to match your connector (e.g. `CyberThreatApiConfig` and `cyber_threat_api`).
        - [ ] Replace `api_key` with the credentials your API requires. Always use
            `SecretStr` for secrets, so that their value never appears in logs.
        - [ ] Add, change or remove options to fit your API and your processors.
    """

    api_base_url: HttpUrl = Field(
        description="External API base URL.",
        default=HttpUrl("https://api.example.com/v1"),
    )
    api_key: SecretStr = Field(
        description="API key used to authenticate against the external API."
    )
    create_autonomous_system: bool = Field(
        description="Whether to create the autonomous system of the IP address, "
        "with a `belongs-to` relationship from the IP address.",
        default=True,
    )


class ConnectorSettings(BaseInternalEnrichmentConnectorSettings):
    """All the configuration of the connector.

    Overrides `BaseInternalEnrichmentConnectorSettings` (from `connectors-sdk`)
    to use `InternalEnrichmentConnectorConfig` and `TemplateConfig` above.

    TODO:
        - [ ] Rename the `template` attribute to match your connector's name
            (e.g. `cyber_threat_api` for a `CyberThreatApiConfig` class).
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    template: TemplateConfig = Field(default_factory=TemplateConfig)
