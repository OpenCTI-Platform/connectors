"""OpenCTI RST WHOIS API connector settings module."""

from connectors_sdk import (
    BaseConfigModel,
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalEnrichmentConnectorSettings,
    DeprecatedField,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import AliasChoices, Field, SecretStr


class RSTWhoisApiConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Defaults of the `connector` section for the RST WHOIS API connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="80a2d7fa-6527-45d6-b1e6-bc3ef51e6f03",
    )
    name: str = Field(
        description="The name of the connector.",
        default="RST WHOIS API",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Domain-Name", "Url", "indicator"],
    )
    max_tlp: TLPLevel = Field(
        description=(
            "The highest TLP of the entities the connector is allowed to enrich. "
            "Entities marked with a higher TLP are skipped and never sent to the external source."
        ),
        default=TLPLevel.AMBER_STRICT,
    )


class RSTWhoisApiConfig(BaseConfigModel):
    """Settings specific to the RST WHOIS API connector."""

    api_key: SecretStr = Field(
        description="The RST Cloud API key.",
    )
    base_url: str = Field(
        description="The base URL of the RST Cloud API.",
        default="https://api.rstcloud.net/v1",
    )
    timeout: int = Field(
        description="The timeout of the RST Cloud API requests, in seconds.",
        default=10,
    )
    whois_output_object: str = Field(
        description=(
            "Where to store the WHOIS data: 'note' to create a Note attached to the entity, "
            "'description' to update the description of the entity."
        ),
        default="note",
    )
    update_output_action: str = Field(
        description=(
            "How to store the WHOIS data: 'overwrite' to replace the previous data, "
            "'append' to add the new data to the previous one."
        ),
        default="overwrite",
    )
    output_format: str = Field(
        description=(
            "The WHOIS data format: 'standard' for the basic WHOIS fields, "
            "'extended' for additional WHOIS fields."
        ),
        default="standard",
    )
    output_include_raw: bool = Field(
        description="Whether to include the raw WHOIS response in the output.",
        default=False,
    )
    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="The highest TLP of the entities the connector is allowed to enrich.",
    )


class ConnectorSettings(BaseInternalEnrichmentConnectorSettings):
    """Settings of the RST WHOIS API connector."""

    connector: RSTWhoisApiConnectorConfig = Field(
        default_factory=RSTWhoisApiConnectorConfig
    )
    rst_whois_api: RSTWhoisApiConfig = Field(
        default_factory=RSTWhoisApiConfig,
        # The legacy config.yml section name is `rst-whois-api`.
        validation_alias=AliasChoices("rst_whois_api", "rst-whois-api"),
    )
