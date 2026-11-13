from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class EsetConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="a4df8389-6ba4-4e2c-b09e-f8014f0d0af1",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ESET ETI Report Enrichment Connector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["report"],
    )
    max_tlp: TLPLevel = Field(
        description=(
            "The highest TLP of the entities the connector is allowed to enrich. "
            "Entities marked with a higher TLP are skipped and never sent to the external source."
        ),
        default=TLPLevel.RED,
    )


class EsetConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `EsetConnector`.
    """

    api_key: SecretStr = Field(
        description="ESET Threat Intelligence API key.",
    )
    api_secret: SecretStr = Field(
        description="ESET Threat Intelligence API secret.",
    )
    api_host: HttpUrl = Field(
        description="ESET Threat Intelligence API base URL.",
        default=HttpUrl("https://eti.eset.com/"),
    )


class LegacyConnectorTemplateConfig(BaseConfigModel):
    """
    Legacy `connector_template` section, left over from the connector template.
    Only its `max_tlp` variable is migrated, to `connector.max_tlp`.
    """

    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="Max TLP level of the reports to enrich.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `EsetConnectorConfig` and `EsetConfig`.
    """

    connector: EsetConnectorConfig = Field(default_factory=EsetConnectorConfig)
    eset: EsetConfig = Field(default_factory=EsetConfig)

    # Legacy `CONNECTOR_TEMPLATE_*` env vars prefix
    connector_template: LegacyConnectorTemplateConfig = Field(
        default_factory=LegacyConnectorTemplateConfig
    )
