from connectors_sdk import (
    TLP,
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Connector-level configuration for the VisionHeight internal enrichment connector.
    Overrides the base class to set our defaults for `id`, `name` and `scope`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="72de5a27-4619-4189-a66b-ad89819b200a",
    )
    name: str = Field(
        description="The name of the connector.",
        default="VisionHeight",
    )
    scope: ListFromString = Field(
        description="Comma-separated list of OpenCTI entity types this connector enriches.",
        default=["IPv4-Addr", "Domain-Name"],
    )
    max_tlp: TLP = Field(
        description=(
            "The highest TLP of the entities the connector is allowed to enrich. "
            "Entities marked with a higher TLP are skipped and never sent to the external source."
        ),
        default=TLP.AMBER_STRICT,
    )


class VisionHeightConfig(BaseConfigModel):
    """
    VisionHeight-specific configuration: API credentials and URL.
    """

    api_base_url: HttpUrl = Field(
        description="VisionHeight API base URL. Override for white-label or staging endpoints.",
        default="https://api.visionheight.com",
    )
    api_key: SecretStr = Field(
        description="VisionHeight API key used to authenticate requests (sent as the x-api-key header).",
    )
    max_tlp_level: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="Maximum TLP level of observables this connector will enrich. Observables marked above this level cause the enrichment to abort with an error logged.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Top-level settings combining base connector config with VisionHeight-specific config.
    Loaded by the OpenCTI connector helper at startup.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    visionheight: VisionHeightConfig = Field(default_factory=VisionHeightConfig)
