from typing import Annotated, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from connectors_sdk.core.pydantic import ListFromString
from pydantic import Field, HttpUrl, PlainSerializer, SecretStr

TLPToLower = Annotated[
    Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseConnectorConfig` to add connector specific configuration parameters and/or defaults.
    """

    id: str = Field(
        default="kaspersky--8825ba29-8475-4e6a-95b7-9206052c0934",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="Kaspersky Enrichment",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=["StixFile", "IPv4-Addr", "Domain-Name", "Hostname", "Url"],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )
    auto: bool = Field(
        default=True,
        description="If True, the connector will automatically import data from the API.",
    )


class KasperskyConfig(BaseConfigModel):
    """
    Define config vars specific to Kaspersky connector.
    """

    # Connector extra parameters
    api_base_url: HttpUrl = Field(
        default=HttpUrl("https://tip.kaspersky.com"),
        description="Kaspersky API base URL.",
    )

    api_key: SecretStr = Field(
        description="API key used to authenticate requests to the Kaspersky service.",
    )

    max_tlp: TLPToLower = Field(
        default="TLP:AMBER",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI. "
        "Available values: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include additional configuration parameters specific to the connector.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    kaspersky: KasperskyConfig = Field(default_factory=KasperskyConfig)
