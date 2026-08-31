"""Configuration model for the Malanta Attribution connector."""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """Connector-level settings, with defaults suited to this connector."""

    name: str = Field(
        description="The name of the connector.",
        default="Malanta Attribution",
    )
    scope: ListFromString = Field(
        description="Entity types processed by the connector.",
        default=["indicator"],
    )
    live_stream_listen_delete: bool = Field(
        default=False,
        description=(
            "Whether to listen for delete events on the live stream. Disabled by"
            " default: this connector only adds attribution and does not revoke it."
        ),
    )


class MalantaAttributionConfig(BaseConfigModel):
    """Settings specific to deriving attribution from Malanta labels."""

    label_prefix: str = Field(
        description=(
            "Label namespace treated as threat-actor attribution. Labels not"
            " starting with this prefix are ignored."
        ),
        default="apt:",
        examples=["apt:"],
    )
    actor_separators: ListFromString = Field(
        description=(
            "Characters splitting several actors inside a single label. Malanta"
            " occasionally emits comma-joined tokens such as 'apt:APT17,APT5'."
        ),
        default=[","],
        examples=[","],
    )
    author_name: str = Field(
        description=(
            "Organization credited with the derived Intrusion Sets and"
            " relationships. Keep this identical to the feed's author so derived"
            " attribution merges with the ingested data."
        ),
        default="Malanta.ai",
        examples=["Malanta.ai"],
    )
    author_description: str | None = Field(
        description="Optional description for the author organization.",
        default=None,
    )
    create_intrusion_sets: bool = Field(
        description=(
            "Create the Intrusion Set when it does not exist. Disable to emit"
            " only relationships towards Intrusion Sets managed elsewhere."
        ),
        default=True,
    )
    min_confidence: int = Field(
        description=(
            "Skip indicators whose confidence is below this threshold. 0"
            " processes everything."
        ),
        default=0,
        ge=0,
        le=100,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Full settings: OpenCTI connection, connector behaviour, and mapping."""

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    malanta_attribution: MalantaAttributionConfig = Field(
        default_factory=MalantaAttributionConfig
    )
