from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pydantic import Field


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    name: str = Field(
        description="The name of the connector.",
        default="Dual Signal Triage",
    )


class DualSignalConfig(BaseConfigModel):
    max_tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Max TLP level of the entities to enrich.",
        default="amber+strict",
    )
    create_note: bool = Field(
        description="Create a Note with the Gate/Prove triage summary.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    dual_signal_triage: DualSignalConfig = Field(default_factory=DualSignalConfig)
