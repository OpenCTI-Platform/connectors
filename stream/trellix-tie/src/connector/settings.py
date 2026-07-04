from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Trellix TIE",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["trellix-tie"],
    )
    live_stream_id: str = Field(
        description="The ID of the OpenCTI live stream to connect to.",
        default="live",
    )


class TrellixTieConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the
    `TrellixTieConnector`.
    """

    dxl_config_path: str = Field(
        description=(
            "Path to the ePO-provisioned OpenDXL configuration file "
            "(dxlclient.config) describing the DXL brokers and client certificate."
        ),
    )
    trust_level: Literal[
        "KNOWN_MALICIOUS",
        "MOST_LIKELY_MALICIOUS",
        "MIGHT_BE_MALICIOUS",
        "UNKNOWN",
        "MIGHT_BE_TRUSTED",
        "MOST_LIKELY_TRUSTED",
        "KNOWN_TRUSTED",
        "KNOWN_TRUSTED_INSTALLER",
        "NOT_SET",
    ] = Field(
        description="Trust level to set on the TIE enterprise reputation for pushed hashes.",
        default="KNOWN_MALICIOUS",
    )
    comment: str = Field(
        description="Comment attached to the reputation set in TIE.",
        default="Set by OpenCTI",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and
    `TrellixTieConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    trellix_tie: TrellixTieConfig = Field(default_factory=TrellixTieConfig)
