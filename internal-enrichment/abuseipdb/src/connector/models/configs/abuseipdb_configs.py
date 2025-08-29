from typing import Annotated, Literal, Optional

from pydantic import (
    Field,
    PlainSerializer,
    SecretStr,
)
from src.connector.models.configs.base_settings import ConfigBaseSettings

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


class _ConfigLoaderAbuseIPDB(ConfigBaseSettings):
    """Interface for loading AbuseIPDB dedicated configuration."""

    # Config Loader
    api_key: SecretStr = Field(
        description="API key used to authenticate requests to the AbuseIPDB service.",
    )
    max_tlp: Optional[TLPToLower] = Field(
        default="TLP:AMBER",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI.",
    )
