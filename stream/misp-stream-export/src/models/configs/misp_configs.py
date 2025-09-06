from typing import Annotated, Literal, Optional

from pydantic import (
    Field,
    PlainSerializer,
    SecretStr,
    PositiveInt
)
from src.models.configs.base_settings import ConfigBaseSettings

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


class _ConfigLoaderMISP(ConfigBaseSettings):
    """Interface for loading MISP dedicated configuration."""

    # Config Loader
    url: str = Field(
        alias="MISP_URL",
        description="URL of the MISP server.",
    )

    api_key: SecretStr = Field(
        alias="MISP_API_KEY",
        description="API token used to authenticate requests to the MISP server.",
    )

