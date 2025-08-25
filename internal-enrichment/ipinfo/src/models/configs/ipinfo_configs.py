from typing import Annotated, Literal, Optional

from pydantic import (
    Field,
    PlainSerializer,
    SecretStr,
)
from src.models.configs import ConfigBaseSettings

TLPToLower = Annotated[
    Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]


class _ConfigLoaderIPInfo(ConfigBaseSettings):
    """Interface for loading IPInfo dedicated configuration."""

    # Config Loader
    token: SecretStr = Field(
        alias="IPINFO_TOKEN",
        description="API token used to authenticate requests to the IPInfo service.",
    )
    max_tlp: Optional[TLPToLower] = Field(
        alias="IPINFO_MAX_TLP",
        default="TLP:AMBER",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI.",
    )
    use_asn_name: Optional[bool] = Field(
        alias="IPINFO_USE_ASN_NAME",
        default=True,
        description="If enabled, uses the ASN name instead of the ASN number in enrichment results.",
    )
