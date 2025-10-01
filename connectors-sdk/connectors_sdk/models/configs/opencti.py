from connectors_sdk.models.configs import BaseConfigModel
from pydantic import (
    Field,
    HttpUrl,
)


class _OpenCTIConfig(BaseConfigModel):
    """
    Define config specific to OpenCTI
    """

    url: HttpUrl = Field(
        description="The base URL of the OpenCTI instance.",
    )
    token: str = Field(
        description="The API token to connect to OpenCTI.",
    )
