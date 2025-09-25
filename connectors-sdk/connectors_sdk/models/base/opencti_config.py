from pydantic import (
    BaseModel,
    Field,
    HttpUrl,
)


class OpenCTIConfig(BaseModel):
    """
    Define config specific to OpenCTI.
    """

    url: HttpUrl = Field(
        description="The base URL of the OpenCTI instance.",
    )
    token: str = Field(
        description="The API token to connect to OpenCTI.",
    )
