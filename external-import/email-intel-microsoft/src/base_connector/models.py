import base64

from pydantic import BaseModel, field_validator


class CustomProperties(BaseModel):
    """Common custom properties."""


class OpenCTIFile(BaseModel):
    name: str
    mime_type: str
    data: bytes

    @field_validator("data")
    @classmethod
    def validate_data(cls, value: bytes) -> bytes:
        return base64.b64encode(value)


class ReportCustomProperties(CustomProperties):
    x_opencti_content: str
    x_opencti_files: list[OpenCTIFile]
