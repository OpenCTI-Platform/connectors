from pydantic import Base64Bytes, BaseModel


class CustomProperties(BaseModel):
    """Common custom properties."""


class OpenCTIFile(BaseModel):
    name: str
    mime_type: str
    data: Base64Bytes


class ReportCustomProperties(CustomProperties):
    x_opencti_content: str
    x_opencti_files: list[OpenCTIFile]
