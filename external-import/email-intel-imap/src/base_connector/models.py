from pydantic import BaseModel


class CustomProperties(BaseModel):
    """Common custom properties."""


class ReportCustomProperties(CustomProperties):
    x_opencti_content: str
