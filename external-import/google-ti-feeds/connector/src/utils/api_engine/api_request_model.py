"""API Request Model."""

from typing import Any

from pydantic import BaseModel

from .interfaces.base_request_model import BaseRequestModel


class ApiRequestModel(BaseRequestModel):
    """API Request Model."""

    url: str
    method: str = "GET"
    headers: dict[str, Any] | None = None
    params: dict[str, Any] | None = None
    data: dict[str, Any] | None = None
    json_payload: dict[str, Any] | None = None
    response_key: str | None = None
    model: type[BaseModel] | None = None
    timeout: int | None = None
