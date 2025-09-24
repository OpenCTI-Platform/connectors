"""API Request Model."""

from typing import Any, Optional, Type

from pydantic import BaseModel

from .interfaces.base_request_model import BaseRequestModel


class ApiRequestModel(BaseRequestModel):
    """API Request Model."""

    url: str
    method: str = "GET"
    headers: Optional[dict[str, Any]] = None
    params: Optional[dict[str, Any]] = None
    data: Optional[dict[str, Any]] = None
    json_payload: Optional[dict[str, Any]] = None
    response_key: Optional[str] = None
    model: Optional[Type[BaseModel]] = None
    timeout: Optional[int] = None
