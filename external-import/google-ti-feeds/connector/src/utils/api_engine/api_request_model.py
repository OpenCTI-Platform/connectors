"""API Request Model."""

from typing import Any, Dict, Optional, Type

from pydantic import BaseModel

from .interfaces.base_request_model import BaseRequestModel


class ApiRequestModel(BaseRequestModel):
    """API Request Model."""

    url: str
    method: str = "GET"
    headers: Optional[Dict[str, Any]] = None
    params: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None
    json_payload: Optional[Dict[str, Any]] = None
    response_key: Optional[str] = None
    model: Optional[Type[BaseModel]] = None
    timeout: Optional[int] = None
