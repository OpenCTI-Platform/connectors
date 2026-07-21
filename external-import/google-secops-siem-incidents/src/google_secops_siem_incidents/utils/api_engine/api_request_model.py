"""Request model for the API engine."""

from typing import Any

from pydantic import BaseModel

from .interfaces.base_request_model import BaseRequestModel


class ApiRequestModel(BaseRequestModel):
    """Describes a single HTTP request to be executed by a strategy."""

    url: str
    method: str = "GET"
    headers: dict[str, str] | None = None
    params: dict[str, Any] | None = None
    data: dict[str, Any] | None = None
    json_body: dict[str, Any] | None = None
    response_key: str | None = None
    response_model: type[BaseModel] | None = None
    timeout: int | None = None

    model_config = {"arbitrary_types_allowed": True}
