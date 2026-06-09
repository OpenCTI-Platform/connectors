"""Base request hook interface."""

from abc import ABC, abstractmethod
from typing import Any

from .base_request_model import BaseRequestModel


class BaseRequestHook(ABC):
    """Abstract hook called before and after each HTTP request."""

    @abstractmethod
    async def before(self, request: BaseRequestModel) -> None:
        """Execute before the HTTP request is sent.

        Args:
            request: The outgoing request model.
        """
        ...

    @abstractmethod
    async def after(self, request: BaseRequestModel, response: Any) -> None:
        """Execute after the HTTP response is received.

        Args:
            request: The request model that was sent.
            response: The raw response received.
        """
        ...
