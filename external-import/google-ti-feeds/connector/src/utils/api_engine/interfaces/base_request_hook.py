"""BaseRequestHook interface."""

from abc import ABC, abstractmethod
from typing import Any

from .base_request_model import BaseRequestModel


class BaseRequestHook(ABC):
    """BaseRequestHook interface.
    This class defines the interface for request hooks.

    This class provides a base implementation for request hooks.
    One before the request is sent and after the response is received.
    """

    @abstractmethod
    async def before(self, request: BaseRequestModel) -> None:
        """Call before the request is sent."""
        raise NotImplementedError("Subclasses must implement this method")

    @abstractmethod
    async def after(self, request: BaseRequestModel, response: Any) -> None:
        """Call after the response is received."""
        raise NotImplementedError("Subclasses must implement this method")
