"""RequestStrategy interface."""

from abc import ABC, abstractmethod
from typing import Any

from .base_request_model import BaseRequestModel


class BaseRequestStrategy(ABC):
    """Base class for request strategies."""

    @abstractmethod
    async def execute(self, request: BaseRequestModel) -> Any:
        """Execute the request strategy."""
        raise NotImplementedError("Subclasses must implement this method")
