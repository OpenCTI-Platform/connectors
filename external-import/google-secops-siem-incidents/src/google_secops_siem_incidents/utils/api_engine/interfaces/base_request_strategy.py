"""Base request strategy interface."""

from abc import ABC, abstractmethod
from typing import Any

from .base_request_model import BaseRequestModel


class BaseRequestStrategy(ABC):
    """Abstract strategy for executing HTTP requests."""

    @abstractmethod
    async def execute(self, request: BaseRequestModel) -> Any:
        """Execute the given request and return the result.

        Args:
            request: The request model to execute.

        Returns:
            Parsed response from the HTTP layer.
        """
        ...

    @abstractmethod
    async def close(self) -> None:
        """Close the underlying HTTP resources."""
        ...
