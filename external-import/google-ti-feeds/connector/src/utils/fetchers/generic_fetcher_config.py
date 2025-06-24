"""Generic fetcher configuration for any API endpoint.

This module provides a flexible configuration system for creating fetchers
that can work with any API endpoint, response model, and exception handling.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Type

from pydantic import BaseModel


@dataclass
class GenericFetcherConfig:
    """Configuration for a generic API fetcher.

    This configuration allows creating fetchers for any API endpoint with
    flexible response handling and exception management.
    """

    entity_type: str
    """The type of entity being fetched (e.g., 'users', 'products', 'reports')"""

    endpoint: str
    """The API endpoint URL or URL template (e.g., '/api/users/{id}' or '/api/users')"""

    display_name: str
    """Human-readable name for logging and error messages (e.g., 'users', 'products')"""

    exception_class: Type[Exception]
    """Exception class to raise on errors"""

    response_model: Optional[Type[BaseModel]] = None
    """Optional Pydantic model for response parsing. If None, returns raw data"""

    display_name_singular: Optional[str] = None
    """Singular form of display name. Auto-generated if not provided"""

    method: str = "GET"
    """HTTP method to use (GET, POST, PUT, DELETE, etc.)"""

    headers: Optional[Dict[str, str]] = None
    """Additional headers to include in requests"""

    timeout: Optional[float] = 60.0
    """Request timeout in seconds"""

    response_key: Optional[str] = None
    """Key to extract from response JSON (e.g., 'data', 'results')"""

    save_to_file: bool = False
    """If True, save raw response to a file named by SHA256 hash for debugging/testing"""

    def __post_init__(self) -> None:
        """Post-initialization to set defaults."""
        if self.display_name_singular is None:
            if self.display_name.endswith("s") and len(self.display_name) > 1:
                self.display_name_singular = self.display_name[:-1]
            else:
                self.display_name_singular = self.display_name

        if self.headers is None:
            self.headers = {}

    def format_endpoint(self, **kwargs: Any) -> str:
        """Format the endpoint URL with provided parameters.

        Args:
            **kwargs: Parameters to substitute in the endpoint template

        Returns:
            Formatted endpoint URL

        Example:
            config = GenericFetcherConfig(endpoint='/api/users/{user_id}', ...)
            url = config.format_endpoint(user_id='123')  # Returns '/api/users/123'

        """
        try:
            return self.endpoint.format(**kwargs)
        except KeyError as e:
            missing_param = str(e).strip("'")
            raise ValueError(
                f"Missing required parameter '{missing_param}' for endpoint '{self.endpoint}'"
            ) from e

    def create_exception(self, message: str, **kwargs: Any) -> Exception:
        """Create an exception instance with the configured exception class.

        Args:
            message: Error message
            **kwargs: Additional parameters to pass to exception constructor

        Returns:
            Exception instance

        """
        try:
            return self.exception_class(message, **kwargs)
        except TypeError:
            return self.exception_class(message)
