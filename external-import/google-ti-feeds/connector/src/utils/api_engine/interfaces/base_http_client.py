"""BaseHttpClient Interfaces."""

from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseHttpClient(ABC):
    """BaseHttpClient Interfaces.

    This class defines the interface for a base HTTP client.

    It provides an abstract base class for implementing HTTP clients.
    Subclasses must implement the `request` method to perform HTTP requests.
    """

    @abstractmethod
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
        json_payload: Optional[dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """Perform an HTTP request and return the parsed JSON.

        Args:
            method (str): The HTTP method to use.
            url (str): The URL to send the request to.
            headers (Optional[dict[str, str]], optional): The headers to include in the request. Defaults to None.
            params (Optional[dict[str, Any]], optional): The query parameters to include in the request. Defaults to None.
            data (Optional[dict[str, Any]], optional): The data to include in the request body. Defaults to None.
            json_payload (Optional[dict[str, Any]], optional): The JSON data to include in the request body. Defaults to None.
            timeout (Optional[int], optional): The timeout in seconds for the request. Defaults to None.

        Returns:
            dict[str, Any]: The JSON response from the server.

        """
        raise NotImplementedError("Subclass must implement this method.")
