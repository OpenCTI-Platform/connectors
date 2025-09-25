"""BaseHttpClient Interfaces."""

from abc import ABC, abstractmethod
from typing import Any


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
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_payload: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Perform an HTTP request and return the parsed JSON.

        Args:
            method (str): The HTTP method to use.
            url (str): The URL to send the request to.
            headers (dict[str, str] | None, optional): The headers to include in the request. Defaults to None.
            params (dict[str, Any] | None, optional): The query parameters to include in the request. Defaults to None.
            data (dict[str, Any] | None, optional): The data to include in the request body. Defaults to None.
            json_payload (dict[str, Any] | None, optional): The JSON data to include in the request body. Defaults to None.
            timeout (int | None, optional): The timeout in seconds for the request. Defaults to None.

        Returns:
            dict[str, Any]: The JSON response from the server.

        """
        raise NotImplementedError("Subclass must implement this method.")
