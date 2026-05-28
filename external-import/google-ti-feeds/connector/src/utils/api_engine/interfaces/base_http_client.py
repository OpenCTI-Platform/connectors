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
        timeout: float | None = None,
        as_bytes: bool = False,
    ) -> dict[str, Any] | tuple[int, bytes]:
        """Perform an HTTP request and return the parsed JSON or raw bytes.

        Args:
            method (str): The HTTP method to use.
            url (str): The URL to send the request to.
            headers (dict[str, str] | None, optional): The headers to include in the request. Defaults to None.
            params (dict[str, Any] | None, optional): The query parameters to include in the request. Defaults to None.
            data (dict[str, Any] | None, optional): The data to include in the request body. Defaults to None.
            json_payload (dict[str, Any] | None, optional): The JSON data to include in the request body. Defaults to None.
            timeout (float | None, optional): The timeout in seconds for the request. Defaults to None.
            as_bytes (bool, optional): Whether to return raw bytes instead of parsed JSON. Defaults to False.

        Returns:
            dict[str, Any] | tuple[int, bytes]: The JSON response from the server or raw bytes.

        """
        raise NotImplementedError("Subclass must implement this method.")
