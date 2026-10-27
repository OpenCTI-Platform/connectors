"""ShodanInternetDbHostByIdProvider."""

from typing import Any

import requests
from connectors_sdk.client.base_client_api import BaseClientApi
from connectors_sdk.client.exceptions import ApiClientError, ApiNotFoundError
from connectors_sdk.converters.shodan_internetdb.models import (
    ShodanInternetDbHostInput,
    ShodanInternetDbResult,
)
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.providers.base import AbstractByIdProvider
from pydantic import ValidationError

INTERNETDB_URL = "https://internetdb.shodan.io"


class ShodanInternetDbClient(BaseClientApi):
    """Client for the Shodan InternetDB API (no API key).

    It inherits timeout, retries on 429 and 5xx, rate limiting and typed errors
    (``ApiNotFoundError`` on 404) from ``BaseClientApi``.
    """

    def __init__(self, base_url: str = INTERNETDB_URL, **kwargs: Any) -> None:
        """Initialize the client.

        Args:
            base_url: The InternetDB URL.
            **kwargs: Passed to ``BaseClientApi`` (timeout, ssl_verify, retries...).
        """
        super().__init__(base_url, **kwargs)

    def get_host(self, ip: str) -> Any:
        """Return the InternetDB response body of an IP.

        Args:
            ip: The IP address.

        Returns:
            The parsed JSON body.

        Raises:
            ApiNotFoundError: If InternetDB has no information on the IP.
            ApiClientError: On other HTTP errors.
        """
        return self._get(ip)


class ShodanInternetDbHostByIdProvider(AbstractByIdProvider[ShodanInternetDbHostInput]):
    """Return the Shodan InternetDB data of IP addresses.

    The items are the input of ``ShodanInternetDbHostConverter``.

    Examples:
        >>> class FakeClient:
        ...     def get_host(self, ip):
        ...         return {"cpes": [], "hostnames": [], "ip": ip, "ports": [443], "tags": [], "vulns": []}
        >>> provider = ShodanInternetDbHostByIdProvider(client=FakeClient())
        >>> provider.get_data(["1.2.3.4"])["1.2.3.4"].result.ports
        [443]
    """

    def __init__(self, client: ShodanInternetDbClient | None = None) -> None:
        """Initialize the provider.

        Args:
            client: The InternetDB client. Defaults to a client on the public API.
        """
        self.client = client or ShodanInternetDbClient()

    def get_data(self, ids: list[str]) -> dict[str, ShodanInternetDbHostInput]:
        """Query InternetDB once per distinct IP.

        Args:
            ids: The IP addresses.

        Returns:
            The data of each IP, keyed by IP. An IP unknown to InternetDB (404)
            is absent.

        Raises:
            DataRetrievalError: If a request fails, InternetDB answers with
                another error, or a response has an unexpected format.
        """
        results: dict[str, ShodanInternetDbHostInput] = {}
        for ip in dict.fromkeys(ids):
            try:
                body = self.client.get_host(ip)
            except ApiNotFoundError:
                continue
            except (ApiClientError, requests.RequestException) as err:
                raise DataRetrievalError(
                    f"Cannot query Shodan InternetDB for {ip}"
                ) from err
            try:
                result = ShodanInternetDbResult.model_validate(body)
            except ValidationError as err:
                raise DataRetrievalError(
                    f"Unexpected Shodan InternetDB response for {ip}"
                ) from err
            results[ip] = ShodanInternetDbHostInput(observable_value=ip, result=result)
        return results
