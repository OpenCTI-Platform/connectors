"""EXAMPLE HTTP client -- shows how to call an external API.

`TemplateClient`, its `/ip/{ip}` endpoint and the `IPReputation` model are
an example: they do not match any real API. Rewrite them for the API your
connector calls.

The client keeps all the network code (base URL, authentication, requests,
errors) in one place. The processors only call its methods, and get
validated, typed objects back (see `template_client/models.py`).

`BaseClientApi` (from `connectors-sdk`) already provides:
    - an HTTP session, created on the first request;
    - retries with backoff on 429 and 5xx responses;
    - optional rate limiting;
    - typed exceptions for HTTP errors (`ApiNotFoundError` on 404,
      `ApiServerError` on 5xx...).

The client does not catch these exceptions: it lets them go up to the
processor, which decides what an error means. For example, a 404 means that
the source does not know the entity: this is not a failure.

TODO:
    - [ ] Rename `TemplateClient` and the `template_client` package
        (e.g. `CyberThreatApiClient` and `cyber_threat_api_client`).
    - [ ] Change `session_headers` for the authentication scheme of your API.
    - [ ] Replace `get_ip_reputation` with one method per endpoint you call.
"""

from connectors_sdk import BaseClientApi
from template_client.models import IPReputation


class TemplateClient(BaseClientApi):
    """EXAMPLE client -- rewrite it for your own API."""

    def __init__(self, base_url: str, api_key: str):
        """Create the client.

        Args:
            base_url: The external API base URL.
            api_key: The API key used to authenticate every request.

        Add any other argument your API needs (a second credential, a proxy...).
        """
        super().__init__(base_url=base_url)

        self._api_key = api_key

    @property
    def session_headers(self) -> dict[str, str]:
        """The HTTP headers sent with every request.

        `BaseClientApi` reads this property once, when it creates the HTTP
        session (on the first request). Never log these headers: they contain
        the API key.
        """
        return {
            "Accept": "application/json",
            "Authorization": "Bearer " + self._api_key,
        }

    def get_ip_reputation(self, ip: str) -> IPReputation:
        """EXAMPLE -- get the reputation of an IP address.

        Args:
            ip: The IP address.

        Returns:
            The reputation of the IP, validated against `IPReputation`.

        Raises:
            ApiNotFoundError: If the API does not know the IP (HTTP 404).
            ApiClientError: If the request fails for another reason.
        """
        return IPReputation.model_validate(self._get(f"/ip/{ip}"))
