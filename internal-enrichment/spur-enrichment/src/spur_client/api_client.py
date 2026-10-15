from connectors_sdk import ApiClientError, BaseClientApi
from spur_client.models import IPContext


class SpurClient(BaseClientApi):
    """Client for the Spur Context API (https://docs.spur.us/context-api/endpoints)."""

    def __init__(self, base_url: str, api_key: str, timeout: int = 60) -> None:
        self._api_key = api_key
        super().__init__(base_url, timeout=timeout)

    @property
    def session_headers(self) -> dict[str, str]:
        return {"Token": self._api_key}

    def get_ip_context(self, ip: str) -> IPContext | None:
        """Return the IP Context object of a public IPv4 or IPv6 address.

        Each call consumes one query of the Context API quota.

        Returns:
            The IP Context object, or `None` when Spur rejects the address
            (HTTP 400, e.g. a private or reserved IP).

        Raises:
            ApiClientError: On any other HTTP error (401 invalid token, 403 no
                Context API access, 429 quota exhausted, 5xx...).
            pydantic.ValidationError: When the response is not a valid IP Context object.
        """
        try:
            response = self._get(f"/v2/context/{ip}")
        except ApiClientError as err:
            if err.status_code == 400:
                return None
            raise
        return IPContext.model_validate(response)
