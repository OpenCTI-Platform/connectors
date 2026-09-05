from typing import Any

import requests
from doppel_client.constants import DOPPEL_ATTRIBUTION_HEADERS
from doppel_client.oauth import OAuthTokenProvider
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class DoppelClientError(Exception):
    """Raised when a request to the Doppel API fails."""


class DoppelClient:
    """Thin client for the Doppel Brand Protection API."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: HttpUrl,
        api_key: str | None = None,
        user_api_key: str | None = None,
        api_version: str = "v1",
        client_id: str | None = None,
        client_secret: str | None = None,
        token_url: HttpUrl | None = None,
        token_audience: str = "doppel-external",
    ):
        """
        Initialize the client with necessary configuration.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            base_url (HttpUrl): The Doppel API base URL.
            api_key (str | None): Doppel API key required for V1; omit for V2.
            user_api_key (str | None): Doppel user API key required for V1; omit
                for V2.
            api_version (str): Doppel API version (`v1` or `v2`).
            client_id (str | None): Doppel OAuth client ID for V2.
            client_secret (str | None): Doppel OAuth client secret for V2.
            token_url (HttpUrl | None): OAuth token endpoint for V2.
            token_audience (str): OAuth audience for V2.
        """
        self.helper = helper
        if api_version not in {"v1", "v2"}:
            raise ValueError("api_version must be v1 or v2")

        configured_base_url = str(base_url).rstrip("/")
        api_root = self._strip_api_version(configured_base_url)
        self.base_url = f"{api_root}/{api_version}"

        self.session = requests.Session()
        headers = {
            **DOPPEL_ATTRIBUTION_HEADERS,
            "Content-Type": "application/json",
        }
        self.oauth_token_provider: OAuthTokenProvider | None = None

        if api_version == "v1":
            if not api_key or not user_api_key:
                raise ValueError("Doppel V1 API and user API keys are required")
            headers.update(
                {
                    "x-api-key": api_key,
                    "x-user-api-key": user_api_key,
                }
            )
        else:
            if not client_id or not client_secret:
                raise ValueError("Doppel V2 client credentials are required")
            resolved_token_url = (
                str(token_url).rstrip("/") if token_url else f"{api_root}/oauth/token"
            )
            self.oauth_token_provider = OAuthTokenProvider(
                token_url=resolved_token_url,
                client_id=client_id,
                client_secret=client_secret,
                audience=token_audience,
            )

        self.session.headers.update(headers)

    @staticmethod
    def _strip_api_version(base_url: str) -> str:
        """Remove a configured API version so the selected version is authoritative."""
        for suffix in ("/v1", "/v2"):
            if base_url.endswith(suffix):
                return base_url[: -len(suffix)]
        return base_url

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Issue a request and refresh a rejected V2 token once."""
        request_method = getattr(self.session, method.lower())
        if self.oauth_token_provider is None:
            return request_method(url, **kwargs)

        access_token = self.oauth_token_provider.get_token()
        headers = {
            **kwargs.pop("headers", {}),
            "Authorization": f"Bearer {access_token}",
        }
        response = request_method(url, headers=headers, **kwargs)
        if response.status_code != 401:
            return response

        response.close()
        access_token = self.oauth_token_provider.refresh_after_unauthorized(
            access_token
        )
        retry_headers = {
            **headers,
            "Authorization": f"Bearer {access_token}",
        }
        return request_method(url, headers=retry_headers, **kwargs)

    def create_alert(
        self, entity: str, entity_type: str, tags: list[str] | None = None
    ) -> dict:
        """
        Create an alert in Doppel for the given entity.

        :param entity: The observable value (URL or domain).
        :param entity_type: The Doppel entity type (e.g. "url" or "domain").
        :param tags: Optional list of tags to attach to the alert.
        :return: The created alert as a dict.
        """
        url = f"{self.base_url}/alert"
        payload = {
            "entity": entity,
            "entity_type": entity_type,
            "tags": tags or [],
        }
        self.helper.connector_logger.info(
            "[API] Creating Doppel alert",
            {"url_path": url, "entity": entity, "entity_type": entity_type},
        )
        try:
            response = self._request("POST", url, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, requests.HTTPError) as err:
            raise DoppelClientError(
                f"Failed to create Doppel alert for '{entity}': {err}"
            ) from err

    def request_takedown(self, entity: str, comment: str) -> dict:
        """
        Request a takedown for an existing alert by setting its queue state to "actioned".

        :param entity: The observable value used to identify the alert.
        :param comment: Comment attached to the takedown request.
        :return: The updated alert as a dict.
        """
        url = f"{self.base_url}/alert"
        payload = {
            "queue_state": "actioned",
            "comment": comment,
        }
        self.helper.connector_logger.info(
            "[API] Requesting Doppel takedown",
            {"url_path": url, "entity": entity},
        )
        try:
            response = self._request(
                "PUT",
                url,
                params={"entity": entity},
                json=payload,
                timeout=30,
            )
            response.raise_for_status()
            return response.json() if response.content else {}
        except (requests.RequestException, requests.HTTPError) as err:
            raise DoppelClientError(
                f"Failed to request Doppel takedown for '{entity}': {err}"
            ) from err
