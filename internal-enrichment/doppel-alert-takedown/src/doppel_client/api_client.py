import requests
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
        api_key: str,
        user_api_key: str,
    ):
        """
        Initialize the client with necessary configuration.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            base_url (HttpUrl): The Doppel API base URL.
            api_key (str): The Doppel API key (`x-api-key` header).
            user_api_key (str): The Doppel user API key (`x-user-api-key` header).
        """
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "x-user-api-key": user_api_key,
            }
        )

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
        url = f"{self.base_url}/v1/alert"
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
            response = self.session.post(url, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as err:
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
        url = f"{self.base_url}/v1/alert"
        payload = {
            "queue_state": "actioned",
            "comment": comment,
        }
        self.helper.connector_logger.info(
            "[API] Requesting Doppel takedown",
            {"url_path": url, "entity": entity},
        )
        try:
            response = self.session.put(
                url, params={"entity": entity}, json=payload, timeout=30
            )
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.RequestException as err:
            raise DoppelClientError(
                f"Failed to request Doppel takedown for '{entity}': {err}"
            ) from err
