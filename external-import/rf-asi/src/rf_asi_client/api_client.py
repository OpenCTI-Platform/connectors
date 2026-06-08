import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class RfAsiClient:
    def __init__(self, helper: OpenCTIConnectorHelper, base_url: HttpUrl, api_key: str):
        """
        Initialize the client with necessary configuration.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            base_url (HttpUrl): The external API base URL.
            api_key (str): The API key to authenticate the connector to the external API.
        """
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")
        headers = {
            "accept": "application/json",
            "apikey": api_key,
        }
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(
        self, api_url: str, params: dict | None = None
    ) -> requests.Response:
        """
        Internal method to handle API GET requests.

        :param api_url: Full URL for the API endpoint.
        :param params: Optional query parameters.
        :return: HTTP response on success.
        :raises requests.RequestException: On non-2xx responses or transport errors.
        """
        self.helper.connector_logger.info(
            "[API] HTTP Get Request to endpoint", {"url_path": api_url}
        )
        response = self.session.get(api_url, params=params, timeout=30)
        response.raise_for_status()
        return response

    @staticmethod
    def _parse_list_response(payload: dict) -> tuple[list[dict], str | None]:
        """
        Extract exposure items and the next pagination cursor from a list response.

        :param payload: JSON body from the exposures list endpoint.
        :return: Tuple of exposure summary items and optional next cursor.
        """
        data = payload.get("data") or []
        pagination = (payload.get("meta") or {}).get("pagination") or {}
        next_cursor = pagination.get("next_cursor")
        return data, next_cursor

    def list_exposures(
        self,
        project_id: str,
        limit: int = 100,
        cursor: str | None = None,
        **filters,
    ) -> list[dict]:
        """
        List all exposures for a project, following cursor-based pagination.

        :param project_id: ASI project identifier.
        :param limit: Number of exposures to fetch per page (1-1000).
        :param cursor: Optional starting pagination cursor.
        :param filters: Optional API query filters (e.g. filter_severity_min).
        :return: All exposure summary dicts from the API (signature + asset_count).
        :raises requests.RequestException: If the first page request fails.
        """
        exposures: list[dict] = []
        next_cursor = cursor
        url = f"{self.base_url}/projects/{project_id}/exposures"

        while True:
            params: dict = {"limit": limit, **filters}
            if next_cursor:
                params["cursor"] = next_cursor

            try:
                response = self._request_data(url, params=params)
                page_items, next_cursor = self._parse_list_response(response.json())
                exposures.extend(page_items)
            except requests.RequestException as err:
                self.helper.connector_logger.error(
                    "[API] Error while fetching exposures",
                    {"url_path": url, "error": str(err)},
                )
                if exposures:
                    self.helper.connector_logger.warning(
                        "[API] Returning partial exposure results after pagination failure",
                        {"collected_count": len(exposures)},
                    )
                    return exposures
                raise

            if not next_cursor:
                break

        return exposures
