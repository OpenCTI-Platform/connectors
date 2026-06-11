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

    @staticmethod
    def _parse_assets_response(payload: dict) -> tuple[dict, list[dict], str | None]:
        """
        Extract signature, asset exposures, and next cursor from a get-assets response.

        :param payload: JSON body from the exposure assets endpoint.
        :return: Tuple of signature dict, asset exposure items, and optional next cursor.
        """
        data = payload.get("data") or {}
        if not isinstance(data, dict):
            data = {}
        signature = data.get("signature") or {}
        asset_exposures = data.get("asset_exposures") or []
        pagination = (payload.get("meta") or {}).get("pagination") or {}
        next_cursor = pagination.get("next_cursor")
        return signature, asset_exposures, next_cursor

    def list_exposures_page(
        self,
        project_id: str,
        limit: int = 100,
        cursor: str | None = None,
        **filters,
    ) -> tuple[list[dict], str | None]:
        """
        Fetch one page of exposures for a project.

        :param project_id: ASI project identifier.
        :param limit: Number of exposures to fetch per page (1-1000).
        :param cursor: Optional pagination cursor.
        :param filters: Optional API query filters (e.g. filter_severity_min).
        :return: Tuple of exposure summary items and optional next cursor.
        :raises requests.RequestException: On non-2xx responses or transport errors.
        """
        url = f"{self.base_url}/projects/{project_id}/exposures"
        params: dict = {"limit": limit, **filters}
        if cursor:
            params["cursor"] = cursor

        response = self._request_data(url, params=params)
        return self._parse_list_response(response.json())

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
            try:
                page_items, next_cursor = self.list_exposures_page(
                    project_id,
                    limit=limit,
                    cursor=next_cursor,
                    **filters,
                )
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

    def list_exposures_batch(
        self,
        project_id: str,
        *,
        page_limit: int,
        run_limit: int,
        cursor: str | None = None,
        **filters,
    ) -> tuple[list[dict], str | None]:
        """
        Fetch up to ``run_limit`` exposures, following cursor-based pagination.

        :param project_id: ASI project identifier.
        :param page_limit: Number of exposures to fetch per API page.
        :param run_limit: Maximum exposures to collect in this batch.
        :param cursor: Optional starting pagination cursor.
        :param filters: Optional API query filters (e.g. filter_severity_min).
        :return: Tuple of exposure summary items and optional next cursor for resuming.
        :raises requests.RequestException: If the first page request fails.
        """
        exposures: list[dict] = []
        next_cursor = cursor
        url = f"{self.base_url}/projects/{project_id}/exposures"

        while len(exposures) < run_limit:
            remaining = run_limit - len(exposures)
            try:
                page_items, next_cursor = self.list_exposures_page(
                    project_id,
                    limit=min(page_limit, remaining),
                    cursor=next_cursor,
                    **filters,
                )
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
                    if len(exposures) > run_limit:
                        exposures = exposures[:run_limit]
                    return exposures, next_cursor
                raise

            if len(exposures) >= run_limit:
                break
            if not next_cursor:
                break

        if len(exposures) > run_limit:
            exposures = exposures[:run_limit]

        return exposures, next_cursor

    def get_exposure_assets_page(
        self,
        project_id: str,
        signature_id: str,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[dict, list[dict], str | None]:
        """
        Fetch one page of assets for an exposure signature.

        :param project_id: ASI project identifier.
        :param signature_id: Exposure signature identifier.
        :param limit: Number of assets to fetch per page (1-1000).
        :param cursor: Optional pagination cursor.
        :return: Tuple of signature dict, asset exposure items, and optional next cursor.
        :raises requests.RequestException: On non-2xx responses or transport errors.
        """
        url = f"{self.base_url}/projects/{project_id}/exposures/{signature_id}"
        params: dict = {"limit": limit}
        if cursor:
            params["cursor"] = cursor

        response = self._request_data(url, params=params)
        return self._parse_assets_response(response.json())

    def get_exposure_assets(
        self,
        project_id: str,
        signature_id: str,
        limit: int = 100,
        cursor: str | None = None,
    ) -> dict:
        """
        Fetch all assets for an exposure signature, following cursor-based pagination.

        :param project_id: ASI project identifier.
        :param signature_id: Exposure signature identifier.
        :param limit: Number of assets to fetch per page (1-1000).
        :param cursor: Optional starting pagination cursor.
        :return: Dict with ``signature`` and accumulated ``asset_exposures`` items.
        :raises requests.RequestException: If the first page request fails.
        """
        signature: dict = {}
        asset_exposures: list[dict] = []
        next_cursor = cursor
        url = f"{self.base_url}/projects/{project_id}/exposures/{signature_id}"

        while True:
            try:
                page_signature, page_assets, next_cursor = (
                    self.get_exposure_assets_page(
                        project_id,
                        signature_id,
                        limit=limit,
                        cursor=next_cursor,
                    )
                )
                if page_signature:
                    signature = page_signature
                asset_exposures.extend(page_assets)
            except requests.RequestException as err:
                self.helper.connector_logger.error(
                    "[API] Error while fetching exposure assets",
                    {
                        "url_path": url,
                        "signature_id": signature_id,
                        "error": str(err),
                    },
                )
                if signature or asset_exposures:
                    self.helper.connector_logger.warning(
                        "[API] Returning partial exposure asset results after pagination failure",
                        {
                            "signature_id": signature_id,
                            "collected_count": len(asset_exposures),
                        },
                    )
                    return {
                        "signature": signature,
                        "asset_exposures": asset_exposures,
                    }
                raise

            if not next_cursor:
                break

        return {"signature": signature, "asset_exposures": asset_exposures}
