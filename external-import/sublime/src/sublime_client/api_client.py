import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class SublimeClient:
    def __init__(self, helper: OpenCTIConnectorHelper, base_url: HttpUrl, api_key: str):
        """
        Initialize the client with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `api_key`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            base_url (str): The external API base URL.
            api_key (str): The API key to authenticate the connector to the external API.
        """
        self.helper = helper
        self.base_url = base_url
        headers = {
            "Authorization": f"Bearer {api_key.get_secret_value()}",
            "Accept": "application/json",
            "User-Agent": "OpenCTI-SublimeConnector/1.0",
        }
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params, timeout=30)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_group_ids(self, start_time, end_time) -> list:
        """
        Fetch list of flagged group IDs within time range from Sublime API.
        Args:
            start_time (str): ISO 8601 timestamp for range start
            end_time (str): ISO 8601 timestamp for range end
        Returns:
            list: List of group canonical IDs that are flagged
        """
        try:
            params = {
                "created_at__gte": start_time,
                "created_at__lt": end_time,
                "fetch_all_ids": True,
                "stats_limit": 100000,
                "flagged__eq": True,
            }

            api_url = self.base_url.unicode_string().rstrip("/")
            if not api_url.endswith("/v1"):
                api_url = api_url + "/v1"

            full_url = "{}/messages/groups".format(api_url)

            self.helper.log_debug(
                "Fetch time range: {} to {}".format(start_time, end_time)
            )
            self.helper.log_debug(
                "API request: {} with {} parameters".format(full_url, len(params))
            )

            response = self._request_data(api_url=full_url, params=params)

            if not response.ok:
                self.helper.log_error(
                    "[!] API request failed - Status: {}, Response: {}".format(
                        response.status_code, response.text
                    )
                )
                raise Exception(
                    "API request failed: {} {}".format(
                        response.status_code, response.text
                    )
                )

            data = response.json()
            group_ids = data.get("all_group_canonical_ids") or []
            return group_ids

        except Exception as err:
            self.helper.connector_logger.error(err)

    def get_single_group(self, group_id: str) -> dict:
        """
        Fetch individual message group by ID from Sublime API.
        Args:
            group_id (str): Canonical ID of the message group to fetch
        Returns:
            dict: Message group data dictionary, or None if fetch fails
        """
        try:
            api_url = self.base_url.unicode_string().rstrip("/")
            if not api_url.endswith("/v1"):
                api_url = api_url + "/v1"

            full_url = "{}/messages/groups/{}".format(api_url, group_id)

            self.helper.log_debug("Fetching group: {}".format(group_id))

            response = self._request_data(api_url=full_url)

            # Enable if you need in depth troubleshooting
            # self.helper.log_debug("DEBUG: Response body: {}".format(response.text))

            if not response.ok:
                self.helper.log_warning(
                    "[!] Failed to fetch group {}: {} {}".format(
                        group_id, response.status_code, response.text
                    )
                )
                return None

            data = response.json()

            # Map API field name to code expectation (data_model -> MDM)
            if "data_model" in data and "MDM" not in data:
                data["MDM"] = data["data_model"]

            return data
        except Exception as err:
            self.helper.connector_logger.error(err)
