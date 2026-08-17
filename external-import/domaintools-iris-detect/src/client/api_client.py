import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class DomainToolsClient:
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
        # Define headers in session and update when needed
        headers = {"x-api-key": api_key}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        params = params or {}
        params["app_partner"] = "OpenCTI"
        params["app_name"] = "Iris Detect"
        params["app_version"] = "1.0"
        try:

            response = self.session.get(api_url, params=params, timeout=60)
            self.helper.connector_logger.info(
                "[API] HTTP GET Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": api_url, "error": str(err)}
            )
            return None

    def get_entities(self, dt_parameters: dict | None = None) -> tuple[dict, list]:
        """Fetch Iris Detect results from the DomainTools Iris Detect API.
        Args:
            dt_parameters: Optional query parameters.
        Returns:
            A tuple of (monitor_id_to_term, results) from the API.
        """
        dt_parameters = dt_parameters or {}

        # DomainTools Iris Detect - Get Monitor IDs and Terms
        monitor_id_term: dict = {}
        response = self._request_data(
            f"{str(self.base_url).rstrip('/')}/monitors/", params=None
        )

        if response is None:
            return monitor_id_term, []

        data = response.json()
        for t in data.get("monitors", []):
            monitor_id_term[t["id"]] = t["term"]

        # DomainTools Iris Detect - Get Data
        result_data = list()
        try:
            # ===========================
            # === Add your code below ===
            # ===========================
            limit = 50
            offset = 0

            while True:
                dt_parameters["offset"] = offset
                dt_parameters["limit"] = limit

                response = self._request_data(
                    f"{str(self.base_url).rstrip('/')}/domains/new/",
                    params=dt_parameters,
                )

                if response is None:
                    break

                json_response = response.json()
                results_total = json_response.get("total_count", 0)
                result_data.extend(json_response.get("watchlist_domains", []))

                if dt_parameters.get("preview"):
                    break  # if preview is true, only pull the first page of data since it is just for testing purposes.
                # if offset > results_total:
                if offset + limit >= results_total:
                    break

                offset += limit
            # ===========================
            # === Add your code above ===
            # ===========================

            # raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)

        return monitor_id_term, result_data
