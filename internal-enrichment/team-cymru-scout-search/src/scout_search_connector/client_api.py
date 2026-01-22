import requests


class ScoutSearchConnectorClient:
    """
    Handles external API calls to Scout Search Connector API
    and returns STIX 2.1 bundles.
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

        if not self.config.api_base_url or not self.config.api_key:
            raise ValueError("API base URL and API key are required")

        self.helper.connector_logger.info(
            "[ScoutSearchConnector] Client initialized",
            {"api_url": self.config.api_base_url},
        )

    def _request_data(self, endpoint: str, params: dict = None) -> dict:
        """
        Make HTTP request to the API endpoint
        """
        try:
            # Log the request
            self.helper.connector_logger.info(
                "[ScoutSearchConnector] Making API request",
                {"endpoint": endpoint, "params": params},
            )

            response = self.session.get(endpoint, params=params, timeout=1000)

            # Log response status
            self.helper.connector_logger.debug(
                "[ScoutSearchConnector] API response received",
                {"status_code": response.status_code, "endpoint": endpoint},
            )

            response.raise_for_status()

            if response.status_code == 204 or not response.content:
                self.helper.connector_logger.info(
                    "[ScoutSearchConnector] Empty response received", {"endpoint": endpoint}
                )
                return {}

            result = response.json()
            self.helper.connector_logger.info(
                "[ScoutSearchConnector] API request successful",
                {"endpoint": endpoint, "data_received": bool(result)},
            )
            return result

        except requests.exceptions.Timeout:
            self.helper.connector_logger.error(
                "[ScoutSearchConnector] API request timeout",
                {"endpoint": endpoint, "timeout": 1000},
            )
            return {}
        except requests.exceptions.HTTPError as e:
            self.helper.connector_logger.error(
                "[ScoutSearchConnector] HTTP error",
                {
                    "endpoint": endpoint,
                    "status_code": e.response.status_code,
                    "error": str(e),
                },
            )
            return {}
        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "[ScoutSearchConnector] API request failed",
                {"endpoint": endpoint, "error": str(e)},
            )
            return {}
        except Exception as e:
            self.helper.connector_logger.error(
                "[ScoutSearchConnector] Unexpected error",
                {"endpoint": endpoint, "error": str(e)},
            )
            return {}

    def search_query(self, query: str) -> dict:
        """
        Search for query intelligence
        Endpoint: GET /search?query={search_query}
        """
        endpoint = f"{self.config.api_base_url}/search"
        self.helper.connector_logger.debug(
            "[ScoutSearchConnector] Search query endpoint",
            {"endpoint": endpoint, "query": query},
        )
        days = self.config.search_interval
        return self._request_data(endpoint, params={"query": query, "days": days})

    def get_entity(self, observable_type: str, pattern: str) -> dict:
        """
        Fetch the STIX bundle for the given observable.
        Supports: Indicator
        """
        try:
            self.helper.connector_logger.info(
                "[ScoutSearchConnector] Processing observable",
                {"type": observable_type, "value": pattern},
            )

            if observable_type == "Indicator":
                return self.search_query(pattern)

            # No else needed here
            self.helper.connector_logger.warning(
                "[ScoutSearchConnector] Unsupported observable type",
                {"observable_type": observable_type, "value": pattern},
            )
            return {}

        except Exception as e:
            self.helper.connector_logger.error(
                "[ScoutSearchConnector] Error processing entity",
                {"type": observable_type, "value": pattern, "error": str(e)},
            )
            return {}
