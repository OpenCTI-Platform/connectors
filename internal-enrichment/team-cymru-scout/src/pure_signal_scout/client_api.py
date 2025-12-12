import requests


class PureSignalScoutClient:
    """
    Handles external API calls to Pure Signal Scout API
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
            "[PureSignalScout] Client initialized",
            {"api_url": self.config.api_base_url},
        )

    def _request_data(self, endpoint: str, params: dict = None) -> dict:
        """
        Make HTTP request to the API endpoint
        """
        try:
            # Log the request
            self.helper.connector_logger.info(
                "[PureSignalScout] Making API request",
                {"endpoint": endpoint, "params": params},
            )

            response = self.session.get(endpoint, params=params, timeout=1000)

            # Log response status
            self.helper.connector_logger.debug(
                "[PureSignalScout] API response received",
                {"status_code": response.status_code, "endpoint": endpoint},
            )

            response.raise_for_status()

            if response.status_code == 204 or not response.content:
                self.helper.connector_logger.info(
                    "[PureSignalScout] Empty response received", {"endpoint": endpoint}
                )
                return {}

            result = response.json()
            self.helper.connector_logger.info(
                "[PureSignalScout] API request successful",
                {"endpoint": endpoint, "data_received": bool(result)},
            )
            return result

        except requests.exceptions.Timeout:
            self.helper.connector_logger.error(
                "[PureSignalScout] API request timeout",
                {"endpoint": endpoint, "timeout": 1000},
            )
            return {}
        except requests.exceptions.HTTPError as e:
            self.helper.connector_logger.error(
                "[PureSignalScout] HTTP error",
                {
                    "endpoint": endpoint,
                    "status_code": e.response.status_code,
                    "error": str(e),
                },
            )
            return {}
        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "[PureSignalScout] API request failed",
                {"endpoint": endpoint, "error": str(e)},
            )
            return {}
        except Exception as e:
            self.helper.connector_logger.error(
                "[PureSignalScout] Unexpected error",
                {"endpoint": endpoint, "error": str(e)},
            )
            return {}

    def search_domain(self, domain: str) -> dict:
        """
        Search for domain intelligence
        Endpoint: GET /search?query={search_query}
        """
        endpoint = f"{self.config.api_base_url}/search"
        self.helper.connector_logger.debug(
            "[PureSignalScout] Domain search endpoint",
            {"endpoint": endpoint, "domain": domain},
        )
        return self._request_data(endpoint, params={"query": domain})

    def get_foundation_data(self, ip_address: str) -> dict:
        if not ip_address:
            self.helper.connector_logger.warning(
                "[PureSignalScout] No IPs provided for foundation data"
            )
            return {}

        endpoint = f"{self.config.api_base_url}/ip/foundation"

        self.helper.connector_logger.debug(
            "[PureSignalScout] Foundation data endpoint",
            {"endpoint": endpoint, "ip": ip_address},
        )

        result = self._request_data(endpoint, params={"ips": ip_address})

        if result and isinstance(result, dict):
            return result
        return {}

    def get_entity(self, observable_type: str, observable_value: str) -> dict:
        """
        Fetch the STIX bundle for the given observable.
        Supports: IPv4-Addr, IPv6-Addr, Domain-Name
        """
        try:
            self.helper.connector_logger.info(
                "[PureSignalScout] Processing observable",
                {"type": observable_type, "value": observable_value},
            )

            if observable_type in ["IPv4-Addr", "IPv6-Addr"]:
                return self.get_foundation_data(observable_value)

            if observable_type == "Domain-Name":
                return self.search_domain(observable_value)

            # No else needed here
            self.helper.connector_logger.warning(
                "[PureSignalScout] Unsupported observable type",
                {"observable_type": observable_type, "value": observable_value},
            )
            return {}

        except Exception as e:
            self.helper.connector_logger.error(
                "[PureSignalScout] Error processing entity",
                {"type": observable_type, "value": observable_value, "error": str(e)},
            )
            return {}
