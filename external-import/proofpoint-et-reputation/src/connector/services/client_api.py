import requests
from connector.services.config_variables import ProofpointEtReputationConfig
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout
from urllib3.util.retry import Retry


def _make_session(retries: int = 3, backoff_factor: float = 0.3) -> requests.Session:
    """
    Create a configured `requests.Session` with retry and backoff policies.

    Args:
        retries (int): The maximum number of retries for failed requests. Defaults to 3.
        backoff_factor (float): A factor for calculating the delay between retries. Defaults to 0.3.

    Returns:
        requests.Session: A configured session ready for making HTTP requests.
    """
    session = requests.Session()

    retry = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
    )

    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session


class ProofpointEtReputationClient:
    def __init__(
        self, helper: OpenCTIConnectorHelper, config: ProofpointEtReputationConfig
    ):
        """
        Initialize the Proofpoint ET Reputation Client with necessary configurations

        Args:
            helper (OpenCTIConnectorHelper): An instance of the OpenCTI connector helper for logging and other utilities.
            config (ProofpointEtReputationConfig): Configuration object containing API token and connector settings.

        Returns:
            None
        """
        self.helper = helper
        self.config = config
        self.base_url = "https://rules.emergingthreatspro.com/"

    def _build_query_request(self, reputation_list_entity: str) -> requests.Request:
        """
         Constructs the full URL for an API request, including the path and query parameters.

         This method takes the provided API endpoint path and optional query parameters,
         constructs a complete URL, and prepares the request for sending. The request is
         then returned as a `PreparedRequest` object, which can be sent using the `session`.

         The method combines the `base_url`,`extra_api_token`, the `path`, and any query parameters provided to build a
         complete API request and returns a prepared request ready to be executed.

        Args:
             reputation_list_entity (str): The entity type for which reputation data is requested

         Returns:
             requests.Request: A `requests.Request` object configured for the query.
        """
        try:
            return requests.Request(
                "GET",
                f"{self.base_url}{self.config.extra_api_token}/reputation/{reputation_list_entity}.json",
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR-API] Error occurred while building the query request.",
                {"error": str(e)},
            )
            raise ValueError("Failed to build the query request due to an error.")

    def _fetch_data(self, reputation_list_entity: str) -> dict:
        """
        Fetch reputation data for a specific collection from the ProofPoint ET Reputation API.

        This method sends an HTTP GET request to retrieve reputation data for the specified collection.
        It handles various error scenarios, including retries, timeouts, and connection issues.

        Args:
            reputation_list_entity (str): The entity type to query ("iprepdata" or "domainrepdata").

        Returns:
            dict: The reputation data as a dictionary if the request is successful, or an error dictionary with
            details about the failure.
        """
        try:
            with _make_session() as session:
                build_query_request = self._build_query_request(reputation_list_entity)
                prepared_request = session.prepare_request(build_query_request)
                response = session.send(prepared_request)
                response.raise_for_status()
                results = response.json()
                return results

        except RetryError as err:
            message = "[CONNECTOR-API] A retry error occurred during data recovery, maximum retries exceeded for url"
            return {"error": str(err), "message": message}

        except HTTPError as err:
            message = "[CONNECTOR-API] A http error occurred during data recovery"
            return {"error": str(err), "message": message}

        except Timeout as err:
            message = (
                "[CONNECTOR-API] A timeout error has occurred during data recovery"
            )
            return {"error": str(err), "message": message}

        except ConnectionError as err:
            message = "[CONNECTOR-API] A connection error occurred during data recovery"
            return {"error": str(err), "message": message}

        except Exception as err:
            message = "[CONNECTOR-API] An unexpected error occurred during the recovery of all data"
            return {"error": str(err), "message": message}

    def proofpoint_get_ips_reputation(self, reputation_list: str) -> dict:
        """
        Retrieve IP reputation data from the ProofPoint ET Reputation API.

        Args:
            reputation_list (str): The identifier of the IP reputation list to query.

        Returns:
            dict: The IP reputation data as a dictionary, or an error dictionary if the request fails.
        """
        return self._fetch_data(reputation_list)

    def proofpoint_get_domains_reputation(self, reputation_list: str) -> dict:
        """
        Retrieve domain reputation data from the ProofPoint ET Reputation API.

        Args:
            reputation_list (str): The identifier of the domain reputation list to query.

        Returns:
            dict: The domain reputation data as a dictionary, or an error dictionary if the request fails.
        """
        return self._fetch_data(reputation_list)
