import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout
from urllib3.util.retry import Retry


def make_session(api_token, retries: int = 3, backoff_factor: float = 0.3) -> requests.Session:
    """Create a requests session with retries and backoff."""
    session = requests.Session()
    session.headers.update(
        {"Authorization": f"Bearer {api_token}"}
    )

    retry = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
    )

    adapter = requests.adapters.HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session

class ProofpointEtReputationClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.base_url = "https://rules.emergingthreatspro.com/"

    def build_query_request(self, reputation_list_entity: str) -> requests:
        """
        Constructs the full URL for an API request, including the path and query parameters.

        This method takes the provided API endpoint path and optional query parameters,
        constructs a complete URL, and prepares the request for sending. The request is
        then returned as a `PreparedRequest` object, which can be sent using the `session`.

        The method combines the `base_url`, the `path`, and any query parameters provided to build a complete API
        request and returns a prepared request ready to be executed.

        :param reputation_list_entity:

        :return: A `requests.PreparedRequest` object, which is a fully constructed and prepared request
                 that can be sent using `requests.Session`.
        """
        try:
            return requests.Request(
                "GET",
                f"{self.base_url}{self.config.api_token}/reputation/{reputation_list_entity}.json"
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR-API] Error occurred while building the query request.", {"error": str(e)}
            )
            raise ValueError("Failed to build the query request due to an error.")

    def fetch_data(self, reputation_list_entity) -> dict | None:
        try:
            with make_session(self.config.api_token) as session:
                build_query_request = self.build_query_request(reputation_list_entity)
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
            message = "[CONNECTOR-API] A timeout error has occurred during data recovery"
            return {"error": str(err), "message": message}

        except ConnectionError as err:
            message = "[CONNECTOR-API] A connection error occurred during data recovery"
            return {"error": str(err), "message": message}

        except Exception as err:
            message = "[CONNECTOR-API] An unexpected error occurred during the recovery of all data"
            return {"error": str(err), "message": message}

    def proofpoint_get_ips_reputation(self, reputation_list) -> dict | None:
        return self.fetch_data(reputation_list)

    def proofpoint_get_domains_reputation(self, reputation_list) -> dict | None:
        return self.fetch_data(reputation_list)
