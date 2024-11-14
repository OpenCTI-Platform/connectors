from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout
from urllib3.util.retry import Retry


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.base_url = "https://api.riskiq.net/pt"

        # Define auth in session and config retries
        self.session = requests.Session()
        self.session.auth = self._get_basic_auth()
        self.retries_builder()

    def _get_basic_auth(self) -> HTTPBasicAuth:
        """
        Retrieves the HTTP Basic Authentication credentials for authenticating API requests.

        This method uses the `riskiq_username` and `riskiq_key` from the configuration to
        create an instance of `HTTPBasicAuth` which is used to authenticate requests
        to the Riskiq API.

        :return: An instance of `HTTPBasicAuth` containing the username and API key.
        """
        return HTTPBasicAuth(self.config.riskiq_username, self.config.riskiq_key)

    def build_query_request(self, path: str, params: dict = None) -> requests:
        """
        Constructs the full URL for an API request, including the path and query parameters.

        This method takes the provided API endpoint path and optional query parameters,
        constructs a complete URL, and prepares the request for sending. The request is
        then returned as a `PreparedRequest` object, which can be sent using the `session`.

        The method combines the `base_url`, the `path`, and any query parameters provided to build a complete API
        request and returns a prepared request ready to be executed.

        :param path: The specific endpoint path of the API (e.g., '/v2/dns/passive').
            This should be appended to the base URL to form the complete API URL.

        :param params: A dictionary containing query parameters to include in the request URL.
            If no parameters are provided, the default is `None`.

        :return: A `requests.PreparedRequest` object, which is a fully constructed and prepared request
                 that can be sent using `requests.Session`.
        """
        try:

            request = requests.Request("GET", f"{self.base_url}{path}", params=params)
            return self.session.prepare_request(request)

        except Exception as e:
            self.helper.connector_logger.error(
                "Error occurred while building the query request.", {"error": str(e)}
            )
            raise ValueError("Failed to build the query request due to an error.")

    def retries_builder(self) -> None:
        """
        Configures the session's retry strategy for API requests.

        Sets up the session to retry requests upon encountering specific HTTP status codes (429) using
        exponential backoff (2). The retry mechanism will be applied for both HTTP and HTTPS requests.
        This function uses the `Retry` and `HTTPAdapter` classes from the `requests.adapters` module.

        - Retries up to 5 times with an increasing delay between attempts (max: 64s).
        """
        retry_strategy = Retry(
            total=5, backoff_factor=2, status_forcelist=[429], raise_on_status=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

    def fetch_data(self, request: requests.PreparedRequest) -> dict | None:
        """
        Sends a request to the API and retrieves the response data.

        This method takes a prepared HTTP request, sends it using the session, and checks if the response is successful.
        If the request is successful, it parses the response as JSON and returns the resulting data.
        If there is an error during the request, the method logs the error and returns `None`.

        :param request: A `requests.PreparedRequest` object that contains the HTTPrequest details to be sent to the API.

        :return:
            - A dictionary containing the JSON-parsed response data from the API if the request is successful.
            - `None` if there is an error during the request or if the request fails.
        """
        try:
            response = self.session.send(request)
            response.raise_for_status()
            results = response.json()
            return results

        except RetryError as err:
            self.helper.connector_logger.error(
                "A retry error occurred during data recovery, maximum retries exceeded for url",
                {"retry_error": str(err)},
            )
            return None

        except HTTPError as err:
            self.helper.connector_logger.error(
                "A http error occurred during data recovery",
                {"http_error": str(err)},
            )
            return None

        except Timeout as err:
            self.helper.connector_logger.error(
                "A timeout error has occurred during data recovery",
                {"timeout_error": str(err)},
            )
            return None

        except ConnectionError as err:
            self.helper.connector_logger.error(
                "A connection error occurred during data recovery",
                {"connection_error": str(err)},
            )
            return None

        except Exception as err:
            self.helper.connector_logger.error(
                "An unexpected error occurred during the recovery of all data",
                {"error": str(err)},
            )
            return None

    def _check_quota_reached(self) -> bool:
        """
        Checks the user's current quota status based on the provided query and compares it against the license limits.

        This method sends a request to the '/v2/account/quota' endpoint using the given query to fetch the user's quota
        information. It compares the current usage of the `searchApi` resource with its defined limits. If the current
        usage exceeds or matches the quota limit, it logs an informational message indicating that the user must wait
        for the next reset. If the quota is within the limits, it logs a different message indicating that the quota is
        still available.

        :return:
            - `True` if the user's `searchApi` quota has been reached or if there was an error retrieving quota data.
            - `False` if the user's `searchApi` quota has not yet been reached.
        """
        url_prepared = self.build_query_request("/v2/account/quota")
        results = self.fetch_data(url_prepared)

        if results is None:
            return True

        user_data = results.get("user")
        if user_data is None:
            self.helper.connector_logger.error(
                "An error was encountered while retrieving user quota information"
            )
            return True

        license_currents = user_data.get("licenseCounts")
        license_limits = user_data.get("licenseLimits")
        if license_currents is None or license_limits is None:
            self.helper.connector_logger.error(
                "An error was encountered while retrieving user quota information",
                {
                    "next_reset": user_data.get("next_reset"),
                },
            )
            return True

        license_currents_search_api = license_currents.get("searchApi")
        license_limits_search_api = license_limits.get("searchApi")
        if license_currents_search_api == license_limits_search_api:
            self.helper.connector_logger.info(
                "The user's quota has been reached, you will have to wait for the next reset",
                {
                    "current_quota": license_currents_search_api,
                    "limits_quota": license_limits_search_api,
                    "next_reset": user_data.get("next_reset"),
                },
            )
            return True
        else:
            self.helper.connector_logger.info(
                "The user's quota has not yet been reached",
                {
                    "current_quota": license_currents_search_api,
                    "limits_quota": license_limits_search_api,
                    "next_reset": user_data.get("next_reset"),
                },
            )
            return False

    def passivetotal_get_observables(self, stix_entity_value: str) -> dict | None:
        """
        Retrieves the Passive DNS related observables from the PassiveTotal API based on the provided entity value.

        This method first checks if the user's quota for the `searchApi` has been reached.
        If the quota has been reached, it returns `None` and does not proceed with the query.
        If the quota has not been reached, it constructs a request to the PassiveTotal API endpoint, incorporating
        "formatted_date_iso_format" configured to filter the results based on the calculated duration specified in the
        "convert_to_duration_period" method.

        The method sends a GET request to the PassiveTotal API with the constructed parameters and returns the data.

        :param stix_entity_value: A string representing the search value for which data is being retrieved.
                                  This can be a Domain Name or an IP Address.

        :return:
            - A dictionary containing the passive DNS results from the PassiveTotal API if the quota is available and
            the request is successful.
            - `None` if the user's quota has been reached or if there is an issue with the request.
        """

        is_quota_reached = self._check_quota_reached()
        if is_quota_reached:
            return None

        new_date = datetime.now() - self.config.import_last_seen_time_window
        formatted_date_iso_format = new_date.isoformat(timespec="seconds").replace(
            "T", " "
        )

        params = {
            "query": stix_entity_value,
            "start": formatted_date_iso_format,
        }

        url_prepared = self.build_query_request("/v2/dns/passive", params)
        return self.fetch_data(url_prepared)
