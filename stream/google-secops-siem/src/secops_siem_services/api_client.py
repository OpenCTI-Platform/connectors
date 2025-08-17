import time
from typing import Any, List, Optional

from google.auth.transport import requests as ChronicleRequests
from google.oauth2 import service_account
from requests import Response
from requests.exceptions import ConnectionError, HTTPError, Timeout

SECOPS_SIEM_API_BASE_URL = "https://chronicle.googleapis.com"
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class SecOpsEntitiesClient:
    def __init__(self, helper, config):
        """
        Init Chronicle API client.
        :param helper: Connector's helper from PyCTI
        :param config: Connector's config
        """
        self.helper = helper
        self.config = config

        # Define auth in session and config retries
        self.chronicle_http_session = self.init_session()

        self.base_url_with_region = self.regionalized_url(
            SECOPS_SIEM_API_BASE_URL, self.config.chronicle_project_region
        )
        parent = (
            f"projects/{self.config.chronicle_project_id}/"
            f"locations/{self.config.chronicle_project_region}/"
            f"instances/{self.config.chronicle_project_instance}"
        )
        self.url = f"{self.base_url_with_region}/v1alpha/{parent}/entities:import"

    def init_session(self) -> ChronicleRequests.AuthorizedSession:
        """
        Initializes an authorized session for interacting with the Chronicle API using a service account.

        This method leverages the Google Python library to handle authentication and token management,
        including retry strategies for specific status codes. It ensures that credentials are refreshed
        automatically when expired (e.g., for a 401 Unauthorized error).

        :return:
            An instance of `ChronicleRequests.AuthorizedSession`, ready for authenticated API calls.

        :raises:
            Raises any exceptions encountered during the session initialization process, such as:

            - ValueError: If the service account information is invalid.
            - google.auth.exceptions.GoogleAuthError: For authentication-specific errors.
            - Exception: For unexpected errors.

        Error logging:
            All errors are logged with `self.helper.connector_logger.error` to ensure traceability.
        """
        service_account_info = {
            "type": "service_account",
            "project_id": self.config.chronicle_project_id,
            "private_key": self.config.chronicle_private_key,
            "private_key_id": self.config.chronicle_private_key_id,
            "client_email": self.config.chronicle_client_email,
            "client_id": self.config.chronicle_client_id,
            "auth_uri": self.config.chronicle_auth_uri,
            "token_uri": self.config.chronicle_token_uri,
            "auth_provider_x509_cert_url": self.config.chronicle_auth_provider_cert,
            "client_x509_cert_url": self.config.chronicle_client_cert_url,
        }

        try:
            credentials = service_account.Credentials.from_service_account_info(
                info=service_account_info, scopes=SCOPES
            )
            # Create a Chronicle session with retries when token expired
            return ChronicleRequests.AuthorizedSession(
                credentials=credentials,
                refresh_status_codes=[401],
                max_refresh_attempts=3,
            )
        except Exception as err:
            self.helper.connector_logger.error(
                "[API] Error while authenticating : ",
                {"error": str(err)},
            )
            raise err

    @staticmethod
    def regionalized_url(base_url: str, region: str) -> str:
        """
        Constructs a regionalized URL for the Chronicle API, always ensuring a region prefix is included.

        This function guarantees that the base URL includes the region code as a prefix to the hostname,
        regardless of whether the region is "us" or any other. It first checks if the URL already contains
        the region prefix and avoids duplicating it. This method is recommended for v1alpha samples.

        :param base_url:
            The default API URL without a region-specific prefix.
        :param region:
            The target region for the API request. The region code will always be prepended to the hostname
            in the base URL, even for "us".

        :return:
            A string representing the modified regionalized URL with the region prefix.

        Example Usage:
            base_url = "https://api.chronicle.security"
            region = "apac"

            regionalized_url = regionalized_url(base_url, region)
            # Result: "https://apac-api.chronicle.security"

        Logic:
            - Checks if the `base_url` already starts with the region prefix.
            - If not, prepends the region code followed by a hyphen to the hostname.
        """
        if not base_url.startswith(f"https://{region}-"):
            base_url = base_url.replace("https://", f"https://{region}-")
        return base_url

    @staticmethod
    def backoff_delay(backoff_factor: float, attempts: int) -> float:
        """
        Calculate the delay for a retry attempt using an exponential backoff algorithm.

        :param backoff_factor: float, the base delay time in seconds. This value is
                               multiplied by the exponential factor to determine the delay.
        :param attempts: int, the number of retry attempts already made (1-based).
        :return: float, the calculated delay time in seconds.

        Example:
            For `backoff_factor` = 0.5 and `attempts` = 3, the delay is calculated as:
            delay = 0.5 * (2 ** (3 - 1)) = 0.5 * 4 = 2.0 seconds.
        """
        delay = backoff_factor * (2 ** (attempts - 1))
        return delay

    def _send_request(
        self,
        entities: List[Any],
        backoff_factor: int = 30,
        total: int = 4,
        retry_status_forcelist: Optional[List[int]] = None,
    ) -> Optional[Response]:
        """
        Send a POST request with retry logic and exponential backoff for specified HTTP statuses.

        :param entities: List[Any], the list of entities to include in the request body.
        :param backoff_factor: int, the base delay factor (in seconds) for exponential backoff. Defaults to 10.
        :param total: int, the maximum number of retry attempts. Defaults to 4.
        :param retry_status_forcelist: Optional[List[int]], a list of HTTP status codes that should trigger retries.
                                 Defaults to an empty list.
        :return: Optional[Response], the HTTP response object from the final successful request, or the last
                 response after all retries fail.

        Retry Logic:
            - If the response status code matches any in `status_forcelist`, the method retries the request
              after a delay calculated using the `backoff_delay` function.
            - Delays between retries increase exponentially, and logs are generated for each retry attempt.

        Error Handling:
            - Tracks and logs responses with status codes in `status_forcelist` during retries.
            - Returns the most recent response (`last_response`) if all retries fail.
        """
        if retry_status_forcelist is None:
            retry_status_forcelist = []
        last_response: Optional[Response] = None

        # Implement retry logic
        for attempt in range(total):

            body = {"inline_source": {"entities": entities, "log_type": "OPENCTI"}}
            response = self.chronicle_http_session.request(
                method="POST", url=self.url, json=body
            )

            if response.status_code in retry_status_forcelist:
                # Implement backoff
                delay = self.backoff_delay(backoff_factor, attempt)
                time.sleep(delay)

                self.helper.connector_logger.info(
                    "[API] Request failed. Retrying in a few seconds",
                    {"status_code": response.status_code, "delay_in_seconds": delay},
                )

                # Track the last response
                last_response = response
                continue
            else:
                return response

        # Return the last response after all retries fail
        return last_response

    def ingest(self, entities: list):
        """
        Ingests a list of entities by making an HTTP POST request to the configured Chronicle URL.

        This method constructs a request payload with the provided entities and sends it to the Chronicle SIEM platform.
        It includes robust error handling to log and manage common issues like HTTP errors, timeouts, and connection errors.

        :param entities:
            A list of entities to be ingested. Each entity is expected to be a dictionary containing the relevant
            data required by the Chronicle API.

        :return:
            A boolean indicating the success of the operation (True if the ingestion was successful and the API
            returned a 200 status code, None otherwise).

        :raises:
            No explicit exceptions are raised directly from this method. Errors are caught, logged, and result
            in a return value of None. These include:

            - RetryError: If maximum retries are exceeded during the request.
            - HTTPError: For HTTP errors (e.g., 4xx, 5xx responses).
            - Timeout: If the request times out.
            - ConnectionError: For network-related connection issues.
            - Exception: For any other unexpected errors.

        Error logging:
            Errors are logged using `self.helper.connector_logger` with appropriate log levels and error details.
        """
        try:

            response = self._send_request(
                entities=entities, retry_status_forcelist=[429]
            )

            if response.status_code == 200:
                # Google returns True for response.ok when the request is successful
                return response.ok
            else:
                response.raise_for_status()

        except HTTPError as err:
            self.helper.connector_logger.error(
                "An HTTP error occurred during data handling",
                {"http_error": str(err)},
            )
            return None

        except Timeout as err:
            self.helper.connector_logger.error(
                "A timeout error has occurred during data handling",
                {"timeout_error": str(err)},
            )
            return None

        except ConnectionError as err:
            self.helper.connector_logger.error(
                "A connection error occurred during data handling",
                {"connection_error": str(err)},
            )
            return None

        except Exception as err:
            self.helper.connector_logger.error(
                "An unexpected error occurred during data handling",
                {"error": str(err)},
            )
            return None
