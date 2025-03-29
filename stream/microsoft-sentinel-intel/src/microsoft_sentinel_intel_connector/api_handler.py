from datetime import datetime, timedelta

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout
from urllib3.util.retry import Retry


class SentinelApiHandlerError(Exception):
    def __init__(self, msg, metadata):
        self.msg = msg
        self.metadata = metadata


class SentinelApiHandler:
    def __init__(self, helper, config):
        """
        Init Sentinel Intel API handler.
        :param helper: PyCTI helper instance
        :param config: Connector config variables
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        self.session = requests.Session()
        self.retries_builder()
        self._expiration_token_date = None
        self.workspace_url = f"https://api.ti.sentinel.azure.com/workspaces/{self.config.workspace_id}/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview"

    def _get_authorization_managed_identity_token(self):
        """
        Get a token from the metadata endpoint
        """
        response_json = {}
        try:
            url = "http://169.254.169.254/metadata/identity/oauth2/token"
            params = {
                "api-version": "2018-02-01",
                "resource": "https://management.azure.com/",
            }
            headers = {"Metadata": "true"}
            response = requests.get(url, params=params, headers=headers)
            response_json = response.json()
            response.raise_for_status()
            oauth_token = response_json["access_token"]
            oauth_expired = float(response_json["expires_in"])  # time in seconds
            self.session.headers.update({"Authorization": f"Bearer {oauth_token}"})
            self._expiration_token_date = datetime.now() + timedelta(
                seconds=int(oauth_expired * 0.9)
            )
        except (requests.exceptions.HTTPError, KeyError) as e:
            error_description = response_json.get("error_description", "Unknown error")
            error_message = f"[ERROR] Failed generating oauth token (managed identity): {error_description}"
            self.helper.connector_logger.error(
                error_message, {"response": response_json}
            )
            raise e

    def _update_authorization_header(self):
        if self.config.login_type == "client_secret":
            self._get_authorization_client_secret_token()
        elif self.config.login_type == "managed_identity":
            self._get_authorization_managed_identity_token()

    def _get_authorization_client_secret_token(self):
        """
        Get an OAuth access token and set it as Authorization header in headers.
        """
        response_json = {}
        try:
            url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
            body = {
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "grant_type": "client_credentials",
                "scope": "https://management.azure.com/.default",
            }
            response = requests.post(url, data=body)
            response_json = response.json()
            response.raise_for_status()

            oauth_token = response_json["access_token"]
            oauth_expired = float(response_json["expires_in"])  # time in seconds
            self.session.headers.update({"Authorization": f"Bearer {oauth_token}"})
            self._expiration_token_date = datetime.now() + timedelta(
                seconds=int(oauth_expired * 0.9)
            )
        except (requests.exceptions.HTTPError, KeyError) as e:
            error_description = response_json.get("error_description", "Unknown error")
            error_message = (
                f"[ERROR] Failed generating oauth token: {error_description}"
            )
            self.helper.connector_logger.error(
                error_message, {"response": response_json}
            )
            raise e

    def retries_builder(self) -> None:
        """
        Configures the session's retry strategy for API requests.

        Sets up the session to retry requests upon encountering specific HTTP status codes (429 and 401) using
        exponential backoff. The retry mechanism will be applied for both HTTP and HTTPS requests.
        This function uses the `Retry` and `HTTPAdapter` classes from the `requests.adapters` module.

        - Retries up to 5 times with an increasing delay between attempts.
        """
        retry_strategy = Retry(total=5, backoff_factor=2, status_forcelist=[429, 401])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

    def _send_request(self, method: str, url: str, **kwargs) -> dict | None:
        """
        Send a request to Sentinel API. Refresh auth token if it is expired
        :param method: Request HTTP method
        :param url: Request URL
        :param kwargs: Any arguments valid for session.requests() method
        :return: Any data returned by the API
        """
        try:
            if (
                self._expiration_token_date is None
                or datetime.now() > self._expiration_token_date
            ):
                self._update_authorization_header()

            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            self.helper.connector_logger.debug(
                "[API] HTTP Request to endpoint",
                {"url_path": f"{method.upper()} {url}"},
            )

            if response.content:
                return response.json()

        except (RetryError, HTTPError, Timeout, ConnectionError) as err:
            raise SentinelApiHandlerError(
                "[API] An error occured during request",
                {"url_path": f"{method.upper()} {url} {str(err)}"},
            ) from err

    def _build_request_body(self, indicator: dict) -> dict:
        del indicator[
            "extensions"
        ]  # Todo: add configurable labels + make it configurable to delete extensions
        data = {"sourcesystem": self.config.source_system, "stixobjects": [indicator]}
        return data

    def post_indicator(self, indicator: dict) -> dict | None:
        """
        Create a Threat Intelligence Indicator on Sentinel from an OpenCTI observable.
        :param indicator: OpenCTI observable to create Threat Intelligence Indicator for
        :return: Threat Intelligence Indicator if request is successful, None otherwise
        """
        request_body = self._build_request_body(indicator)
        data = self._send_request(
            "post",
            self.workspace_url,
            json=request_body,
        )
        return data

    def delete_indicator(self, indicator_id: str) -> bool:
        """
        Delete a Threat Intelligence Indicator on Sentinel corresponding to an OpenCTI observable.
        :param indicator_id: OpenCTI observable to delete Threat Intelligence Indicator for
        :return: True if request is successful, False otherwise
        """
        raise NotImplementedError("DELETE indicators is not implemented yet")
