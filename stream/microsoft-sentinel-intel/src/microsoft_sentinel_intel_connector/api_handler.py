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
        self.management_url = f"https://management.azure.com/subscriptions/{self.config.subscription_id}/resourceGroups/{self.config.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.config.workspace_name}/providers/Microsoft.SecurityInsights/threatIntelligence/main"
        self.extra_labels = (
            self.config.extra_labels.split(",") if self.config.extra_labels else None
        )

    def _get_authorization_managed_identity_token(self):
        """
        Get a token from the metadata endpoint
        """
        url = "http://169.254.169.254/metadata/identity/oauth2/token"
        params = {
            "api-version": "2018-02-01",
            "resource": "https://management.azure.com/",
        }
        headers = {"Metadata": "true"}
        response = requests.get(url, params=params, headers=headers)
        response_json = response.json()
        return response_json

    def _update_authorization_header(self):
        response = {}

        if self.config.login_type == "client_secret":
            response = self._get_authorization_client_secret_token()
        elif self.config.login_type == "managed_identity":
            response = self._get_authorization_managed_identity_token()
        else:
            self.helper.connector_logger.error(
                "[ERROR]: No auth mechanism has been provided"
            )

        try:
            oauth_token = response["access_token"]
            oauth_expired = float(response["expires_in"])  # time in seconds
            self.session.headers.update({"Authorization": f"Bearer {oauth_token}"})
            self._expiration_token_date = datetime.now() + timedelta(
                seconds=int(oauth_expired * 0.9)
            )
        except (requests.exceptions.HTTPError, KeyError) as e:
            error_description = response.get("error_description", "Unknown error")
            error_message = f"[ERROR] Failed generating oauth token (managed identity): {error_description}"
            self.helper.connector_logger.error(error_message, {"response": response})
            raise e

    def _get_authorization_client_secret_token(self):
        """
        Get an OAuth access token and set it as Authorization header in headers.
        """
        response_json = {}
        url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
        body = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "grant_type": "client_credentials",
            "scope": "https://management.azure.com/.default",
        }
        response = requests.post(url, data=body)
        response_json = response.json()
        return response_json

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
                {"url_path": f"{method.upper()} {url} {response.status_code}"},
            )

            if response.content:
                return response.json()

        except (RetryError, HTTPError, Timeout, ConnectionError) as err:
            raise SentinelApiHandlerError(
                "[API] An error occured during request",
                {"url_path": f"{method.upper()} {url} {str(err)}"},
            ) from err

    def _build_request_body(self, indicator: dict) -> dict:
        """
        Builds a request body dictionary by modifying the provided indicator.

        This function checks for the presence of configuration options like `delete_extensions`
        and `extra_labels` and updates the indicator accordingly. It then creates a dictionary
        containing the source system and the indicator as part of the request body.

        :params: indicator (dict): A dictionary representing a STIX indicator.
        :return dict: A dictionary with the keys "sourcesystem" and "stixobjects",
                  where "stixobjects" contains the modified indicator.
        """

        if self.config.delete_extensions:
            del indicator["extensions"]

        if self.extra_labels:
            if "labels" in indicator:
                indicator["labels"] = list(
                    set(indicator["labels"].append(self.extra_labels))
                )
            else:
                indicator["labels"] = self.extra_labels

        data = {"sourcesystem": self.config.source_system, "stixobjects": [indicator]}
        return data

    def post_indicator(self, indicator: dict) -> None:
        """
        Create a Threat Intelligence Indicator on Sentinel from an OpenCTI indicator.
        :param indicator: OpenCTI indicator
        """
        request_body = self._build_request_body(indicator)
        self._send_request(
            "post",
            self.workspace_url,
            json=request_body,
        )

    def delete_indicator(self, indicator_id: str):
        """
        Delete a Threat Intelligence Indicator on Sentinel corresponding to an OpenCTI indicator.
        :param indicator_id: OpenCTI indicator to delete Threat Intelligence Indicator for
        """
        name = self._search_indicator_name(indicator_id)
        url = f"{self.management_url}/indicators/{name}?api-version=2025-03-01"
        self._send_request("delete", url)

    def _search_indicator_name(self, indicator_id: str) -> str:
        """
        Search a Threat Intelligence Indicator name based on the Opencti ID
        :param indicator_id: OpenCTI indicator to search Threat Intelligence Indicator for
        """
        url = f"{self.management_url}/queryIndicators?api-version=2025-03-01"
        data = {"keywords": indicator_id}
        resp = self._send_request("post", url, json=data)
        if resp is not None and len(resp["value"]) == 1:
            return resp["value"][0]["name"]
        else:
            self.helper.connector_logger.error(
                f"[SEARCH] Indicator not found in Sentinel: {indicator_id}"
            )
