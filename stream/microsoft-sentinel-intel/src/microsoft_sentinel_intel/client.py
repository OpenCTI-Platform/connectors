from datetime import datetime, timedelta

import requests
from azure.core.exceptions import AzureError
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from microsoft_sentinel_intel.config import ConnectorSettings
from microsoft_sentinel_intel.errors import ConnectorClientError
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout
from urllib3.util.retry import Retry


class ConnectorClient:
    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorSettings):
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
        self.workspace_url = f"https://api.ti.sentinel.azure.com/workspaces/{self.config.microsoft_sentinel_intel.workspace_id}/threat-intelligence-stix-objects:upload?api-version={self.config.microsoft_sentinel_intel.workspace_api_version}"
        self.management_url = f"https://management.azure.com/subscriptions/{self.config.microsoft_sentinel_intel.subscription_id}/resourceGroups/{self.config.microsoft_sentinel_intel.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.config.microsoft_sentinel_intel.workspace_name}/providers/Microsoft.SecurityInsights/threatIntelligence/main"
        self.extra_labels = (
            self.config.microsoft_sentinel_intel.extra_labels.split(",")
            if self.config.microsoft_sentinel_intel.extra_labels
            else None
        )

    def _get_authorization_token(self):
        """
        Get an OAuth token using azure-identity SDK based.
        """

        if all(
            {
                self.config.microsoft_sentinel_intel.tenant_id,
                self.config.microsoft_sentinel_intel.client_id,
                self.config.microsoft_sentinel_intel.client_secret,
            }
        ):
            credential = ClientSecretCredential(
                self.config.microsoft_sentinel_intel.tenant_id,
                self.config.microsoft_sentinel_intel.client_id,
                self.config.microsoft_sentinel_intel.client_secret,
            )
        else:
            credential = DefaultAzureCredential()
        try:
            token = credential.get_token("https://management.azure.com/.default")
            return {"access_token": token.token, "expires_on": token.expires_on}
        except AzureError as e:
            self.helper.connector_logger.error(
                f"[ERROR] Azure Identity failed: {str(e)}"
            )
            raise

    def _update_authorization_header(self):
        response = {}

        token = self._get_authorization_token()
        try:
            oauth_token = token["access_token"]
            oauth_expired = float(token["expires_on"])  # time in seconds
            self.session.headers.update({"Authorization": f"Bearer {oauth_token}"})
            self._expiration_token_date = datetime.now() + timedelta(
                seconds=int(oauth_expired * 0.9)
            )
        except (requests.exceptions.HTTPError, KeyError) as e:
            error_description = response.get("error_description", "Unknown error")
            error_message = f"[ERROR] Failed generating oauth token (managed identity): {error_description}"
            self.helper.connector_logger.error(error_message, {"response": response})
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
                {"url_path": f"{method.upper()} {url} {response.status_code}"},
            )

            if response.content:
                res = response.json()
                if errors := res.get("errors"):
                    raise ConnectorClientError(
                        "[API] Error in response from Sentinel",
                        {"url_path": f"{method.upper()} {url}", "errors": errors},
                    )

        except (RetryError, HTTPError, Timeout, ConnectionError) as err:
            raise ConnectorClientError(
                "[API] An error occurred during request",
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

        if self.config.microsoft_sentinel_intel.delete_extensions:
            del indicator["extensions"]

        if self.extra_labels:
            if "labels" in indicator:
                indicator["labels"] = list(
                    set(indicator["labels"].append(self.extra_labels))
                )
            else:
                indicator["labels"] = self.extra_labels

        data = {
            "sourcesystem": self.config.microsoft_sentinel_intel.source_system,
            "stixobjects": [indicator],
        }
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
        url = f"{self.management_url}/indicators/{name}?api-version={self.config.microsoft_sentinel_intel.management_api_version}"

        self._send_request("delete", url)

    def _search_indicator_name(self, indicator_id: str) -> str:
        """
        Search a Threat Intelligence Indicator name based on the Opencti ID
        :param indicator_id: OpenCTI indicator to search Threat Intelligence Indicator for
        """
        url = f"{self.management_url}/queryIndicators?api-version={self.config.microsoft_sentinel_intel.management_api_version}"
        data = {"keywords": indicator_id}
        resp = self._send_request("post", url, json=data)
        if resp is not None and len(resp["value"]) == 1:
            return resp["value"][0]["name"]
        else:
            self.helper.connector_logger.error(
                f"[SEARCH] Indicator not found in Sentinel: {indicator_id}"
            )
