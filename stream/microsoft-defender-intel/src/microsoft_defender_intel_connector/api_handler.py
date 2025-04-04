from datetime import datetime, timedelta

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout
from urllib3.util.retry import Retry

from .utils import (
    IOC_TYPES,
    get_action,
    get_description,
    get_expiration_datetime,
    get_severity,
)


class DefenderApiHandlerError(Exception):
    def __init__(self, msg, metadata):
        self.msg = msg
        self.metadata = metadata


class DefenderApiHandler:
    def __init__(self, helper, config):
        """
        Init Defender Intel API handler.
        :param helper: PyCTI helper instance
        :param config: Connector config variables
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        self.session = requests.Session()
        self.retries_builder()
        self._expiration_token_date = None

    def _get_authorization_header(self):
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
                "scope": self.config.base_url + "/.default",
            }
            response = requests.post(url, data=body)
            response_json = response.json()
            response.raise_for_status()

            oauth_token = response_json["access_token"]
            oauth_expired = float(response_json["expires_in"])  # time in seconds
            self.session.headers.update({"Authorization": "Bearer " + oauth_token})
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

        Sets up the session to retry requests upon encountering specific HTTP status codes (429) using
        exponential backoff. The retry mechanism will be applied for both HTTP and HTTPS requests.
        This function uses the `Retry` and `HTTPAdapter` classes from the `requests.adapters` module.

        - Retries up to 5 times with an increasing delay between attempts.
        """
        retry_strategy = Retry(total=5, backoff_factor=2, status_forcelist=[429])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

    def _send_request(self, method: str, url: str, **kwargs) -> dict | None:
        """
        Send a request to Defender API.
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
                self._get_authorization_header()

            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            self.helper.connector_logger.debug(
                "[API] HTTP Request to endpoint",
                {"url_path": f"{method.upper()} {url}"},
            )
            if response.content:
                return response.json()

        except (RetryError, HTTPError, Timeout, ConnectionError) as err:
            raise DefenderApiHandlerError(
                "[API] An error occured during request",
                {"url_path": f"{method.upper()} {url}"},
            ) from err

    def _build_request_body(self, observable: dict, defender_id: str | None) -> dict:
        """
        Build Defender POST/PATCH request's body from an observable.
        :param observable: Observable to build body from
        :return: Dict containing keys/values required for POST/PATCH requests on Defender.
        """
        if "hashes" in observable:
            if "sha256" in observable["hashes"]:
                observable["type"] = "sha256"
                observable["value"] = observable["hashes"]["sha256"]
            elif "sha1" in observable["hashes"]:
                observable["type"] = "sha1"
                observable["value"] = observable["hashes"]["sha1"]
            elif "md5" in observable["hashes"]:
                observable["type"] = "md5"
                observable["value"] = observable["hashes"]["md5"]
        body = None
        if observable["type"] in IOC_TYPES:
            body = {
                "indicatorType": IOC_TYPES[observable["type"]],
                "indicatorValue": observable["value"],
                "application": "OpenCTI Microsoft Defender Intel Synchronizer",
                "action": self.config.action or get_action(observable),
                "title": observable["value"],
                "description": get_description(observable),
                "externalId": OpenCTIConnectorHelper.get_attribute_in_extension(
                    "id", observable
                ),
                "lastUpdateTime": OpenCTIConnectorHelper.get_attribute_in_extension(
                    "updated_at", observable
                ),
                "expirationTime": get_expiration_datetime(
                    observable, int(self.config.expire_time)
                ),
                "severity": get_severity(observable),
                "generateAlert": True,
            }
            if defender_id is not None:
                body["id"] = defender_id
        return body

    def get_indicators(self) -> list[dict]:
        """
        Get Threat Intelligence Indicators from Defender.
        :return: List of Threat Intelligence Indicators if request is successful, None otherwise
        """
        data = self._send_request(
            "get", f"{self.config.base_url}{self.config.resource_path}"
        )
        result = data["value"]
        while "@odata.nextLink" in data and data["@odata.nextLink"] is not None:
            data = self._send_request("get", data["@odata.nextLink"])
            result = result + data["value"]
        return result

    def find_indicators(self, value) -> list[dict] | None:
        """
        Get Threat Intelligence Indicators from Defender.
        :param value: Value of the indicator
        :return: List of Threat Intelligence Indicators if request is successful, None otherwise
        """
        params = f"$filter=indicatorValue eq '{value}'"
        data = self._send_request(
            "get", f"{self.config.base_url}{self.config.resource_path}", params=params
        )
        result = data["value"]
        while "@odata.nextLink" in data and data["@odata.nextLink"] is not None:
            data = self._send_request("get", data["@odata.nextLink"])
            result = result + data["value"]
        return result

    def post_indicator(self, observable: dict, defender_id: str | None) -> dict | None:
        """
        Create a Threat Intelligence Indicator on Defender from an OpenCTI observable.
        :param observable: OpenCTI observable to create Threat Intelligence Indicator for
        :param defender_id: Defender ID
        :return: Threat Intelligence Indicator if request is successful, None otherwise
        """
        request_body_observable = self._build_request_body(observable, defender_id)
        data = self._send_request(
            "post",
            f"{self.config.base_url}{self.config.resource_path}",
            json=request_body_observable,
        )
        return data

    def post_indicators(self, observables: list[dict]) -> dict | None:
        """
        Create a Threat Intelligence Indicator on Defender from an OpenCTI observable.
        :param observables: OpenCTI observables to create Threat Intelligence Indicator for
        :return: Threat Intelligence Indicator if request is successful, None otherwise
        """
        request_body = {"Indicators": []}
        for observable in observables:
            request_body_observable = self._build_request_body(observable, None)
            if request_body_observable is not None:
                request_body["Indicators"].append(request_body_observable)

        data = self._send_request(
            "post",
            f"{self.config.base_url}{self.config.resource_path}/import",
            json=request_body,
        )
        return data

    def delete_indicators(self, indicators_ids: list[str]) -> bool:
        """
        Delete a Threat Intelligence Indicator on Defender corresponding to an OpenCTI observable.
        :param indicators_ids: Indicators IDs
        :return: True if request is successful, False otherwise
        """
        request_body = {"IndicatorIds": indicators_ids}
        self._send_request(
            "post",
            f"{self.config.base_url}{self.config.resource_path}/BatchDelete",
            json=request_body,
        )
        return True

    def delete_indicator(self, indicator_id: str) -> bool:
        """
        Delete a Threat Intelligence Indicator on Defender corresponding to an OpenCTI observable.
        :param indicator_id: OpenCTI observable to delete Threat Intelligence Indicator for
        :return: True if request is successful, False otherwise
        """
        self._send_request(
            "delete",
            f"{self.config.base_url}{self.config.resource_path}/{indicator_id}",
        )
        return True
