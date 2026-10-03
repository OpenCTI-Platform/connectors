from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import quote

import requests
from microsoft_defender_intel_connector.utils import (
    IOC_TYPES,
    get_action,
    get_description,
    get_expiration_datetime,
    get_severity,
)
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout
from urllib3.util.retry import Retry

APPLICATION_NAME = "OpenCTI Microsoft Defender Intel"
"""`application` of every indicator created by the connector."""

ALERTS_RESOURCE_PATH = "api/alerts"
"""Path of the alerts API, relative to the base URL."""

MAX_PAGE_SIZE = 10_000
"""Maximum `$top` accepted by the indicators and alerts APIs."""


class DefenderApiHandlerError(Exception):
    def __init__(self, msg, metadata):
        self.msg = msg
        self.metadata = metadata


class DefenderApiHandler:
    def __init__(
        self,
        helper,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        base_url: HttpUrl,
        resource_path: str,
        action: Literal[
            "Warn",
            "Block",
            "Audit",
            "Alert",
            "AlertAndBlock",
            "BlockAndRemediate",
            "Allowed",
        ],
        expired_after: int,
    ):
        """
        Init Defender Intel API handler.
        :param helper: PyCTI helper instance
        :param config: Connector config variables
        """
        self.helper = helper

        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = str(base_url).rstrip("/")
        self.resource_path = resource_path
        self.action = action
        self.expired_after = expired_after

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
            url = (
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            )
            body = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
                "scope": self.base_url + "/.default",
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
            raise DefenderApiHandlerError(
                f"Failed to generate OAuth token: {error_description}",
                {"response": response_json},
            ) from e

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
                "[API] An error occurred during request",
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
                "application": APPLICATION_NAME,
                "action": self.action or get_action(observable),
                "title": observable["value"],
                "description": get_description(observable),
                "externalId": OpenCTIConnectorHelper.get_attribute_in_extension(
                    "id", observable
                ),
                "lastUpdateTime": OpenCTIConnectorHelper.get_attribute_in_extension(
                    "updated_at", observable
                ),
                "expirationTime": get_expiration_datetime(
                    observable, int(self.expired_after)
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
            "get", f"{self.base_url}/{self.resource_path.lstrip('/')}"
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
        # OData string literals escape single quotes by doubling them; then
        # percent-encode the whole expression so reserved characters (?, &, =,
        # spaces, quotes) inside a URL indicator value can't leak into the
        # query-string structure and truncate the $filter (which otherwise
        # yields a 400 "unterminated string literal"). Keep "$filter=" literal.
        odata_value = value.replace("'", "''")
        params = "$filter=" + quote(f"indicatorValue eq '{odata_value}'", safe="")
        data = self._send_request(
            "get", f"{self.base_url}/{self.resource_path.lstrip('/')}", params=params
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
            f"{self.base_url}/{self.resource_path.lstrip('/')}",
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
            f"{self.base_url}/{self.resource_path.strip('/')}/import",
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
            f"{self.base_url}/{self.resource_path.strip('/')}/BatchDelete",
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
            f"{self.base_url}/{self.resource_path.strip('/')}/{indicator_id}",
        )
        return True

    def _get_page(self, url: str, params: str) -> list[dict[str, Any]]:
        """
        Read one page of an OData collection.
        :param url: Collection URL
        :param params: Encoded query string
        :return: Items of the page
        :raise DefenderApiHandlerError: On any error or an unexpected payload
        """
        data = self._send_request("get", url, params=params)
        items = data.get("value") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise DefenderApiHandlerError(
                "[API] Unexpected response format: missing 'value' list",
                {"url_path": f"GET {url}"},
            )
        return [item for item in items if isinstance(item, dict)]

    def iter_application_indicators(
        self,
        application: str = APPLICATION_NAME,
        page_size: int = MAX_PAGE_SIZE,
        max_pages: int = 100,
    ) -> Iterator[dict[str, Any]]:
        """
        Iterate over the active indicators of an application, paginated with `$top` and `$skip`.

        Offsets shift when indicators are created or deleted during the listing, which
        would silently skip a row. Each page after the first therefore starts one row
        early and must start with the last row of the previous page; otherwise the
        listing fails, so the reconciliation never acts on a listing with a hole.
        :param application: The `application` of the indicators (the connector's by default)
        :param page_size: `$top` of each page (2 to 10,000)
        :param max_pages: Safety bound of the number of pages
        :return: Indicator entities
        :raise DefenderApiHandlerError: On any error or when rows moved between pages,
            never yield a partial listing silently
        """
        if page_size < 2:
            raise ValueError("page_size must be at least 2 to verify page overlaps")
        url = f"{self.base_url}/{self.resource_path.strip('/')}"
        odata_application = application.replace("'", "''")
        query_filter = quote(f"application eq '{odata_application}'", safe="")
        read = 0
        previous_last_id = None
        for page in range(max_pages):
            skip = read if previous_last_id is None else read - 1
            items = self._get_page(
                url,
                f"$filter={query_filter}&$top={page_size}&$skip={skip}",
            )
            full_page = len(items) == page_size
            if previous_last_id is not None:
                if not items or items[0].get("id") != previous_last_id:
                    raise DefenderApiHandlerError(
                        "[API] Indicators changed during the read-back, listing discarded",
                        {"page": page, "skip": skip},
                    )
                items = items[1:]
            yield from items
            if not full_page:
                return
            read += len(items)
            previous_last_id = items[-1].get("id")
        raise DefenderApiHandlerError(
            "[API] Indicator read-back stopped before reaching the end",
            {"max_pages": max_pages, "page_size": page_size},
        )

    def list_alerts(
        self,
        since: datetime,
        max_alerts: int = MAX_PAGE_SIZE,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        List the alerts created since a date, with their evidence.
        :param since: Only alerts created at or after this date
        :param max_alerts: Maximum number of alerts returned (10,000 at most per request)
        :param until: Only alerts created strictly before this date, when given
        :return: Alert entities
        :raise DefenderApiHandlerError: On any error or an unexpected payload
        """
        since_utc = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        expression = f"alertCreationTime ge {since_utc}"
        if until is not None:
            until_utc = until.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            expression += f" and alertCreationTime lt {until_utc}"
        query_filter = quote(expression, safe="")
        url = f"{self.base_url}/{ALERTS_RESOURCE_PATH}"
        alerts: list[dict[str, Any]] = []
        while len(alerts) < max_alerts:
            top = min(MAX_PAGE_SIZE, max_alerts - len(alerts))
            items = self._get_page(
                url,
                f"$filter={query_filter}&$expand=evidence&$top={top}"
                f"&$skip={len(alerts)}",
            )
            alerts.extend(items[:top])
            if len(items) < top:
                break
        return alerts
