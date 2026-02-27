"""MokN API client for fetching login attempts."""

import json
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from pycti import OpenCTIConnectorHelper
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

# API Configuration
API_ENDPOINT = "/api/v1/baits/logins"
API_TIMEOUT = 30
API_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "OpenCTI-MokN-Connector/1.0",
}

# API Filter Configuration
FILTER_TYPES = ["MEDIUM", "HIGH"]
FILTER_GLOBAL_OPERATOR = "and"
FILTER_OPERATOR_EQUALS = "equals"


class MoknApiClient:
    """Handles communication with MokN API."""

    def __init__(self, helper: OpenCTIConnectorHelper, config: Any) -> None:
        """
        Initialize API client.
        :param helper: OpenCTI connector helper.
        :param config: Connector settings.
        """
        self.helper = helper
        self.config = config
        self.console_url = config.mokn.console_url.rstrip("/")
        self.api_key = config.mokn.api_key.get_secret_value()
        self.first_run_days_back = config.mokn.first_run_days_back

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential_jitter(initial=1, max=60, jitter=1),
        reraise=True,
    )
    def _request_data(
        self, api_url: str, json_data: Dict[str, Any]
    ) -> requests.Response:
        """
        Handle POST API requests.
        :param api_url: API URL.
        :param json_data: JSON payload.
        :return: HTTP response.
        """
        headers = {**API_HEADERS, "X-MOKN-API-KEY": self.api_key}

        try:
            response = requests.post(
                api_url, headers=headers, json=json_data, timeout=API_TIMEOUT
            )
            self.helper.connector_logger.info(
                "[API] HTTP Post Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg,
                {"url_path": api_url, "error": str(err), "type": type(err).__name__},
            )
            raise

    def _timestamp_to_iso(self, timestamp: Any) -> str:
        """
        Convert Unix timestamp to ISO format.
        :param timestamp: Unix timestamp value.
        :return: ISO8601 timestamp string.
        """
        try:
            if isinstance(timestamp, str):
                timestamp = int(timestamp)
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, TypeError) as e:
            self.helper.connector_logger.error(
                "Invalid timestamp format",
                {"timestamp": timestamp, "error": str(e), "type": type(e).__name__},
            )
            default_dt = datetime.now(timezone.utc) - timedelta(hours=1)
            return default_dt.isoformat()

    def _build_date_range(
        self, params: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, str]:
        """
        Build date range for API request.
        :param params: Optional params including last_run_timestamp.
        :return: (datetime_from, datetime_to) ISO strings.
        """
        now = datetime.now(timezone.utc)
        datetime_to = now.isoformat()

        if params and "last_run_timestamp" in params:
            last_run_timestamp = params["last_run_timestamp"]
            datetime_from = self._timestamp_to_iso(last_run_timestamp)

            try:
                if isinstance(last_run_timestamp, str):
                    last_run_timestamp = int(last_run_timestamp)
                log_timestamp = datetime.fromtimestamp(
                    last_run_timestamp, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.connector_logger.info(
                    "Filtering data since", {"since": log_timestamp}
                )
            except (ValueError, TypeError):
                pass
        else:
            days_ago = now - timedelta(days=self.first_run_days_back)
            datetime_from = days_ago.isoformat()
            self.helper.connector_logger.info(
                "First run - filtering data",
                {
                    "days_back": self.first_run_days_back,
                    "since": days_ago.strftime("%Y-%m-%d %H:%M:%S"),
                },
            )

        return datetime_from, datetime_to

    def _build_request_body(
        self, datetime_from: str, datetime_to: str
    ) -> Dict[str, Any]:
        """
        Build API request body with filters.
        :param datetime_from: ISO datetime start.
        :param datetime_to: ISO datetime end.
        :return: Request body.
        """
        return {
            "filters": {
                "global_operator": FILTER_GLOBAL_OPERATOR,
                "filters": [
                    {
                        "id": "type",
                        "values": FILTER_TYPES,
                        "operator": FILTER_OPERATOR_EQUALS,
                    },
                    {
                        "id": "datetime_from",
                        "values": datetime_from,
                        "operator": FILTER_OPERATOR_EQUALS,
                    },
                    {
                        "id": "datetime_to",
                        "values": datetime_to,
                        "operator": FILTER_OPERATOR_EQUALS,
                    },
                ],
            },
            "pending": True,
        }

    def _extract_records_from_response(
        self, response_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Extract login attempts list from API response.
        :param response_data: Response JSON.
        :return: List of login attempts.
        """
        if "data" not in response_data:
            if isinstance(response_data, list):
                return response_data
            return response_data.get("results", response_data.get("items", []))

        data = response_data["data"]

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            # Search for lists in dictionary values
            for value in data.values():
                if isinstance(value, list):
                    return value

            self.helper.connector_logger.error(
                "No list found in 'data'",
                {"structure": json.dumps(data, indent=2)},
            )
            return []

        self.helper.connector_logger.error(
            "'data' has unexpected type", {"type": str(type(data))}
        )
        return []

    def get_entities(
        self, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch login attempts using POST with filters and pagination.
        :param params: Optional params including last_run_timestamp.
        :return: List of login attempts.
        """
        try:
            api_url = f"{self.console_url}{API_ENDPOINT}"
            datetime_from, datetime_to = self._build_date_range(params)

            self.helper.connector_logger.info(
                "Fetching login attempts", {"from": datetime_from, "to": datetime_to}
            )

            request_body = self._build_request_body(datetime_from, datetime_to)
            all_records = []
            current_url = api_url
            page_number = 1
            total_count = 0

            # Loop through all pages
            while current_url:
                self.helper.connector_logger.info(
                    "Fetching page",
                    {"page": page_number, "url_path": current_url},
                )

                # Use POST for all pages (first and subsequent) with same filters
                response = self._request_data(current_url, json_data=request_body)
                response_data = response.json()
                page_records = self._extract_records_from_response(response_data)

                if page_records:
                    all_records.extend(page_records)
                    self.helper.connector_logger.info(
                        "Page fetched",
                        {
                            "page": page_number,
                            "records": len(page_records),
                            "total": len(all_records),
                        },
                    )

                # Get total count from first page
                if page_number == 1:
                    total_count = response_data.get("count", len(all_records))
                    if total_count:
                        self.helper.connector_logger.info(
                            "Total records available", {"total": total_count}
                        )

                # Check for next page (always absolute URL with ?page=X)
                next_url = response_data.get("next")
                if next_url:
                    current_url = next_url
                    page_number += 1
                else:
                    current_url = None

            if all_records:
                self.helper.connector_logger.info(
                    "Pagination complete",
                    {"records": len(all_records), "pages": page_number},
                )

            return all_records

        except (requests.RequestException, ValueError, TypeError) as err:
            self.helper.connector_logger.error(
                "Error in get_entities",
                {"error": str(err), "type": type(err).__name__},
            )
            self.helper.connector_logger.error(traceback.format_exc())
            raise

    def fetch_attack_data(
        self, last_run_timestamp: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch login attempts from MokN API using POST with filters.
        :param last_run_timestamp: Last run unix timestamp.
        :return: List of login attempts.
        """
        params = (
            {"last_run_timestamp": last_run_timestamp} if last_run_timestamp else None
        )
        return self.get_entities(params)
