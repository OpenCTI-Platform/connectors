import hashlib
import hmac
import json
import logging
from json import JSONDecodeError
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException
from shadowserver.constants import BASE_URL, DOWNLOAD_URL, LIMIT, TIMEOUT
from shadowserver.utils import from_csv_to_list, validate_date_format

LOGGER = logging.getLogger(__name__)


class ShadowserverAPI:
    """
    This class interacts with the Shadowserver API to retrieve and process reports.
    """

    def __init__(self, api_key: str, api_secret: str):
        """
        Initializes a new instance of the API class.

        Parameters:
            api_key (str): The API key for authentication.
            api_secret (str): The API secret for authentication.
        """
        self.base_url = BASE_URL
        self.api_key = api_key
        self.api_secret = api_secret
        self.session = requests.Session()

    def _generate_hmac(self, request: dict) -> Tuple[bytes, str]:
        """
        Generate HMAC for the given request.

        Args:
            request (dict): The request dictionary.

        Returns:
            tuple: A tuple containing the request bytes and the HMAC.
        """
        request_string = json.dumps(request)
        secret_bytes = self.api_secret.encode("utf-8")
        request_bytes = request_string.encode("utf-8")
        hmac_generator = hmac.new(secret_bytes, request_bytes, hashlib.sha256)
        hmac_value = hmac_generator.hexdigest()
        return request_bytes, hmac_value

    def _request(self, uri_path: str, request: dict) -> Optional[Dict]:
        """
        Sends a request to the specified URI path with the given request data.

        Args:
            uri_path (str): The URI path to send the request to.
            request (dict): The request data to send.

        Returns:
            dict or None: The JSON response from the request, or None if an error occurred.
        """
        url = urljoin(self.base_url, uri_path)
        request["apikey"] = self.api_key
        request_bytes, hmac2 = self._generate_hmac(request)

        try:
            response = self.session.post(
                url, data=request_bytes, headers={"HMAC2": hmac2}, timeout=TIMEOUT
            )
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            LOGGER.error(f"Request to {url} failed: {e}")
        except JSONDecodeError as e:
            LOGGER.error(f"Failed to parse response: {e}")
        except Exception as e:
            LOGGER.error(f"Unexpected error occurred: {e}")
        return None

    def get_report_list(
        self,
        date: Optional[str] = None,
        limit: int = 1000,
        reports: Optional[List[str]] = None,
        type: Optional[str | List[str]] = None,
    ) -> Optional[Dict]:
        """
        Submit API request to retrieve a list of reports.

        Args:
            date (str, optional): The date for which to retrieve reports. Defaults to None.
            limit (int, optional): The maximum number of reports to retrieve. Defaults to 1000.
            reports (list, optional): A list of report names to retrieve. Defaults to None.
            type (str or list, optional): The type(s) of reports to retrieve. Defaults to None.

        Returns:
            dict or None: The JSON response from the request, or None if an error occurred.
        """
        if date and not validate_date_format(date):
            LOGGER.error(f"Invalid date format: {date}")
            raise ValueError(f"Invalid date format: {date}")

        request = {"date": date, "limit": limit}
        if reports:
            request["reports"] = reports
        if type:
            request["type"] = type

        return self._request(uri_path="reports/list", request=request)

    def get_report(self, report_id: str) -> bytes:
        """
        Download a report file from Shadowserver.

        Args:
            report_id (str): Report identifier returned by reports/list.
        Returns:
            bytes: The content of the downloaded report file.
        """
        url = urljoin(DOWNLOAD_URL, report_id)

        try:
            response = self.session.get(url, timeout=TIMEOUT)
            response.raise_for_status()
            return response.content
        except RequestException as e:
            LOGGER.error(f"Failed to download report {report_id}: {e}")
            return b""

    def get_subscriptions(self) -> Optional[Dict]:
        """
        Retrieves the list of available report types from the Shadowserver API.

        Returns:
            dict or None: The JSON response from the request, or None if an error occurred.
        """
        return self._request(uri_path="reports/types", request={})

    def get_report_data(
        self,
        report: dict,
        limit: int = LIMIT,
    ) -> list[Any]:
        """
        Download and parse a Shadowserver report as a list of row dicts.

        Args:
            report (dict): The report parameters containing 'id' and 'report' keys.
            limit (int, optional): Unused, kept for API compatibility. Defaults to LIMIT.

        Returns:
            list: Parsed rows from the CSV report, or an empty list on failure.
        """
        if not report.get("id") or not report.get("report"):
            raise ValueError(f"Invalid report: {report}")

        LOGGER.debug(
            f"Getting report: {report.get('id')}, {report.get('report')}, {limit}"
        )
        csv_content = self.get_report(report_id=report.get("id"))

        if csv_content:
            report_list = from_csv_to_list(csv_content)
            LOGGER.debug(f"Report list length: {len(report_list)}")
            return report_list
        return []
