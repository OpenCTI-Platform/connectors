import hashlib
import hmac
import json
import logging
from json import JSONDecodeError
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper
from requests.exceptions import RequestException
from shadowserver.constants import (
    BASE_URL,
    CHUNK_SIZE,
    DOWNLOAD_URL,
    LIMIT,
    MAX_REPORT_SIZE,
    TIMEOUT,
    TLP_MAP,
)
from shadowserver.stix_transform import ShadowserverStixTransformation
from shadowserver.utils import from_csv_to_list, validate_date_format

LOGGER = logging.getLogger(__name__)


class ShadowserverAPI:
    """
    This class interacts with the Shadowserver API to retrieve and process reports.
    """

    def __init__(self, api_key: str, api_secret: str, marking_refs: str):
        """
        Initializes a new instance of the API class.

        Parameters:
            api_key (str): The API key for authentication.
            api_secret (str): The API secret for authentication.
            marking_refs (str, optional): The marking references. Defaults to "TLP:WHITE".

        Raises:
            ValueError: If marking_refs is invalid.
        """
        self.base_url = BASE_URL
        self.api_key = api_key
        self.api_secret = api_secret
        self.marking_refs = TLP_MAP[marking_refs]
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
        type: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Submit API request to retrieve a list of reports.

        Args:
            date (str, optional): The date for which to retrieve reports. Defaults to None.
            limit (int, optional): The maximum number of reports to retrieve. Defaults to 1000.
            reports (list, optional): A list of report names to retrieve. Defaults to None.
            type (str, optional): The type of reports to retrieve. Defaults to None.

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

        Uses streaming with a size limit to avoid unbounded memory use.
        Note: Segmentation faults (e.g. from SSL/native code) cannot be
        caught in Python; the process would terminate. For critical isolation,
        run the connector in a separate process.

        Args:
            report_id (str): Report identifier returned by reports/list.
        Returns:
            bytes: The content of the downloaded report file, or b"" on error
                or if the report exceeds MAX_REPORT_SIZE.
        """
        url = urljoin(DOWNLOAD_URL, report_id)

        try:
            with self.session.get(url, timeout=TIMEOUT, stream=True) as response:
                response.raise_for_status()
                size = response.headers.get("Content-Length")
                if size and int(size) > MAX_REPORT_SIZE:
                    LOGGER.error(
                        f"Report {report_id} too large - {size} > {MAX_REPORT_SIZE} bytes"
                    )
                    return b""

                chunks = []
                for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    if len(chunks) * CHUNK_SIZE + len(chunk) > MAX_REPORT_SIZE:
                        LOGGER.error(
                            f"Report {report_id} too large - max size: {MAX_REPORT_SIZE} bytes"
                        )
                        return b""
                    chunks.append(chunk)
                return b"".join(chunks)
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

    def get_stix_report(
        self,
        report: dict,
        api_helper: OpenCTIConnectorHelper,
        limit: int = LIMIT,
        incident: dict = {},
        labels: List[str] = ["Shadowserver"],
    ) -> list[Any]:
        """
        Retrieves a STIX report based on the specified report parameters.

        Args:
            report (dict): The report parameters containing 'id' and 'report' keys.
            api_helper (OpenCTIConnectorHelper): The OpenCTI connector helper instance.
            limit (int, optional): The maximum number of results to return. Defaults to LIMIT.
            labels (list, optional): Labels to apply to the STIX objects. Defaults to ['Shadowserver'].

        Returns:
            list: A list of STIX objects.
        """
        if not report.get("id") or not report.get("report"):
            raise ValueError(f"Invalid report: {report}")

        LOGGER.debug(
            f"Getting report: {report.get('id')}, {report.get('report')}, {limit}"
        )
        csv_content = self.get_report(report_id=report.get("id"))

        if csv_content:
            # Parse CSV content into list of dictionaries
            report_list = from_csv_to_list(csv_content)
            LOGGER.debug(f"Report list length: {len(report_list)}")
            stix_transformation = ShadowserverStixTransformation(
                marking_refs=self.marking_refs,
                report_list=report_list,
                report=report,
                labels=labels,
                api_helper=api_helper,
                incident=incident,
            )
            return stix_transformation.get_stix_objects()
        else:
            return []
