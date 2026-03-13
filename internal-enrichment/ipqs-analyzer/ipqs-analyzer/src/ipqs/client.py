# -*- coding: utf-8 -*-
"""IPQS client module."""

import time

from pycti import OpenCTIConnectorHelper
from requests import Response, session
from requests.exceptions import ConnectTimeout, HTTPError, InvalidURL, ProxyError


class IPQSClient:  # pylint: disable=too-few-public-methods
    """IPQS client."""

    _SCAN_ENDPOINT = "/malware/scan"
    _LOOKUP_ENDPOINT = "/malware/lookup"
    _POSTBACK_ENDPOINT = "/postback"

    def __init__(
        self, helper: OpenCTIConnectorHelper, base_url: str, api_key: str
    ) -> None:
        """Initialize IPQS client."""
        self.helper = helper
        self.url = base_url
        self.headers = {"IPQS-KEY": api_key}
        self.session = session()
        self.file_enrich_fields = {
            "file_name": "File Name",
            "file_hash": "File Hash",
            "type": "Scan Type",
            "detected_scans": "Detected Scans",
            "detected": "Detected",
            "total_scans": "Total Scans",
            "status": "Status",
            "resut": "Result",
            "file_size": "File Size",
            "file_type": "File Type",
            "sha1": "SHA1",
            "md5": "MD5",
            "scan_date": "Scan Date",
            "scan_date_date": "Scan Date",
            "scan_date_timezone_type": "Scan Timezone Type",
            "scan_date_timezone": "Scan Timezone",
        }

    def _query(
        self,
        endpoint: str,
        params: dict = None,
        file: dict = None,
    ) -> Response:
        """General get method to fetch the response from ipqs."""
        try:
            self.helper.log_info("Processing...")
            url = f"{self.url}{endpoint}"
            if file or params.get("url"):
                response = self.session.post(
                    url,
                    headers=self.headers,
                    files=file,
                    json=params,
                    timeout=60,
                )
                if response.status_code == 503:
                    self.helper.log_error("Service Unavailable")
                response = response.json()
            else:
                response = self.session.get(
                    url, headers=self.headers, params=params, timeout=60
                ).json()
            return response
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            msg = "Error connecting with the ipqs."
            self.helper.log_error(f"{msg} Error: {error}")
            return None

    def get_ipqs_info(self, file: dict = None, params: dict = None):
        """
        Returns the IPQS data.
        """

        try:
            if file or params:
                response = self._query(
                    self._LOOKUP_ENDPOINT,
                    file=file,
                    params=params,
                )
                if response.get("status") == "cached":
                    return response
                response = self._query(
                    self._SCAN_ENDPOINT,
                    file=file,
                    params=params,
                )
                retry = 0
                max_retry = 8
                polling_interval = 10
                params = {"request_id": response.get("request_id")}
                while retry <= max_retry:
                    if not response.get("success"):
                        self.helper.log_error(
                            f"Enrichment failed: {response.get('message')}"
                        )
                        break
                    if response.get("status") != "pending":
                        break
                    response = self._query(
                        self._POSTBACK_ENDPOINT,
                        params=params,
                    )
                    retry += 1
                    time.sleep(polling_interval)

        except HTTPError as error:
            msg = (
                f"Error when requesting data from ipqs. {error.response}: "
                f"{error.response.reason}"
            )
            self.helper.log_error(msg)
            raise
        return response
