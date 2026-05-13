# -*- coding: utf-8 -*-
"""IPQS client module."""

import time
from typing import Optional

from pycti import OpenCTIConnectorHelper
from requests import RequestException, session
from requests.exceptions import (
    ConnectTimeout,
    HTTPError,
    InvalidURL,
    JSONDecodeError,
    ProxyError,
)


class IPQSClient:  # pylint: disable=too-few-public-methods
    """IPQS client."""

    _SCAN_ENDPOINT = "/malware/scan"
    _LOOKUP_ENDPOINT = "/malware/lookup"
    _POSTBACK_ENDPOINT = "/postback"

    # Polling defaults for asynchronous scans.
    _MAX_POLLING_ATTEMPTS = 9
    _POLLING_INTERVAL_SECONDS = 10
    _REQUEST_TIMEOUT_SECONDS = 60

    def __init__(
        self, helper: OpenCTIConnectorHelper, base_url: str, api_key: str
    ) -> None:
        """Initialize IPQS client."""
        self.helper = helper
        self.url = base_url.rstrip("/") if base_url else base_url
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
            "result": "Result",
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
        params: Optional[dict] = None,
        file: Optional[dict] = None,
    ) -> Optional[dict]:
        """Send a request to IPQS and return the decoded JSON payload.

        Returns ``None`` when the request fails because of a network/SSL/HTTP
        error, an unavailable upstream service, or an invalid JSON payload.
        Callers MUST handle ``None`` explicitly.
        """
        url = f"{self.url}{endpoint}"
        is_post = bool(file) or bool(params and params.get("url"))
        try:
            self.helper.log_info(f"IPQS request: {endpoint}")
            if is_post:
                response = self.session.post(
                    url,
                    headers=self.headers,
                    files=file,
                    json=params,
                    timeout=self._REQUEST_TIMEOUT_SECONDS,
                )
            else:
                response = self.session.get(
                    url,
                    headers=self.headers,
                    params=params,
                    timeout=self._REQUEST_TIMEOUT_SECONDS,
                )

            if response.status_code == 503:
                self.helper.log_error(
                    f"IPQS service unavailable (HTTP 503) on {endpoint}."
                )
                return None
            if response.status_code >= 500:
                self.helper.log_error(
                    f"IPQS server error (HTTP {response.status_code}) on {endpoint}."
                )
                return None
            if response.status_code == 401:
                self.helper.log_error(
                    "IPQS authentication failed (HTTP 401); check IPQS_ANALYZER_API_KEY."
                )
                return None
            response.raise_for_status()

            try:
                return response.json()
            except (JSONDecodeError, ValueError) as error:
                self.helper.log_error(
                    f"IPQS returned a non-JSON response on {endpoint}: {error}"
                )
                return None
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            self.helper.log_error(
                f"Connection error while contacting IPQS ({endpoint}): {error}"
            )
            return None
        except HTTPError as error:
            self.helper.log_error(f"HTTP error from IPQS ({endpoint}): {error}")
            return None
        except RequestException as error:
            self.helper.log_error(
                f"Unexpected error while contacting IPQS ({endpoint}): {error}"
            )
            return None

    def get_ipqs_info(
        self,
        file: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Optional[dict]:
        """Return the IPQS data for an artifact or URL.

        The lookup endpoint is tried first to leverage the 24h cache; on a
        cache miss the scan endpoint is called and the postback endpoint is
        polled until a final result is returned, an error occurs, or the
        polling budget is exhausted.
        """
        if not file and not params:
            self.helper.log_error(
                "get_ipqs_info called without 'file' or 'params'; nothing to query."
            )
            return None

        # Try the cache first.
        response = self._query(self._LOOKUP_ENDPOINT, file=file, params=params)
        if response is None:
            self.helper.log_error("No response received from IPQS lookup request.")
            return None
        if response.get("status") == "cached":
            return response

        # Cache miss: submit a scan request.
        response = self._query(self._SCAN_ENDPOINT, file=file, params=params)
        if response is None:
            self.helper.log_error("No response received from IPQS scan request.")
            return None

        if not response.get("success", False):
            # Scan rejected (invalid input, no credits, etc.) — surface as-is.
            return response

        request_id = response.get("request_id")
        if not request_id:
            self.helper.log_error(
                "Scan response missing 'request_id'; cannot poll for results."
            )
            return response

        # Poll the postback endpoint for an asynchronous result.
        postback_params = {"request_id": request_id}
        for _ in range(self._MAX_POLLING_ATTEMPTS):
            if response.get("status") != "pending":
                break
            time.sleep(self._POLLING_INTERVAL_SECONDS)
            postback_response = self._query(
                self._POSTBACK_ENDPOINT, params=postback_params
            )
            if postback_response is None:
                self.helper.log_error(
                    "No response received from IPQS during postback polling; "
                    "returning the last known response."
                )
                break
            response = postback_response
            if not response.get("success", False):
                self.helper.log_error(
                    f"IPQS postback returned failure: {response.get('message')}"
                )
                break

        return response
