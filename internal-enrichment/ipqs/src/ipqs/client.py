# -*- coding: utf-8 -*-
"""IPQS client module."""

import time
from typing import Optional

from pycti import OpenCTIConnectorHelper
from requests import RequestException, Response, session
from requests.exceptions import (
    ConnectTimeout,
    HTTPError,
    InvalidURL,
    JSONDecodeError,
    ProxyError,
)


class IPQSClient:
    """IPQS client.

    Speaks to two IPQS API families:

    * the fraud-and-risk-scoring endpoints (``/ip``, ``/url``, ``/email``,
      ``/phone``) used by ``IPQSConnector._process_ip`` /
      ``_process_url`` / ``_process_email`` / ``_process_phone``;
    * the malware-file-scanner endpoints (``/malware/scan``,
      ``/malware/lookup``, ``/postback``) used by
      ``IPQSConnector._process_artifact``. The flow is cache-first
      (lookup) then submit (scan) then poll (postback) until a final
      result is returned, the upstream surfaces an error, or the
      polling budget is exhausted.
    """

    _MALWARE_SCAN_ENDPOINT = "/malware/scan"
    _MALWARE_LOOKUP_ENDPOINT = "/malware/lookup"
    _MALWARE_POSTBACK_ENDPOINT = "/postback"

    # Polling defaults for asynchronous malware scans.
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
        self.ip_enrich_fields = {
            "zip_code": "Zip Code",
            "ISP": "ISP",
            "ASN": "ASN",
            "organization": "Organization",
            "is_crawler": "Is Crawler",
            "timezone": "Timezone",
            "mobile": "Mobile",
            "host": "Host",
            "proxy": "Proxy",
            "vpn": "VPN",
            "tor": "TOR",
            "active_vpn": "Active VPN",
            "active_tor": "Active TOR",
            "recent_abuse": "Recent Abuse",
            "bot_status": "Bot Status",
            "connection_type": "Connection Type",
            "abuse_velocity": "Abuse Velocity",
            "country_code": "Country Code",
            "region": "Region",
            "city": "City",
            "latitude": "Latitude",
            "longitude": "Longitude",
        }
        self.url_enrich_fields = {
            "unsafe": "Unsafe",
            "server": "Server",
            "domain_rank": "Domain Rank",
            "dns_valid": "DNS Valid",
            "parking": "Parking",
            "spamming": "Spamming",
            "malware": "Malware",
            "phishing": "Phishing",
            "suspicious": "Suspicious",
            "adult": "Adult",
            "category": "Category",
            "domain_age": "Domain Age",
            "domain": "IPQS: Domain",
            "ip_address": "IPQS: IP Address",
        }
        self.email_enrich_fields = {
            "valid": "Valid",
            "disposable": "Disposable",
            "smtp_score": "SMTP Score",
            "overall_score": "Overall Score",
            "first_name": "First Name",
            "generic": "Generic",
            "common": "Common",
            "dns_valid": "DNS Valid",
            "honeypot": "Honeypot",
            "deliverability": "Deliverability",
            "frequent_complainer": "Frequent Complainer",
            "spam_trap_score": "Spam Trap Score",
            "catch_all": "Catch All",
            "timed_out": "Timed Out",
            "suspect": "Suspect",
            "recent_abuse": "Recent Abuse",
            "suggested_domain": "Suggested Domain",
            "leaked": "Leaked",
            "sanitized_email": "Sanitized Email",
            "domain_age": "Domain Age",
            "first_seen": "First Seen",
        }
        self.phone_enrich_fields = {
            "formatted": "Formatted",
            "local_format": "Local Format",
            "valid": "Valid",
            "recent_abuse": "Recent Abuse",
            "VOIP": "VOIP",
            "prepaid": "Prepaid",
            "risky": "Risky",
            "active": "Active",
            "carrier": "Carrier",
            "line_type": "Line Type",
            "city": "City",
            "zip_code": "Zip Code",
            "dialing_code": "Dialing Code",
            "active_status": "Active Status",
            "leaked": "Leaked",
            "name": "Name",
            "timezone": "Timezone",
            "do_not_call": "Do Not Call",
            "country": "Country",
            "region": "Region",
        }
        # Fields surfaced in the Indicator description when enriching an
        # Artifact (and any future Url malware-scan use case).
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

    def _query(self, url: str, params: dict = None) -> Response:
        """General get method to fetch the response from ipqs."""
        try:
            response = self.session.get(url, headers=self.headers, params=params).json()
            if str(response["success"]) != "True":
                msg = response["message"]
                self.helper.log_error(f"Error: {msg}")
                return None
            return response
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            msg = "Error connecting with the ipqs."
            self.helper.log_error(f"{msg} Error: {error}")
            return None

    def get_ipqs_info(self, enrich_type, enrich_value):
        """
        Returns the IPQS data.
        """
        url = f"{self.url}/{enrich_type}"
        params = {enrich_type: enrich_value}
        try:
            response = self._query(url, params)
        except HTTPError as error:
            msg = f"Error when requesting data from ipqs. {error.response}: {error.response.reason}"
            self.helper.log_error(msg)
            raise
        return response

    # ------------------------------------------------------------------
    # Malware file scanner endpoints
    #
    # Adapted from the standalone connector proposed in PR
    # https://github.com/OpenCTI-Platform/connectors/pull/5970 — instead of
    # shipping a separate ``ipqs-analyzer`` connector, the malware-file-scanner
    # flow lives next to the existing fraud-and-risk-scoring flow so a single
    # IPQS API key can drive every supported observable type.
    # ------------------------------------------------------------------
    def _query_malware(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        file: Optional[dict] = None,
    ) -> Optional[dict]:
        """Send a request to the IPQS malware-file-scanner API.

        Returns the decoded JSON payload, or ``None`` when the request fails
        because of a network / SSL / HTTP error, an unavailable upstream
        service, or an invalid JSON payload. Callers MUST handle ``None``
        explicitly.
        """
        url = f"{self.url}{endpoint}"
        is_post = bool(file) or bool(params and params.get("url"))
        try:
            self.helper.log_info(f"IPQS malware request: {endpoint}")
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
                    "IPQS authentication failed (HTTP 401); " "check IPQS_PRIVATE_KEY."
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

    def get_malware_scan_info(
        self,
        file: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Optional[dict]:
        """Return the IPQS malware-scan data for an Artifact or URL.

        The lookup endpoint is tried first to leverage the 24h cache; on a
        cache miss the scan endpoint is called and the postback endpoint
        is polled until a final result is returned, an error occurs, or
        the polling budget is exhausted.
        """
        if not file and not params:
            self.helper.log_error(
                "get_malware_scan_info called without 'file' or 'params'; "
                "nothing to query."
            )
            return None

        # Try the cache first.
        response = self._query_malware(
            self._MALWARE_LOOKUP_ENDPOINT, file=file, params=params
        )
        if response is None:
            self.helper.log_error("No response received from IPQS lookup request.")
            return None
        if response.get("status") == "cached":
            return response

        # Cache miss: submit a scan request.
        response = self._query_malware(
            self._MALWARE_SCAN_ENDPOINT, file=file, params=params
        )
        if response is None:
            self.helper.log_error("No response received from IPQS scan request.")
            return None

        if not response.get("success", False):
            # Scan rejected (invalid input, no credits, ...) — surface as-is.
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
            postback_response = self._query_malware(
                self._MALWARE_POSTBACK_ENDPOINT, params=postback_params
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
