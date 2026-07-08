"""HTTP client for the Palo Alto Networks WildFire public API."""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Optional

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter, Retry

# WildFire returns -102 when a hash is unknown to the cloud.
VERDICT_NOT_FOUND = -102
# WildFire returns -100 while a submitted sample is still being analysed.
VERDICT_PENDING = -100


class WildfireAPIError(Exception):
    """Custom exception for Palo Alto Networks WildFire API errors."""


class PaloaltoWildfireClient:
    """Thin client around the WildFire ``get/verdict`` and ``get/report`` endpoints."""

    TIMEOUT = 60

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        api_key: str,
        base_url: str = "https://wildfire.paloaltonetworks.com/publicapi",
    ) -> None:
        """
        Initialize the WildFire client.

        :param helper: The OpenCTI connector helper (used for logging).
        :param api_key: The WildFire API key.
        :param base_url: The WildFire API base URL (cloud region or appliance).
        """
        self.helper = helper
        self.api_key = api_key
        self.base_url = str(base_url).rstrip("/")

        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=2,
            allowed_methods=None,
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _post(self, endpoint: str, data: dict) -> Optional[requests.Response]:
        url = self.base_url + endpoint
        payload = dict(data)
        payload["apikey"] = self.api_key
        try:
            response = self.session.post(url, data=payload, timeout=self.TIMEOUT)
            self.helper.connector_logger.debug(
                "[API] WildFire request", meta={"url": url}
            )
            if response.status_code == 404:
                # WildFire returns 404 when the sample/report is unknown.
                return None
            response.raise_for_status()
            return response
        except requests.HTTPError as err:
            status = err.response.status_code if err.response is not None else "?"
            reason = err.response.reason if err.response is not None else ""
            raise WildfireAPIError(
                f"WildFire API request error: {status} ({reason})"
            ) from err
        except requests.RequestException as err:
            # Retry exhaustion (RetryError), timeouts and connection errors are not
            # HTTPError; wrap them so callers always see a WildfireAPIError.
            raise WildfireAPIError(
                f"WildFire API request failed: {type(err).__name__}"
            ) from err

    def get_verdict(self, file_hash: str) -> Optional[int]:
        """
        Return the WildFire verdict code for a file hash, or ``None`` if unknown.

        Verdict codes: 0=benign, 1=malware, 2=grayware, 4=phishing,
        5=command-and-control.
        """
        response = self._post("/get/verdict", {"hash": file_hash})
        if response is None:
            return None
        verdict = self._parse_verdict(response.text)
        if verdict is None or verdict == VERDICT_NOT_FOUND or verdict < 0:
            return None
        return verdict

    def get_verdict_code(self, file_hash: str) -> Optional[int]:
        """Return the raw WildFire verdict code (including negatives), or ``None``."""
        response = self._post("/get/verdict", {"hash": file_hash})
        if response is None:
            return None
        return self._parse_verdict(response.text)

    def get_report(self, file_hash: str) -> Optional[dict]:
        """Return the WildFire report fields for a file hash, or ``None``."""
        response = self._post("/get/report", {"hash": file_hash, "format": "xml"})
        if response is None:
            return None
        return self._parse_report(response.text)

    def submit_file(self, file_name: str, content: bytes) -> Optional[str]:
        """Submit a file for analysis, returning the sample SHA-256 (or ``None``)."""
        url = self.base_url + "/submit/file"
        files = {"file": (file_name, content)}
        try:
            response = self.session.post(
                url, data={"apikey": self.api_key}, files=files, timeout=self.TIMEOUT
            )
            response.raise_for_status()
        except requests.HTTPError as err:
            status = err.response.status_code if err.response is not None else "?"
            reason = err.response.reason if err.response is not None else ""
            raise WildfireAPIError(
                f"WildFire API request error: {status} ({reason})"
            ) from err
        except requests.RequestException as err:
            raise WildfireAPIError(
                f"WildFire API request failed: {type(err).__name__}"
            ) from err
        return self._parse_sha256(response.text)

    def poll_verdict(
        self, file_hash: str, max_wait: int = 600, interval: int = 30
    ) -> Optional[int]:
        """
        Poll the verdict for a submitted sample until it is final (bounded by max_wait).

        Returns the final non-negative verdict code, or ``None`` if it stays pending,
        errors, or is rejected.
        """
        waited = 0
        while waited <= max_wait:
            verdict = self.get_verdict_code(file_hash)
            if verdict is None:
                return None
            if verdict >= 0:
                return verdict
            if verdict != VERDICT_PENDING:
                return None
            time.sleep(interval)
            waited += interval
        return None

    @staticmethod
    def _parse_sha256(xml_text: str) -> Optional[str]:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None
        node = root.find(".//sha256")
        if node is not None and node.text:
            return node.text.strip()
        return None

    @staticmethod
    def _parse_verdict(xml_text: str) -> Optional[int]:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None
        node = root.find(".//verdict")
        if node is None or node.text is None:
            return None
        try:
            return int(node.text.strip())
        except ValueError:
            return None

    @staticmethod
    def _parse_report(xml_text: str) -> Optional[dict]:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None
        file_info = root.find(".//file_info")
        if file_info is None:
            return None

        def _text(tag: str) -> Optional[str]:
            element = file_info.find(tag)
            if element is not None and element.text:
                return element.text.strip()
            return None

        return {
            "md5": _text("md5"),
            "sha1": _text("sha1"),
            "sha256": _text("sha256"),
            "filetype": _text("filetype"),
            "size": _text("size"),
            "malware": _text("malware"),
        }
