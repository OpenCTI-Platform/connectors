"""JSON-RPC client for the FortiSandbox API."""

from __future__ import annotations

import base64
import time
from typing import Optional

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter, Retry


class FortiSandboxAPIError(Exception):
    """Custom exception for FortiSandbox API errors."""


class FortisandboxClient:
    """Thin client around the FortiSandbox JSON-RPC API."""

    TIMEOUT = 60

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        api_base_url: str,
        username: str,
        password: str,
        api_version: str = "4.2.4",
        ssl_verify: bool = True,
    ) -> None:
        """
        Initialize the FortiSandbox client.

        :param helper: The OpenCTI connector helper (used for logging).
        :param api_base_url: The FortiSandbox base URL (without /jsonrpc).
        :param username: The FortiSandbox API username.
        :param password: The FortiSandbox API password.
        :param api_version: The JSON-RPC API version to send with each request.
        :param ssl_verify: Whether to verify the TLS certificate.
        """
        self.helper = helper
        self.base_url = str(api_base_url).rstrip("/")
        self.jsonrpc_url = self.base_url + "/jsonrpc"
        self.username = username
        self.password = password
        self.api_version = api_version
        self.session_token: Optional[str] = None

        self.session = requests.Session()
        self.session.verify = ssl_verify
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

    def _call(self, method: str, params: list, with_session: bool = True) -> dict:
        payload = {
            "method": method,
            "params": params,
            "id": 1,
            "version": self.api_version,
        }
        if with_session and self.session_token:
            payload["session"] = self.session_token
        try:
            response = self.session.post(
                self.jsonrpc_url, json=payload, timeout=self.TIMEOUT
            )
            response.raise_for_status()
        except requests.HTTPError as err:
            status = err.response.status_code if err.response is not None else "?"
            reason = err.response.reason if err.response is not None else ""
            raise FortiSandboxAPIError(
                f"FortiSandbox API request error: {status} ({reason})"
            ) from err
        except requests.RequestException as err:
            # Retry exhaustion (RetryError), timeouts and connection errors are not
            # HTTPError; wrap them so callers always see a FortiSandboxAPIError.
            raise FortiSandboxAPIError(
                f"FortiSandbox API request failed: {type(err).__name__}"
            ) from err
        try:
            return response.json()
        except ValueError as err:
            raise FortiSandboxAPIError(
                "FortiSandbox returned a non-JSON response"
            ) from err

    def login(self) -> str:
        """Authenticate and cache the session token."""
        data = self._call(
            "exec",
            [
                {
                    "url": "/sys/login/user",
                    "name": self.username,
                    "passwd": self.password,
                }
            ],
            with_session=False,
        )
        token = data.get("session")
        if not token:
            raise FortiSandboxAPIError("FortiSandbox login failed (no session token)")
        self.session_token = token
        return token

    def logout(self) -> None:
        """Best-effort logout to release the session."""
        if self.session_token:
            try:
                self._call("exec", [{"url": "/sys/logout"}])
            except FortiSandboxAPIError:
                pass
            self.session_token = None

    def _ensure_session(self) -> None:
        if not self.session_token:
            self.login()

    def get_file_rating(self, checksum: str, ctype: str = "sha256") -> Optional[dict]:
        """Return the FortiSandbox rating record for a file hash, or ``None``."""
        self._ensure_session()
        data = self._call(
            "get",
            [{"url": "/scan/result/filerating", "checksum": checksum, "ctype": ctype}],
        )
        return self._extract_data(data)

    def submit_file(self, filename: str, content: bytes) -> Optional[str]:
        """Submit a file for on-demand analysis, returning its submission id."""
        self._ensure_session()
        encoded = base64.b64encode(content).decode("ascii")
        data = self._call(
            "set",
            [
                {
                    "url": "/alert/ondemand/submit-file",
                    "file": encoded,
                    "filename": filename,
                }
            ],
        )
        result = self._extract_result(data)
        if isinstance(result, dict):
            return (
                result.get("sid")
                or result.get("submit_id")
                or (result.get("data") or {}).get("sid")
            )
        return None

    def get_submission_verdict(
        self, sid: str, max_wait: int = 300, interval: int = 30
    ) -> Optional[dict]:
        """Poll a submission until any of its jobs has a rating (bounded by max_wait)."""
        self._ensure_session()
        waited = 0
        while True:
            data = self._call(
                "get",
                [{"url": "/scan/result/get-jobs-of-submission", "sid": sid}],
            )
            for job in self._extract_jobs(data):
                rating = self._get_job(self._job_id(job))
                if rating is not None:
                    return rating
            # Stop once the budget is spent (>=, not >): when the accumulated wait
            # reaches max_wait we must return without sleeping one more interval.
            waited += interval
            if waited >= max_wait:
                return None
            time.sleep(interval)

    @staticmethod
    def _job_id(job):
        if isinstance(job, dict):
            return job.get("jid") or job.get("job_id")
        return job

    def _get_job(self, jid) -> Optional[dict]:
        data = self._call("get", [{"url": "/scan/result/job", "jid": jid}])
        return self._extract_data(data)

    @staticmethod
    def _extract_result(payload) -> Optional[dict]:
        if not isinstance(payload, dict):
            return None
        result = payload.get("result")
        if isinstance(result, list):
            result = result[0] if result else None
        return result if isinstance(result, dict) else None

    @classmethod
    def _extract_data(cls, payload) -> Optional[dict]:
        result = cls._extract_result(payload)
        if not isinstance(result, dict):
            return None
        data = result.get("data")
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return data[0] if data else None
        if "rating" in result:
            return result
        return None

    @classmethod
    def _extract_jobs(cls, payload) -> list:
        result = cls._extract_result(payload)
        if not isinstance(result, dict):
            return []
        data = result.get("data")
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            jobs = data.get("jobs")
            if isinstance(jobs, list):
                return jobs
        return []
