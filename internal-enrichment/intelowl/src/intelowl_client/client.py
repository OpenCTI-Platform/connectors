"""Minimal client for the IntelOwl REST API.

Only the two endpoints the connector needs are implemented: starting a playbook analysis
of one observable, and reading the resulting job.
"""

import time
from typing import Any, Callable

import requests

# Job statuses after which IntelOwl does no more work on a job
# (api_app/choices.py `Status` in the IntelOwl repository).
TERMINAL_JOB_STATUSES = frozenset(
    {"reported_without_fails", "reported_with_fails", "killed", "failed"}
)


class IntelOwlClientError(Exception):
    """Raised when IntelOwl rejects a request or returns something unexpected."""


class IntelOwlJobTimeoutError(IntelOwlClientError):
    """Raised when a job is still running after the configured timeout."""


class IntelOwlClient:
    """Talks to an IntelOwl instance with an API key (`Authorization: Token <key>`)."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify_ssl: bool = True,
        request_timeout: int = 30,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.request_timeout = request_timeout
        self.session = session or requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update(
            {
                "Authorization": f"Token {api_key}",
                "Accept": "application/json",
                "User-Agent": "OpenCTI-IntelOwl-Connector",
            }
        )

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(
                method, url, timeout=self.request_timeout, **kwargs
            )
        except requests.RequestException as err:
            raise IntelOwlClientError(f"Could not reach IntelOwl at {url}") from err
        if not response.ok:
            raise IntelOwlClientError(
                f"IntelOwl returned HTTP {response.status_code} for {method} {path}: "
                f"{response.text[:500]}"
            )
        try:
            return response.json()
        except ValueError as err:
            raise IntelOwlClientError(
                f"IntelOwl returned a non-JSON response for {method} {path}"
            ) from err

    def analyze_observable(
        self,
        value: str,
        classification: str,
        playbook: str,
        tlp: str,
        tags: list[str] | None = None,
    ) -> int:
        """Start `playbook` on one observable and return the new job ID.

        Args:
            value: The observable value.
            classification: IntelOwl classification: `ip`, `domain`, `url`, `hash` or `generic`.
            playbook: Name of the IntelOwl playbook to run.
            tlp: IntelOwl TLP: `CLEAR`, `GREEN`, `AMBER` or `RED`.
            tags: Tag labels to attach to the job in IntelOwl.
        """
        body = {
            "observables": [[classification, value]],
            "playbook_requested": playbook,
            "tlp": tlp,
            "tags_labels": tags or [],
            "runtime_configuration": {},
        }
        answer = self._request(
            "POST", "/api/playbook/analyze_multiple_observables", json=body
        )
        # The endpoint answers with one job per observable, either as a list or
        # wrapped in {"results": [...]} depending on the IntelOwl version.
        results = answer.get("results") if isinstance(answer, dict) else answer
        if not results or not isinstance(results, list):
            raise IntelOwlClientError(f"Unexpected analysis response: {answer!r}")
        job = results[0]
        if job.get("status") == "not_available" or "job_id" not in job:
            raise IntelOwlClientError(
                f"IntelOwl did not start the analysis: {job.get('errors') or job}"
            )
        return int(job["job_id"])

    def get_job(self, job_id: int) -> dict[str, Any]:
        """Return the job, including its analyzer reports and aggregated data model."""
        return self._request("GET", f"/api/jobs/{job_id}")

    def wait_for_job(
        self,
        job_id: int,
        poll_interval: float,
        timeout: float,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> dict[str, Any]:
        """Poll the job until IntelOwl finishes it, or raise after `timeout` seconds."""
        deadline = clock() + timeout
        while True:
            job = self.get_job(job_id)
            if job.get("status") in TERMINAL_JOB_STATUSES:
                return job
            if clock() >= deadline:
                raise IntelOwlJobTimeoutError(
                    f"IntelOwl job {job_id} is still {job.get('status')!r} after {timeout} seconds"
                )
            sleep(poll_interval)

    def job_url(self, job_id: int) -> str:
        """Link to the job in the IntelOwl web interface."""
        return f"{self.base_url}/jobs/{job_id}"
