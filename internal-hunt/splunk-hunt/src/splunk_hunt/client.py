"""Splunk REST API client running hunt searches as search jobs."""

import base64
import threading
from collections.abc import Hashable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from connectors_sdk.connectors.internal_hunt import (
    HuntApiClient,
    HuntExecutionError,
    RunDeadline,
)

JOB_TTL_SECONDS = 600
RESULTS_PAGE_SIZE = 10000


def splunk_time(value: datetime) -> str:
    """Format a datetime for the Splunk earliest_time/latest_time parameters."""
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}+00:00"


class SplunkClient(HuntApiClient):
    """Client of the Splunk search job API.

    A hunt search is created as a search job over the run time window, polled
    until done within the run deadline, then its results are read page by page
    (at most ``max_results``) and the job is deleted.
    """

    def __init__(
        self,
        base_url: str,
        token: str | None,
        username: str | None,
        password: str | None,
        verify_ssl: bool,
        app: str,
        owner: str,
        poll_interval: float,
        logger: Any,
    ) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the Splunk REST API.
            token: Splunk authentication token (takes precedence).
            username: Splunk user name (basic authentication).
            password: Splunk password (basic authentication).
            verify_ssl: Whether to verify the TLS certificate.
            app: App namespace of the search jobs.
            owner: User namespace of the search jobs.
            poll_interval: Seconds between two job status checks.
            logger: Connector logger.
        """
        super().__init__(base_url=base_url, ssl_verify=verify_ssl)
        self._token = token
        self._username = username
        self._password = password
        self._namespace = f"/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
        self._poll_interval = poll_interval
        self._logger = logger
        self._lock = threading.Lock()
        self._active_jobs: dict[Hashable, str] = {}

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the authentication header (token, or basic authentication)."""
        if self._token:
            return {"Authorization": f"Bearer {self._token}"}
        credentials = f"{self._username}:{self._password}".encode()
        return {"Authorization": f"Basic {base64.b64encode(credentials).decode()}"}

    def search(
        self,
        search: str,
        start: datetime,
        end: datetime,
        max_results: int,
        deadline: RunDeadline,
        job_key: Hashable,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Run a search over a time window.

        Args:
            search: SPL search (starting with ``search`` or a generating command).
            start: Start of the time window.
            end: End of the time window.
            max_results: Maximum number of results to fetch.
            deadline: Run deadline.
            job_key: Key of the run, used to cancel its search job.

        Returns:
            The total number of results and at most ``max_results`` results.

        Raises:
            HuntExecutionError: If Splunk rejects or fails the search.
            HuntTimeoutError: If the job does not complete before the deadline.
        """
        sid = self._create_job(search, start, end, deadline)
        with self._lock:
            self._active_jobs[job_key] = sid
        try:
            content = self._wait_for_job(sid, deadline)
            total = int(content.get("resultCount") or 0)
            results = self._fetch_results(sid, min(total, max_results), deadline)
            return max(total, len(results)), results
        finally:
            with self._lock:
                self._active_jobs.pop(job_key, None)
            self._delete_job(sid)

    def current_context(self, deadline: RunDeadline) -> dict[str, Any]:
        """Read the account of the connector: its user name, roles and capabilities.

        Args:
            deadline: Deadline of the call.

        Returns:
            The ``content`` of the current context (``username``, ``roles``,
            ``capabilities``).
        """
        response = self.hunt_request(
            "GET",
            "/services/authentication/current-context",
            deadline,
            "The Splunk authentication",
            params={"output_mode": "json"},
        )
        entries = response.get("entry") if isinstance(response, dict) else None
        content = (entries or [{}])[0].get("content")
        return content if isinstance(content, dict) else {}

    def cancel(self, job_key: Hashable) -> None:
        """Cancel the running search job of a run, if any.

        Args:
            job_key: Key of the run.
        """
        with self._lock:
            sid = self._active_jobs.get(job_key)
        if sid is None:
            return
        error = self.cleanup_request(
            "POST",
            f"{self._job_path(sid)}/control",
            "The Splunk search job cancellation",
            data={"action": "cancel", "output_mode": "json"},
        )
        if error:
            self._logger.warning(error, {"sid": sid})
        else:
            self._logger.info("[SPLUNK] Search job cancelled", {"sid": sid})

    def _job_path(self, sid: str) -> str:
        """Return the REST path of a search job."""
        return f"{self._namespace}/search/jobs/{quote(sid, safe='')}"

    def _create_job(
        self, search: str, start: datetime, end: datetime, deadline: RunDeadline
    ) -> str:
        """Create the search job and return its id."""
        data = {
            "search": search,
            "earliest_time": splunk_time(start),
            "latest_time": splunk_time(end),
            "exec_mode": "normal",
            "output_mode": "json",
            "rf": "*",
            "timeout": JOB_TTL_SECONDS,
        }
        response = self.hunt_request(
            "POST",
            f"{self._namespace}/search/v2/jobs",
            deadline,
            "The Splunk search job creation",
            data=data,
        )
        sid = response.get("sid") if isinstance(response, dict) else None
        if not sid:
            raise HuntExecutionError("Splunk did not return a search job id.")
        self._logger.info("[SPLUNK] Search job created", {"sid": sid})
        return str(sid)

    def _wait_for_job(self, sid: str, deadline: RunDeadline) -> dict[str, Any]:
        """Poll the search job until it is done, failed or the deadline is reached."""
        while True:
            response = self.hunt_request(
                "GET",
                self._job_path(sid),
                deadline,
                "The Splunk search job status",
                params={"output_mode": "json"},
            )
            entries = response.get("entry") if isinstance(response, dict) else None
            content: dict[str, Any] = (entries or [{}])[0].get("content") or {}
            if content.get("isFailed") or content.get("dispatchState") == "FAILED":
                messages = [
                    str(message.get("text"))
                    for message in content.get("messages") or []
                    if isinstance(message, dict) and message.get("text")
                ]
                raise HuntExecutionError(
                    "The Splunk search failed: " + ("; ".join(messages) or "no details")
                )
            if content.get("isDone") or content.get("dispatchState") == "DONE":
                return content
            deadline.check("The Splunk search job")
            deadline.sleep(self._poll_interval)

    def _fetch_results(
        self, sid: str, count: int, deadline: RunDeadline
    ) -> list[dict[str, Any]]:
        """Read the results of a done job page by page."""
        results: list[dict[str, Any]] = []
        while len(results) < count:
            page_size = min(RESULTS_PAGE_SIZE, count - len(results))
            response = self.hunt_request(
                "GET",
                f"{self._namespace}/search/v2/jobs/{quote(sid, safe='')}/results",
                deadline,
                "The Splunk search results",
                params={
                    "output_mode": "json",
                    "count": page_size,
                    "offset": len(results),
                },
            )
            page = response.get("results") if isinstance(response, dict) else None
            if not page:
                break
            results.extend(row for row in page if isinstance(row, dict))
            if len(page) < page_size:
                break
        return results[:count]

    def _delete_job(self, sid: str) -> None:
        """Delete a finished search job (best effort, the job TTL also cleans it)."""
        error = self.cleanup_request(
            "DELETE",
            self._job_path(sid),
            "The Splunk search job deletion",
            params={"output_mode": "json"},
        )
        if error:
            self._logger.warning(error, {"sid": sid})
