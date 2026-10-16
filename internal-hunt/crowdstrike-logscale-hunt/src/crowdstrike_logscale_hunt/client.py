"""LogScale query jobs client of the CrowdStrike LogScale hunt connector."""

import threading
import time
from collections.abc import Callable, Hashable
from datetime import datetime
from typing import Any
from urllib.parse import quote

import requests
from connectors_sdk.connectors.internal_hunt import (
    HuntApiClient,
    HuntExecutionError,
    RunDeadline,
)

TOKEN_PATH = "/oauth2/token"
TOKEN_REFRESH_MARGIN_SECONDS = 60
MAX_EVENTS = 10000
"""Largest number of events read per query (bounds the ``tail`` of the query)."""

COUNT_FIELD = "_count"


def epoch_ms(value: datetime) -> int:
    """Return a datetime as epoch milliseconds."""
    return int(value.timestamp() * 1000)


class QueryResult:
    """Results of a LogScale query job.

    Attributes:
        events: Events of the query.
        warnings: Warnings returned by LogScale (e.g. partial results).
    """

    def __init__(self, events: list[dict[str, Any]], warnings: list[str]) -> None:
        """Initialize the result.

        Args:
            events: Events of the query.
            warnings: Warnings returned by LogScale.
        """
        self.events = events
        self.warnings = warnings


class LogScaleClient(HuntApiClient):
    """Client of the LogScale query jobs API.

    With Falcon Next-Gen SIEM, the API is served under ``/humio`` by the
    CrowdStrike API and authenticated with OAuth2 client credentials; with a
    LogScale cluster, it is authenticated with an API token. A query runs as a
    query job over the run window, polled until done within the run deadline,
    then deleted.
    """

    def __init__(
        self,
        base_url: str,
        path_prefix: str,
        repository: str,
        verify_ssl: bool,
        poll_interval: float,
        logger: Any,
        api_token: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the CrowdStrike API or of the LogScale cluster.
            path_prefix: Path of the LogScale API under the base URL.
            repository: Repository or view searched.
            verify_ssl: Whether to verify the TLS certificate.
            poll_interval: Seconds between two status checks without LogScale hint.
            logger: Connector logger.
            api_token: LogScale API token (LogScale clusters).
            client_id: CrowdStrike API client ID (Falcon).
            client_secret: CrowdStrike API client secret (Falcon).
            clock: Monotonic clock used for the token expiry.
        """
        super().__init__(base_url=base_url, ssl_verify=verify_ssl)
        self._jobs_path = (
            f"{path_prefix.rstrip('/')}/api/v1/repositories/"
            f"{quote(repository, safe='')}/queryjobs"
        )
        self._poll_interval = poll_interval
        self._logger = logger
        self._api_token = api_token
        self._client_id = client_id
        self._client_secret = client_secret
        self._clock = clock
        self._token_lock = threading.Lock()
        self._access_token: str | None = api_token
        self._token_expires_at = float("inf") if api_token else 0.0
        self._jobs_lock = threading.Lock()
        self._active_jobs: dict[Hashable, str] = {}

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send a request with the current access token."""
        if path != TOKEN_PATH and self._access_token:
            headers = dict(kwargs.pop("headers", None) or {})
            headers["Authorization"] = f"Bearer {self._access_token}"
            kwargs["headers"] = headers
        return super()._raw_request(method, path, **kwargs)

    def _authenticate(self, deadline: RunDeadline) -> None:
        """Obtain a CrowdStrike API access token when none is valid."""
        with self._token_lock:
            if self._clock() < self._token_expires_at:
                return
            answer = self.hunt_request(
                "POST",
                TOKEN_PATH,
                deadline,
                "The CrowdStrike API authentication",
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
            token = answer.get("access_token") if isinstance(answer, dict) else None
            if not token:
                raise HuntExecutionError(
                    "The CrowdStrike API did not return an access token."
                )
            expires_in = answer.get("expires_in")
            lifetime = expires_in if isinstance(expires_in, (int, float)) else 1799
            self._access_token = str(token)
            self._token_expires_at = (
                self._clock() + lifetime - TOKEN_REFRESH_MARGIN_SECONDS
            )

    def query(
        self,
        query: str,
        start: datetime,
        end: datetime,
        deadline: RunDeadline,
        job_key: Hashable,
    ) -> QueryResult:
        """Run a query over a time window.

        Args:
            query: LogScale query.
            start: Start of the time window.
            end: End of the time window.
            deadline: Run deadline.
            job_key: Key of the run, used to cancel its query job.

        Returns:
            The events and warnings of the query.

        Raises:
            HuntExecutionError: If LogScale rejects or cancels the query.
            HuntTimeoutError: If the query does not complete before the deadline.
        """
        self._authenticate(deadline)
        created = self.hunt_request(
            "POST",
            self._jobs_path,
            deadline,
            "The LogScale query job creation",
            json={
                "queryString": query,
                "start": epoch_ms(start),
                "end": epoch_ms(end),
                "isLive": False,
            },
        )
        job_id = created.get("id") if isinstance(created, dict) else None
        if not job_id:
            raise HuntExecutionError("LogScale did not return a query job id.")
        path = f"{self._jobs_path}/{quote(str(job_id), safe='')}"
        with self._jobs_lock:
            self._active_jobs[job_key] = path
        try:
            return self._wait_for_job(path, deadline)
        finally:
            with self._jobs_lock:
                owned = self._active_jobs.pop(job_key, None) is not None
            if owned:
                self._delete_job(path)

    def cancel(self, job_key: Hashable) -> None:
        """Delete the running query job of a run, if any.

        Args:
            job_key: Key of the run.
        """
        with self._jobs_lock:
            path = self._active_jobs.pop(job_key, None)
        if path is not None:
            self._delete_job(path)

    def _wait_for_job(self, path: str, deadline: RunDeadline) -> QueryResult:
        """Poll a query job until it is done."""
        while True:
            answer = self.hunt_request(
                "GET", path, deadline, "The LogScale query job status"
            )
            if not isinstance(answer, dict):
                raise HuntExecutionError("LogScale returned an unexpected answer.")
            if answer.get("cancelled"):
                raise HuntExecutionError("The LogScale query job was cancelled.")
            if answer.get("done"):
                events = [
                    event
                    for event in answer.get("events") or []
                    if isinstance(event, dict)
                ]
                warnings = [
                    str(
                        warning.get("message") if isinstance(warning, dict) else warning
                    )
                    for warning in answer.get("warnings") or []
                ]
                return QueryResult(events, warnings)
            meta = answer.get("metaData") or {}
            poll_after = meta.get("pollAfter")
            interval = (
                poll_after / 1000
                if isinstance(poll_after, (int, float)) and poll_after > 0
                else self._poll_interval
            )
            deadline.check("The LogScale query job")
            deadline.sleep(interval)

    def _delete_job(self, path: str) -> None:
        """Delete a query job (best effort, LogScale also expires unpolled jobs)."""
        error = self.cleanup_request("DELETE", path, "The LogScale query job deletion")
        if error:
            self._logger.warning(error, {"job": path})
