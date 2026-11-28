"""Minimal client for the Privara Unmask API v1.

This file is self-contained on purpose: the same module ships with the OpenCTI
connector and the Cortex analyzer, so each integration can live in its own
upstream repository without a shared package.

Behaviour:
    - TLS verification is always on (requests' default CA bundle, or
      ``REQUESTS_CA_BUNDLE`` / proxies from the environment).
    - Every request has a timeout; redirects are not followed.
    - Retries happen only on HTTP 429 and 5xx, honouring ``Retry-After``.
      Uploads always carry an ``Idempotency-Key``, so a retried upload is never
      charged twice.
    - Job polling follows the server's ``Retry-After`` hint and never polls
      faster than every 15 seconds.
    - An upload answered 409 ``idempotency_in_progress`` (the same upload is
      still being processed) is retried after its ``Retry-After``.
    - Before uploading, a sample is looked up by SHA-256 (free). Only a charged
      result (live or dead) from the last 30 days is reused, like the server's
      own duplicate rule; after a ``none`` / ``void`` / failed / canceled job the
      sample is analysed again, under a new Idempotency-Key derived from that
      job (see ``idempotency_key``).
    - The API key is only ever placed in the ``Authorization`` header. It is
      never logged, never part of an exception message and never in ``repr()``.

API contract: https://app.tajapps.com/api/unmask/v1 (Unmask API v1).
"""

from __future__ import annotations

import email.utils
import hashlib
import time
from typing import Any, Callable
from urllib.parse import quote, urlsplit

import requests

__all__ = [
    "CHARGED_OUTCOMES",
    "DEFAULT_BASE_URL",
    "DEFAULT_MAX_FILE_MB",
    "REFUSED_REASONS",
    "UnmaskClient",
    "UnmaskError",
    "UnmaskTimeout",
    "defang",
    "dashboard_url",
    "idempotency_key",
    "liveness_text",
    "outcome_label",
]

CLIENT_VERSION = "1.0"
# Default only; the OpenCTI connector always passes its `api_base_url` setting.
DEFAULT_BASE_URL = "https://app.tajapps.com/api/unmask/v1"  # noqa: VC104
# Used only when GET /balance cannot be read.
DEFAULT_MAX_FILE_MB = 200
# Job states after which the result no longer changes.
FINAL_STATUSES = frozenset({"done", "failed", "canceled"})
PENDING_STATUSES = frozenset({"queued", "running"})
# The API asks clients not to poll a job faster than this (seconds).
MIN_POLL_INTERVAL = 15.0
LIMITS_TTL = 3600.0
# Outcomes the server reuses for a resubmitted sample (it never charges twice for them).
CHARGED_OUTCOMES = frozenset({"live", "dead"})
# The server's duplicate window: the same sample within this many days returns the
# earlier charged result at no charge (API-V1-SPEC.md, "Outcomes and money").
REUSE_MAX_AGE_DAYS = 30
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# Human text for the API's refused codes (submit answer and job `refused.code`).
REFUSED_REASONS = {
    "not_apk": "it is not an Android package",
    "bad_archive": "the archive is damaged",
    "manifest_unreadable": "its Android manifest cannot be read",
    "too_large": "it is larger than the Privara size limit",
    "zip_bomb": "it looks like a zip bomb",
    "unsafe_entry": "the archive contains an unsafe entry",
    "known_clean": "it is a known clean app",
    "duplicate_in_batch": "the same file was sent twice in one batch",
}

_OUTCOME_LABELS = {
    "live": "C2 found and reachable during the analysis",
    "dead": "C2 found but not reachable during the analysis",
    "none": "no C2 found",
    "void": "the analysis failed on the Privara side (never charged)",
}
_STATUS_LABELS = {
    "failed": "the analysis failed (not charged)",
    "canceled": "the analysis was canceled (not charged)",
    "queued": "waiting for a device",
    "running": "analysis running",
}


def outcome_label(job: dict[str, Any]) -> str:
    """One line describing a job's result (outcome when done, else status)."""
    outcome = job.get("outcome")
    if outcome:
        return _OUTCOME_LABELS.get(outcome, outcome)
    status = job.get("status") or "unknown"
    if status == "canceled" and job.get("canceled_reason") == "trial_ended":
        # The free trial is 10 tries or one C2; this sample was waiting when the trial's first C2 ended
        # it (Unmask API v1, 2026-11-27). Not charged; it can be run at the normal price.
        return (
            "not run: the free trial ended with its first C2 result (not charged); run it at the normal "
            "price from the Privara dashboard or with POST /batches/{batch_id}/continue"
        )
    return _STATUS_LABELS.get(status, status)


_LIVENESS_LABELS = {
    "live": "answered",
    "unreachable": "did not answer",
    "unknown": "not confirmed",
}


def liveness_text(entry: dict[str, Any]) -> str:
    """One line on a C2's liveness check (``liveness`` block, clarifications 12-13).

    Falls back to the ``live`` flag when the server sent no ``liveness``. Unknown
    fields and states are tolerated.
    """
    liveness = entry.get("liveness")
    if not isinstance(liveness, dict) or not liveness.get("state"):
        return "answered" if entry.get("live") else "did not answer"
    state = str(liveness.get("state"))
    text = _LIVENESS_LABELS.get(state, state)
    explain = str(liveness.get("explain") or "").strip()
    reason = str(liveness.get("reason") or "").strip()
    if explain:
        text += f": {explain}"
    elif reason:
        text += f" ({reason})"
    return text


def idempotency_key(prefix: str, sha256: str, after_job_id: str | None = None) -> str:
    """The Idempotency-Key of an upload: ``<prefix>-<sha256>``.

    A sample analysed again after a result that is not reused (``none``,
    ``void``, ``failed``, ``canceled``) gets ``<prefix>-<sha256>-<16 hex>``,
    the hex being derived from that earlier job's id: the server's 24 h
    idempotency window would otherwise replay the earlier job. The key stays
    deterministic, so a retried upload is still never charged twice. Always 8 to
    128 characters of ``[A-Za-z0-9_.:-]``; the job id itself (opaque) is hashed,
    never parsed.
    """
    key = f"{prefix}-{sha256.lower()}"
    if after_job_id:
        key += "-" + hashlib.sha256(after_job_id.encode()).hexdigest()[:16]
    return key[:128]


class UnmaskError(Exception):
    """An error answer from the API (or a transport failure).

    Attributes:
        status: HTTP status code, or ``None`` for a transport failure.
        code: The API's machine code (e.g. ``insufficient_balance``,
            ``invalid_key``, ``missing_scope``, ``not_found``).
        message: The API's human sentence.
    """

    def __init__(
        self,
        status: int | None,
        code: str,
        message: str,
        retry_after: float | None = None,
    ):
        super().__init__(
            f"{code}: {message}"
            if status is None
            else f"HTTP {status} {code}: {message}"
        )
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after

    @property
    def transient(self) -> bool:
        return self.status is None or self.status == 429 or self.status >= 500


class UnmaskTimeout(Exception):
    """The job did not reach a final state within the allowed wait.

    The job keeps running on the Privara side. Its last known state is kept in
    ``job`` so the caller can report the job id.
    """

    def __init__(self, job: dict[str, Any], waited: float):
        super().__init__(
            f"job {job.get('job_id')} still {job.get('status')} after {int(waited)}s"
        )
        self.job = job
        self.waited = waited


def defang(value: str) -> str:
    """Defang an IOC for display (only used when the API did not send ``defanged``)."""
    out = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    head, sep, tail = out.partition("://")
    if not sep:
        head, tail = "", out
    host, slash, rest = tail.partition("/")
    if "[" not in host and host.count(".") >= 1:
        idx = host.rfind(".")
        host = host[:idx] + "[.]" + host[idx + 1 :]
    return f"{head}{sep}{host}{slash}{rest}"


def dashboard_url(base_url: str, path: str = "/dashboard/unmask/wallet") -> str:
    """Return a page on the Privara web app that serves ``base_url``."""
    parts = urlsplit(base_url)
    return f"{parts.scheme}://{parts.netloc}{path}"


def _parse_retry_after(value: str | None, default: float | None) -> float | None:
    if not value:
        return default
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return default
    if when is None:
        return default
    return max(0.0, when.timestamp() - time.time())


class UnmaskClient:
    """Talks to the Unmask API with one API key.

    Args:
        api_key: An Unmask API key (``pvu_...``) with the ``submit`` and ``read`` scopes.
        base_url: API base URL. Must be https (http is accepted for localhost only, for tests).
        integration: Short name of the integration, used in the User-Agent
            (``privara-unmask-<integration>/1.0``).
        timeout: Seconds for connect + read of one request (uploads get 4x).
        max_retries: Retries per request on 429 / 5xx.
        max_retry_after: Longest ``Retry-After`` the client will honour on 429 / 5xx;
            a longer one is returned to the caller as an error instead of blocking.
        session: Optional ``requests.Session`` (tests).
        sleep: Optional sleep function (tests).
        clock: Optional monotonic clock (tests).
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        integration: str = "client",
        timeout: float = 30.0,
        max_retries: int = 3,
        max_retry_after: float = 120.0,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not api_key or not api_key.strip():
            raise ValueError("An Unmask API key is required")
        parts = urlsplit(base_url)
        if parts.scheme != "https" and not (
            parts.scheme == "http" and parts.hostname in _LOCAL_HOSTS
        ):
            raise ValueError("The Unmask API URL must use https")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_retry_after = max_retry_after
        self._sleep = sleep
        self._clock = clock
        self._api_key = api_key.strip()
        self._session = session or requests.Session()
        self._session.verify = True
        self._user_agent = f"privara-unmask-{integration}/{CLIENT_VERSION}"
        self._limits: dict[str, Any] | None = None
        self._limits_at = 0.0

    def __repr__(self) -> str:
        return f"UnmaskClient(base_url={self.base_url!r})"

    # ------------------------------------------------------------------ HTTP

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "User-Agent": self._user_agent,
        }
        if extra:
            headers.update(extra)
        return headers

    def _send(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send one request, retrying on 429 / 5xx. Returns a 2xx/3xx response."""
        url = f"{self.base_url}{path}"
        extra_headers = kwargs.pop("headers", None)
        timeout = kwargs.pop("timeout", self.timeout)
        attempt = 0
        while True:
            try:
                response = self._session.request(
                    method,
                    url,
                    headers=self._headers(extra_headers),
                    timeout=timeout,
                    allow_redirects=False,
                    **kwargs,
                )
            except requests.Timeout as err:
                raise UnmaskError(
                    None, "timeout", f"no answer from the Unmask API within {timeout}s"
                ) from err
            except requests.RequestException as err:
                # Only the exception class: its text can contain the URL and headers.
                raise UnmaskError(
                    None,
                    "network_error",
                    f"cannot reach the Unmask API ({type(err).__name__})",
                ) from err

            status = response.status_code
            if (status == 429 or status >= 500) and attempt < self.max_retries:
                delay = _parse_retry_after(
                    response.headers.get("Retry-After"),
                    default=min(2.0 * 2**attempt, 60.0),
                )
                if delay is not None and delay <= self.max_retry_after:
                    attempt += 1
                    self._sleep(delay)
                    continue
            if status >= 400:
                raise self._error_from(response)
            return response

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        return self._json(self._send(method, path, **kwargs))

    @staticmethod
    def _json(response: requests.Response) -> Any:
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as err:
            raise UnmaskError(
                response.status_code,
                "bad_response",
                "the Unmask API answered with something that is not JSON",
            ) from err

    @staticmethod
    def _error_from(response: requests.Response) -> UnmaskError:
        code, message = "http_error", response.reason or "request failed"
        try:
            body = response.json()
            error = body.get("error") if isinstance(body, dict) else None
            if isinstance(error, dict):
                code = str(error.get("code") or code)
                message = str(error.get("message") or message)
        except ValueError:
            pass
        return UnmaskError(
            response.status_code,
            code,
            message[:500],
            retry_after=_parse_retry_after(response.headers.get("Retry-After"), None),
        )

    # ------------------------------------------------------------- endpoints

    def submit_sample(
        self,
        filename: str,
        content: bytes,
        idempotency_key: str | None = None,
        label: str | None = None,
        notify_email: bool | None = None,
    ) -> dict[str, Any]:
        """POST /samples with one file. Returns the batch answer (``jobs[0]`` is this file).

        The idempotency key (8-128 chars of ``[A-Za-z0-9_.:-]``) defaults to the
        file's SHA-256, so submitting the same sample again within 24 hours
        returns the same job and charges nothing.
        """
        if idempotency_key is None:
            idempotency_key = hashlib.sha256(content).hexdigest()
        data: dict[str, str] = {}
        if label:
            data["label"] = label[:100]
        if notify_email is not None:
            data["notify_email"] = "true" if notify_email else "false"
        attempt = 0
        while True:
            try:
                return self._request(
                    "POST",
                    "/samples",
                    files=[("files", (filename, content, "application/octet-stream"))],
                    data=data,
                    headers={"Idempotency-Key": idempotency_key},
                    timeout=self.timeout * 4,
                )
            except UnmaskError as err:
                # The same upload (same key) is still being processed: wait, then
                # ask again; the answer is then the stored one, charged once.
                if err.code != "idempotency_in_progress" or attempt >= self.max_retries:
                    raise
                delay = err.retry_after if err.retry_after is not None else 10.0
                if delay > self.max_retry_after:
                    raise
                attempt += 1
                self._sleep(max(1.0, delay))

    def get_job(self, job_id: str) -> dict[str, Any]:
        """GET /jobs/{job_id}."""
        return self._request("GET", f"/jobs/{quote(job_id, safe='')}")

    def _get_job_with_hint(self, job_id: str) -> tuple[dict[str, Any], float | None]:
        """GET /jobs/{job_id} and the server's ``Retry-After`` polling hint (seconds)."""
        response = self._send("GET", f"/jobs/{quote(job_id, safe='')}")
        return self._json(response), _parse_retry_after(
            response.headers.get("Retry-After"), None
        )

    def find_jobs(self, sha256: str, limit: int = 20) -> list[dict[str, Any]]:
        """GET /jobs?sha256=: this account's jobs for one sample, newest first (no charge)."""
        answer = self._request(
            "GET", "/jobs", params={"sha256": sha256.lower(), "limit": limit}
        )
        jobs = answer.get("jobs") if isinstance(answer, dict) else answer
        return [job for job in jobs or [] if isinstance(job, dict)]

    def lookup(
        self, sha256: str, now: float | None = None
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Look a sample up before uploading it: ``(job to reuse, earlier job)``.

        - a ``done`` job with a charged outcome (``live`` / ``dead``) that
          finished within ``REUSE_MAX_AGE_DAYS`` comes back in full as the job
          to reuse (nothing is uploaded, nothing charged);
        - else a ``queued`` / ``running`` job is returned to be waited for;
        - else ``(None, newest earlier job or None)``: the sample is uploaded
          again. Pass the earlier job to ``idempotency_key`` so the upload is not
          replayed onto it.
        """
        jobs = [job for job in self.find_jobs(sha256) if job.get("job_id")]
        now = time.time() if now is None else now
        oldest = now - REUSE_MAX_AGE_DAYS * 86400
        for job in jobs:
            finished = job.get("finished_at")
            if (
                job.get("status") == "done"
                and job.get("outcome") in CHARGED_OUTCOMES
                and isinstance(finished, (int, float))
                and finished >= oldest
            ):
                return self.get_job(job["job_id"]), None
        for job in jobs:
            if job.get("status") in PENDING_STATUSES:
                return job, None
        return None, (jobs[0] if jobs else None)

    def find_reusable_job(self, sha256: str) -> dict[str, Any] | None:
        """The job ``lookup`` would reuse or wait for, else None."""
        return self.lookup(sha256)[0]

    def get_balance(self) -> dict[str, Any]:
        """GET /balance."""
        return self._request("GET", "/balance")

    def get_limits(self) -> dict[str, Any]:
        """``limits`` from GET /balance (cached for an hour)."""
        now = self._clock()
        if self._limits is None or now - self._limits_at > LIMITS_TTL:
            limits = self.get_balance().get("limits")
            self._limits = limits if isinstance(limits, dict) else {}
            self._limits_at = now
        return self._limits

    def max_file_bytes(self) -> int:
        """The API's file size limit in bytes (``DEFAULT_MAX_FILE_MB`` if unknown)."""
        try:
            max_mb = self.get_limits().get("max_file_mb")
        except UnmaskError as err:
            if not err.transient:
                raise
            max_mb = None
        if not isinstance(max_mb, (int, float)) or max_mb <= 0:
            max_mb = DEFAULT_MAX_FILE_MB
        return int(max_mb * 1024 * 1024)

    def wait_for_job(
        self,
        job_id: str,
        max_wait: float,
        initial_interval: float = 30.0,
        max_interval: float = 120.0,
        on_poll: Callable[[dict[str, Any]], None] | None = None,
        max_transient_errors: int = 5,
    ) -> dict[str, Any]:
        """Poll GET /jobs/{job_id} until a final state.

        The delay between two polls is the server's ``Retry-After`` when it sends
        one, else an exponential backoff from ``initial_interval`` to
        ``max_interval``; never less than 15 seconds.

        Raises:
            UnmaskTimeout: the job is still queued/running after ``max_wait`` seconds.
            UnmaskError: a non-transient API error (e.g. 401 invalid_key, 404 not_found).
        """
        started = self._clock()
        interval = max(MIN_POLL_INTERVAL, initial_interval)
        errors = 0
        job: dict[str, Any] = {"job_id": job_id, "status": "queued"}
        while True:
            hint = None
            try:
                job, hint = self._get_job_with_hint(job_id)
                errors = 0
            except UnmaskError as err:
                errors += 1
                if not err.transient or errors > max_transient_errors:
                    raise
            else:
                if on_poll is not None:
                    on_poll(job)
                if job.get("status") in FINAL_STATUSES:
                    return job
            waited = self._clock() - started
            remaining = max_wait - waited
            # Not enough time left for one more poll at the minimum interval.
            if remaining < MIN_POLL_INTERVAL:
                raise UnmaskTimeout(job, waited)
            delay = max(MIN_POLL_INTERVAL, hint if hint is not None else interval)
            self._sleep(min(delay, remaining))
            interval = min(interval * 1.5, max_interval)
