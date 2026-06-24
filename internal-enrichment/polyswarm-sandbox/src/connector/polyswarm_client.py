"""
PolySwarm Client - API interactions and PDF Reports

Production-hardened with retry logic, circuit breaker, session reuse,
and proper resource management.
"""

import io
import threading
import time
from typing import Any

import requests
from connector.polyswarm import PolyswarmAPI
from polyswarm_api.exceptions import NotFoundException
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


class CircuitBreaker:
    """Thread-safe circuit breaker for API resilience.

    States:
        CLOSED  — normal operation, requests pass through
        OPEN    — too many failures, all requests blocked for cooldown_seconds
        HALF_OPEN — cooldown expired, one test request allowed through

    After 'failure_threshold' consecutive failures the breaker opens.
    After 'cooldown_seconds' it moves to HALF_OPEN and allows one probe.
    A successful probe closes the breaker; a failed probe re-opens it.
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(
        self, failure_threshold: int = 5, cooldown_seconds: float = 300.0
    ) -> None:
        self._lock = threading.Lock()
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._state = self.CLOSED
        self._failure_count = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> str:
        """Return current breaker state, auto-transitioning OPEN → HALF_OPEN after cooldown."""
        with self._lock:
            # Lazily transition: check if cooldown has elapsed on every read
            # so callers don't need to manage timer logic themselves.
            if (
                self._state == self.OPEN
                and self._opened_at is not None
                and time.monotonic() - self._opened_at >= self.cooldown_seconds
            ):
                self._state = self.HALF_OPEN
            return self._state

    def allow_request(self) -> bool:
        """Return True if a request is allowed through the breaker."""
        return self.state != self.OPEN

    def record_success(self) -> None:
        """Record a successful request — resets failure count and closes the breaker."""
        with self._lock:
            self._failure_count = 0
            self._state = self.CLOSED
            self._opened_at = None

    def record_failure(self) -> None:
        """Record a failed request — opens the breaker once threshold is reached.

        If the breaker is in HALF_OPEN state (test request failed), it
        immediately re-opens with a fresh cooldown timer. This prevents
        a downed API from being retried every cooldown cycle indefinitely.
        """
        with self._lock:
            self._failure_count += 1
            if self._state == self.HALF_OPEN:
                # Test request in HALF_OPEN failed — re-open immediately
                self._state = self.OPEN
                self._opened_at = time.monotonic()
            elif self._failure_count >= self.failure_threshold:
                self._state = self.OPEN
                # monotonic() avoids wall-clock jumps (NTP, DST) affecting cooldown
                self._opened_at = time.monotonic()

    def reset(self) -> None:
        """Force-reset the breaker to CLOSED (used in tests and manual recovery)."""
        with self._lock:
            self._state = self.CLOSED
            self._failure_count = 0
            self._opened_at = None


class PolySwarmAPIError(Exception):
    """Raised when a PolySwarm API call fails with actionable context.

    Attributes:
        category: Short label for error notes (e.g. "API Authentication Failed")
        detail: Human-readable description for the Note body
        recommendations: List of suggested actions for the user
    """

    def __init__(
        self, category: str, detail: str, recommendations: list | None = None
    ) -> None:
        self.category = category
        self.detail = detail
        self.recommendations = recommendations or [
            "Verify your POLYSWARM_API_KEY is valid and active.",
            "Check your PolySwarm plan includes the feature you're trying to use.",
            "Contact sales@polyswarm.io for assistance with your account or quota.",
        ]
        super().__init__(f"{category}: {detail}")


# Map HTTP status codes to user-friendly error context
_HTTP_ERROR_MAP = {
    401: (
        "API Authentication Failed",
        "Your PolySwarm API key is invalid, expired, or not configured correctly.",
        [
            "Verify POLYSWARM_API_KEY is set correctly in your environment or config.",
            "Generate a new API key at https://polyswarm.network.",
            "Contact sales@polyswarm.io if the issue persists.",
        ],
    ),
    403: (
        "API Access Denied",
        "Your PolySwarm account does not have permission for this operation. "
        "This usually means your plan does not include this feature.",
        [
            "Check that your PolySwarm subscription includes this feature (scanning, sandbox, LLM reports).",
            "Upgrade your plan at https://polyswarm.network or contact sales@polyswarm.io.",
        ],
    ),
    402: (
        "API Quota Exceeded",
        "Your PolySwarm API quota has been exhausted. No further requests can be made until "
        "your quota resets or is increased.",
        [
            "Wait for your quota to reset (check your plan's reset cycle).",
            "Contact sales@polyswarm.io to increase your quota or upgrade your plan.",
        ],
    ),
    429: (
        "API Rate Limit Exceeded",
        "Too many requests have been sent to the PolySwarm API in a short period. "
        "The connector will retry automatically, but if this persists your rate limit may need increasing.",
        [
            "Wait a few minutes and retry.",
            "Reduce POLYSWARM_POLL_INTERVAL to lower request frequency.",
            "Contact sales@polyswarm.io to increase your rate limit.",
        ],
    ),
}


class PolySwarmClient:
    """Client for PolySwarm API with retry logic and connection pooling."""

    # Default retry settings for SDK calls
    SDK_MAX_RETRIES = 3
    SDK_BACKOFF_BASE = 2.0  # seconds; exponential: 2, 4, 8

    # Cache TTL for sandbox provider list (seconds)
    _PROVIDERS_CACHE_TTL = 300.0  # 5 minutes

    @staticmethod
    def is_sandbox_success(status: str) -> bool:
        """Check if a sandbox status indicates successful completion."""
        return status.upper() in {"SUCCESS", "SUCCEEDED"}

    @staticmethod
    def is_sandbox_failure(status: str) -> bool:
        """Check if a sandbox status indicates a failure."""
        normalized = status.upper()
        return (
            "FAILED" in normalized
            or "TIMED OUT" in normalized
            or "TIMEDOUT" in normalized
        )

    @staticmethod
    def is_sandbox_terminal(status: str) -> bool:
        """Check if a sandbox status is terminal (no longer pending)."""
        return PolySwarmClient.is_sandbox_success(
            status
        ) or PolySwarmClient.is_sandbox_failure(status)

    def __init__(
        self, api_key: str, api_url: str, community: str, timeout: int, helper: object
    ) -> None:
        """Initialise client with SDK, retry session, and circuit breaker.

        Args:
            api_key: PolySwarm API key.
            api_url: Base API URL (``/v3`` suffix auto-appended for production).
            community: PolySwarm community slug (``default`` or ``private``).
            timeout: HTTP timeout in seconds for SDK calls.
            helper: OpenCTI connector helper for logging.
        """
        self.helper = helper
        # The SDK expects the /v3 path; append it when the user supplies just the host.
        if (
            api_url
            and "api.polyswarm.network" in api_url
            and not api_url.endswith("/v3")
        ):
            api_url = f"{api_url.rstrip('/')}/v3"
        self.api = PolyswarmAPI(
            key=api_key, uri=api_url, community=community, timeout=timeout
        )

        # PROD-01 + PROD-09: Shared session with retry and connection pooling.
        # Used for non-SDK HTTP calls (LLM report download, PDF download).
        self._session = self._create_retry_session()

        # Circuit breaker: 5 consecutive failures → 5 min cooldown
        self._breaker = CircuitBreaker(failure_threshold=5, cooldown_seconds=300.0)

        # Sandbox provider cache
        self._providers_cache: list[dict] | None = None
        self._providers_cache_time: float = 0.0

    def _retry_sdk_call(
        self,
        func: object,
        *args: object,
        operation: str = "SDK call",
        **kwargs: object,
    ) -> object | None:
        """
        Retry wrapper for PolySwarm SDK calls that use the SDK's internal HTTP client.
        Applies exponential backoff on transient errors (network, HTTP 429/5xx).
        Raises PolySwarmAPIError for actionable HTTP errors (401, 402, 403).
        Returns None on exhaustion instead of raising for transient failures.

        Checks the circuit breaker before attempting; records success/failure after.
        """
        if not self._breaker.allow_request():
            self.helper.connector_logger.warning(
                f"[POLYSWARM] {operation} blocked by circuit breaker (OPEN). "
                f"Skipping until cooldown expires."
            )
            return None

        last_error: Exception | None = None
        for attempt in range(1, self.SDK_MAX_RETRIES + 1):
            try:
                # BytesIO streams are consumed by the SDK on each attempt;
                # seek(0) rewinds them so retries re-read the full payload.
                for arg in args:
                    if isinstance(arg, io.BytesIO):
                        arg.seek(0)
                result = func(*args, **kwargs)
                self._breaker.record_success()
                return result
            except requests.HTTPError as e:
                # Check for actionable HTTP status codes
                status_code = (
                    getattr(e.response, "status_code", None)
                    if hasattr(e, "response")
                    else None
                )
                if status_code and status_code in _HTTP_ERROR_MAP:
                    category, detail, recs = _HTTP_ERROR_MAP[status_code]
                    raise PolySwarmAPIError(
                        category=f"{category} ({operation})",
                        detail=f"{detail} (HTTP {status_code} during {operation})",
                        recommendations=recs,
                    ) from e
                # Other HTTP errors — retry
                last_error = e
                if attempt < self.SDK_MAX_RETRIES:
                    wait = self.SDK_BACKOFF_BASE**attempt
                    self.helper.connector_logger.warning(
                        f"[POLYSWARM] {operation} HTTP error (attempt {attempt}/{self.SDK_MAX_RETRIES}): "
                        f"{type(e).__name__}: {e} — retrying in {wait:.0f}s"
                    )
                    time.sleep(wait)
            except (
                OSError,
                requests.RequestException,
                ConnectionError,
                TimeoutError,
            ) as e:
                # Check if wrapped exception has an HTTP response with actionable status
                resp = getattr(e, "response", None)
                status_code = (
                    getattr(resp, "status_code", None) if resp is not None else None
                )
                if status_code and status_code in _HTTP_ERROR_MAP:
                    category, detail, recs = _HTTP_ERROR_MAP[status_code]
                    raise PolySwarmAPIError(
                        category=f"{category} ({operation})",
                        detail=f"{detail} (HTTP {status_code} during {operation})",
                        recommendations=recs,
                    ) from e
                last_error = e
                if attempt < self.SDK_MAX_RETRIES:
                    wait = self.SDK_BACKOFF_BASE**attempt
                    self.helper.connector_logger.warning(
                        f"[POLYSWARM] {operation} failed (attempt {attempt}/{self.SDK_MAX_RETRIES}): "
                        f"{type(e).__name__}: {e} — retrying in {wait:.0f}s"
                    )
                    time.sleep(wait)
            except Exception as e:
                # Some SDK wrappers stringify status codes instead of raising HTTPError;
                # scan the message for known codes so we can still surface actionable errors.
                err_str = str(e).lower()
                for code, (category, detail, recs) in _HTTP_ERROR_MAP.items():
                    if (
                        str(code) in err_str
                        or (code == 403 and "forbidden" in err_str)
                        or (code == 401 and "unauthorized" in err_str)
                    ):
                        raise PolySwarmAPIError(
                            category=f"{category} ({operation})",
                            detail=f"{detail} (during {operation}: {e})",
                            recommendations=recs,
                        ) from e
                # Non-retryable error
                self.helper.connector_logger.error(
                    f"[POLYSWARM] {operation} non-retryable error: {type(e).__name__}: {e}"
                )
                self._breaker.record_failure()
                return None

        self.helper.connector_logger.error(
            f"[POLYSWARM] {operation} failed after {self.SDK_MAX_RETRIES} attempts: {last_error}"
        )
        self._breaker.record_failure()
        return None

    @staticmethod
    def _create_retry_session(
        retries: int = 4,
        backoff_factor: float = 1.0,
        status_forcelist: tuple = (429, 500, 502, 503, 504),
    ) -> requests.Session:
        """Create a ``requests.Session`` with exponential-backoff retry.

        This session is shared across non-SDK HTTP calls (PDF/LLM downloads).
        Connection pooling (pool_maxsize=10) avoids socket churn under load.
        """
        session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
            allowed_methods=["GET", "POST", "PUT"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=10)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def submit_file_async(
        self,
        file_data: bytes,
        filename: str,
        mime_type: str | None = None,
        scan_config: str = "default",
        password: str | None = None,
    ) -> str | None:
        """Submit file for scanning asynchronously. Returns scan instance ID or None on failure."""
        try:
            self.helper.connector_logger.info(
                f"[POLYSWARM] Submitting file for scan: {filename} ({len(file_data)} bytes)"
            )
            # Password-protected archives need server-side unzipping before scan
            prep = {"type": "zip", "password": str(password)} if password else None
            instance = self._retry_sdk_call(
                self.api.submit,
                io.BytesIO(file_data),
                artifact_name=filename,
                scan_config=scan_config,
                preprocessing=prep,
                operation="scan submit",
            )
            if instance and instance.id:
                self.helper.connector_logger.info(
                    f"[POLYSWARM] Scan submitted, instance_id: {instance.id}"
                )
                return instance.id
            return None
        except Exception as e:
            self.helper.connector_logger.error(
                f"[POLYSWARM] Scan submit unexpected error: {type(e).__name__}: {str(e)}"
            )
            return None

    def submit_sandbox_async(
        self,
        file_data: bytes,
        filename: str,
        provider: str = "cape",
        vm_slug: str = "win-10-build-19041",
        network: bool = True,
        password: str | None = None,
    ) -> str | None:
        """Submit file for sandbox analysis asynchronously. Returns sandbox task ID or None."""
        try:
            self.helper.connector_logger.info(
                f"[POLYSWARM] Submitting file for sandbox: {filename} "
                f"(provider={provider}, vm={vm_slug}, network={network})"
            )
            # Password-protected archives need server-side unzipping before detonation
            prep = {"type": "zip", "password": str(password)} if password else None
            task = self._retry_sdk_call(
                self.api.sandbox_file,
                io.BytesIO(file_data),
                artifact_name=filename,
                provider_slug=provider,
                vm_slug=vm_slug,
                network_enabled=network,
                preprocessing=prep,
                operation=f"sandbox submit ({provider})",
            )
            if task and task.id:
                self.helper.connector_logger.info(
                    f"[POLYSWARM] Sandbox submitted, task_id: {task.id}"
                )
                return task.id
            return None
        except Exception as e:
            self.helper.connector_logger.error(
                f"[POLYSWARM] Sandbox submit unexpected error: {type(e).__name__}: {str(e)}"
            )
            return None

    def get_scan_results(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieves raw JSON results for a scan instance, or None if still pending.

        Returns results only when the scan is terminal: either the engine window
        has closed (all verdicts in) or the scan failed outright.
        """
        try:
            result = self.api.lookup(scan_id)
            if result:
                self.helper.connector_logger.debug(
                    f"[POLYSWARM] Scan status: failed={result.failed}, window_closed={result.window_closed}"
                )
            # window_closed means all engines have reported; failed means infra error
            return (
                result.json
                if (result and (result.failed or result.window_closed))
                else None
            )
        except (requests.RequestException, KeyError, AttributeError) as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] Get scan results error: {str(e)}"
            )
            return None
        except Exception as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] Get scan results unexpected error: {type(e).__name__}: {str(e)}"
            )
            return None

    def get_sandbox_results(self, task_id: str) -> dict[str, Any] | None:
        """Retrieves raw JSON results for a sandbox task, or None if still running.

        Uses ``is_sandbox_terminal()`` to detect both success and failure completions,
        so the caller can distinguish them via the ``status`` field in the result.
        """
        try:
            task = self.api.sandbox_task_status(task_id)
            if task:
                self.helper.connector_logger.debug(
                    f"[POLYSWARM] Sandbox status: {task.status}"
                )
            return (
                task.json
                if (task and self.is_sandbox_terminal(str(task.status)))
                else None
            )
        except (requests.RequestException, KeyError, AttributeError) as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] Get sandbox results error: {str(e)}"
            )
            return None
        except Exception as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] Get sandbox results unexpected error: {type(e).__name__}: {str(e)}"
            )
            return None

    def get_available_providers(self) -> list[dict]:
        """Fetch available sandbox providers from the API, cached for 5 minutes.

        Each entry has 'slug', 'name', 'tool', and 'vms' (list of VM options).
        Falls back to a static default if the API call fails.
        """
        now = time.monotonic()
        if (
            self._providers_cache is not None
            and (now - self._providers_cache_time) < self._PROVIDERS_CACHE_TTL
        ):
            return self._providers_cache

        try:
            providers_result = self._retry_sdk_call(
                self.api.sandbox_providers,
                operation="list sandbox providers",
            )
            if providers_result:
                providers = []
                for p in providers_result:
                    providers.append(
                        {
                            "slug": p.slug,
                            "name": p.name,
                            "tool": p.tool,
                            "vms": p.vms,
                        }
                    )
                self._providers_cache = providers
                self._providers_cache_time = now
                self.helper.connector_logger.info(
                    f"[POLYSWARM] Loaded {len(providers)} sandbox providers: "
                    f"{[p['slug'] for p in providers]}"
                )
                return providers
        except Exception as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] Failed to fetch sandbox providers: {e}"
            )

        # Fallback if cache exists but refresh failed
        if self._providers_cache is not None:
            return self._providers_cache

        # Hard fallback — shouldn't happen in practice
        self.helper.connector_logger.warning("[POLYSWARM] Using fallback provider list")
        return [
            {"slug": "cape", "name": "Cape", "tool": "cape", "vms": []},
            {"slug": "triage", "name": "Triage", "tool": "triage", "vms": []},
        ]

    def get_provider_slugs(self) -> list[str]:
        """Return just the slug names of available providers."""
        return [p["slug"] for p in self.get_available_providers()]

    def get_default_vm_for_provider(self, provider_slug: str) -> str | None:
        """Get the best available VM slug for a provider from the API.

        Prefers Windows VMs since the vast majority of malware targets Windows.
        Falls back to the first available VM if no Windows VM is found.
        Returns None if the provider isn't found or has no VMs listed.
        """
        for p in self.get_available_providers():
            if p["slug"] == provider_slug and p["vms"]:
                vms = p["vms"]
                slugs = list(vms.keys()) if isinstance(vms, dict) else list(vms)
                # Prefer Windows VMs
                for slug in slugs:
                    if "win" in slug.lower():
                        return slug
                # No Windows VM — return first available
                return slugs[0] if slugs else None
        return None

    def create_llm_report(
        self,
        instance_id: str | None = None,
        sandbox_task_id: str | None = None,
        provider: str | None = None,
    ) -> str | None:
        """
        Create an LLM report task (non-blocking). Returns the report task ID immediately.
        Call collect_llm_report() later to poll and download the result.

        The SDK's ``llm_report_create`` takes a provider-specific sandbox task
        kwarg (``triage_sandbox_task_id`` or ``cape_sandbox_task_id``), not a
        generic ``sandbox_task_id``. Map it from ``provider`` here.
        """
        if not instance_id and not sandbox_task_id:
            self.helper.connector_logger.warning(
                "[POLYSWARM] LLM report requires instance_id or sandbox_task_id"
            )
            return None

        try:
            source_desc = []
            if instance_id:
                source_desc.append(f"instance_id={instance_id}")
            if sandbox_task_id:
                source_desc.append(f"sandbox_task_id={sandbox_task_id}")
            self.helper.connector_logger.info(
                f"[POLYSWARM] Creating LLM report ({', '.join(source_desc)})"
            )

            kwargs: dict[str, Any] = {
                "instance_id": instance_id,
                "operation": "LLM report create",
            }
            if sandbox_task_id:
                if provider == "triage":
                    kwargs["triage_sandbox_task_id"] = sandbox_task_id
                else:
                    kwargs["cape_sandbox_task_id"] = sandbox_task_id

            report_task = self._retry_sdk_call(
                self.api.llm_report_create,
                **kwargs,
            )

            if not report_task or not report_task.id:
                self.helper.connector_logger.warning(
                    "[POLYSWARM] LLM report creation returned no task ID"
                )
                return None

            self.helper.connector_logger.info(
                f"[POLYSWARM] LLM report created, task_id: {report_task.id}, state: {report_task.state}"
            )
            return report_task.id

        except (OSError, requests.RequestException, AttributeError) as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] LLM report creation failed: {str(e)}"
            )
            return None
        except Exception as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] LLM report creation unexpected error: {type(e).__name__}: {str(e)}"
            )
            return None

    def collect_llm_report(
        self, llm_task_id: str, timeout: int = 120, poll_interval: int = 5
    ) -> dict | str | None:
        """Poll an existing LLM report task until complete, then return the result.

        Separated from ``create_llm_report`` so callers can fire creation early
        (as soon as scan/sandbox succeeds) and defer polling until other work finishes.
        Uses monotonic clock to avoid wall-clock drift affecting the timeout.
        """
        if not llm_task_id:
            return None

        try:
            start = time.monotonic()
            report_task = self.api.llm_report_get(llm_task_id)

            while (time.monotonic() - start) < timeout:
                if report_task.state != "PENDING":
                    break

                time.sleep(poll_interval)
                report_task = self.api.llm_report_get(llm_task_id)
                elapsed = int(time.monotonic() - start)
                self.helper.connector_logger.debug(
                    f"[POLYSWARM] LLM report polling... {elapsed}s, state: {report_task.state}"
                )

            if report_task.state == "PENDING":
                self.helper.connector_logger.warning(
                    f"[POLYSWARM] LLM report {llm_task_id} timed out after {timeout}s"
                )
                return None

            if report_task.state == "FAILED":
                self.helper.connector_logger.warning(
                    f"[POLYSWARM] LLM report {llm_task_id} generation failed"
                )
                return None

            if report_task.state == "SUCCEEDED":
                # polyswarm-api (>= 3.21) returns the report inline on the task.
                report = getattr(report_task, "report", None)
                if report:
                    self.helper.connector_logger.info(
                        f"[POLYSWARM] LLM report {llm_task_id} retrieved"
                    )
                    return report
                self.helper.connector_logger.warning(
                    f"[POLYSWARM] LLM report {llm_task_id} succeeded but no report content"
                )
                return None

            self.helper.connector_logger.warning(
                f"[POLYSWARM] LLM report unexpected state: {report_task.state}"
            )
            return None

        except (OSError, requests.RequestException, AttributeError) as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] LLM report collection failed: {str(e)}"
            )
            return None
        except Exception as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] LLM report collection unexpected error: {type(e).__name__}: {str(e)}"
            )
            return None

    def close(self) -> None:
        """Close the underlying requests session."""
        if self._session:
            self._session.close()

    def generate_pdf(self, task_id: str, report_type: str) -> bytes | None:
        """Generate a PDF report for scan or sandbox results.

        Args:
            task_id: The scan instance ID or sandbox task ID.
            report_type: ``'scan'`` or ``'sandbox'`` — controls which sections
                the PDF template includes.

        Returns:
            Raw PDF bytes, or None if generation/download fails.
        """
        try:
            self.helper.connector_logger.info(
                f"[POLYSWARM] Generating {report_type} PDF report for ID: {task_id}"
            )

            # Template sections differ: scans show engine verdicts; sandboxes show
            # behavioral analysis, dropped files, extracted configs, and network IOCs.
            if report_type == "scan":
                template_metadata = {
                    "includes": ["summary", "detections", "fileMetadata"]
                }
            else:
                template_metadata = {
                    "includes": [
                        "summary",
                        "analysis",
                        "droppedFiles",
                        "extractedConfig",
                        "network",
                    ]
                }

            report = self._retry_sdk_call(
                self.api.report_create,
                type=report_type,
                format="pdf",
                instance_id=task_id if report_type == "scan" else None,
                sandbox_task_id=task_id if report_type == "sandbox" else None,
                template_metadata=template_metadata,
                operation=f"PDF report create ({report_type})",
            )
            if not report or not report.id:
                self.helper.connector_logger.warning(
                    "[POLYSWARM] PDF report creation returned no report object"
                )
                return None

            # Poll for PDF report completion every 15s for up to 5 minutes.
            # PDF generation can take 1-5 mins on PolySwarm's side.
            poll_interval = 15  # seconds between checks
            poll_timeout = 300  # 5 minutes max
            elapsed = 0
            finished = None
            attempt = 0

            while elapsed < poll_timeout:
                time.sleep(poll_interval)
                elapsed += poll_interval
                attempt += 1
                try:
                    finished = self._retry_sdk_call(
                        self.api.report_wait_for,
                        report.id,
                        operation=f"PDF report wait ({report_type}) [{elapsed}s/{poll_timeout}s]",
                    )
                    if finished:
                        self.helper.connector_logger.info(
                            f"[POLYSWARM] PDF report ready after {elapsed}s ({attempt} polls)"
                        )
                        break
                except (
                    ConnectionError,
                    TimeoutError,
                    OSError,
                    ValueError,
                    NotFoundException,
                ) as wait_err:
                    self.helper.connector_logger.debug(
                        f"[POLYSWARM] PDF report poll [{elapsed}s/{poll_timeout}s]: {wait_err}"
                    )

            if not finished:
                self.helper.connector_logger.warning(
                    f"[POLYSWARM] PDF report not ready after {poll_timeout}s, skipping"
                )
                return None

            if finished.state == "SUCCEEDED" and finished.url:
                # PROD-03: No stream=True — we read .content anyway. Uses retry session.
                response = self._session.get(finished.url, timeout=60)
                if response.status_code == 200:
                    self.helper.connector_logger.info(
                        f"[POLYSWARM] Successfully downloaded {report_type} PDF report"
                    )
                    return response.content

            self.helper.connector_logger.warning(
                f"[POLYSWARM] PDF generation failed. State: {getattr(finished, 'state', 'Unknown')}"
            )
            return None
        except (OSError, requests.RequestException, AttributeError) as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] PDF generation skipped: {str(e)}"
            )
            return None
        except Exception as e:
            self.helper.connector_logger.warning(
                f"[POLYSWARM] PDF generation unexpected error: {type(e).__name__}: {str(e)}"
            )
            return None
