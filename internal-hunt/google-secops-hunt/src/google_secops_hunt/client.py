"""Chronicle API client of the Google SecOps hunt connector."""

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any, Protocol
from urllib.parse import quote

import requests
from connectors_sdk.connectors.internal_hunt import (
    HuntApiClient,
    HuntExecutionError,
    HuntQueryRejectedError,
    HuntTimeoutError,
    RunDeadline,
    api_error_message,
)
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleAuthRequest

MAX_RESULTS = 10000
"""Largest number of events (UDM search) or detections (YARA-L) the API returns."""

TOKEN_TIMEOUT_SECONDS = 30.0


class Credentials(Protocol):
    """Google credentials issuing OAuth2 access tokens."""

    token: str | None

    @property
    def valid(self) -> bool:
        """Return True when the access token is valid."""

    def refresh(self, request: Any) -> None:
        """Obtain a new access token."""


def rfc3339(value: datetime) -> str:
    """Format a datetime as an RFC 3339 UTC time with milliseconds."""
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


class SearchResult:
    """Results of a SecOps search.

    Attributes:
        events: UDM events (UDM search, or the events of the YARA-L detections).
        detections: Number of YARA-L detections (``None`` for a UDM search).
        truncated: True when SecOps holds more results than returned.
        event_detections: Detection of each event, in the order of ``events``
            (YARA-L), or ``None`` (UDM search).
    """

    def __init__(
        self,
        events: list[dict[str, Any]],
        detections: int | None,
        truncated: bool,
        event_detections: list[str] | None = None,
    ) -> None:
        """Initialize the result.

        Args:
            events: UDM events.
            detections: Number of YARA-L detections, or ``None``.
            truncated: Whether more results exist.
            event_detections: Detection of each event (YARA-L), or ``None``.
        """
        self.events = events
        self.detections = detections
        self.truncated = truncated
        self.event_detections = event_detections


class _BoundedAuthRequest:
    """google-auth transport whose token requests are bounded by the run deadline."""

    def __init__(self, timeout: float) -> None:
        self._request = GoogleAuthRequest()
        self._timeout = timeout

    def __call__(self, url: str, method: str = "GET", **kwargs: Any) -> Any:
        kwargs["timeout"] = self._timeout
        return self._request(url, method=method, **kwargs)


class SecOpsClient(HuntApiClient):
    """Client of the Chronicle API (v1alpha) of a Google SecOps instance."""

    def __init__(
        self,
        base_url: str,
        project_id: str,
        region: str,
        instance: str,
        credentials: Credentials,
    ) -> None:
        """Initialize the client.

        Args:
            base_url: Chronicle API URL (without region).
            project_id: Google Cloud project ID.
            region: Region of the SecOps instance.
            instance: Customer ID of the SecOps instance.
            credentials: Google credentials of the service account.
        """
        scheme, _, host = base_url.rstrip("/").partition("://")
        super().__init__(base_url=f"{scheme}://{region}-{host}")
        self._instance_path = (
            f"/v1alpha/projects/{quote(project_id, safe='')}"
            f"/locations/{quote(region, safe='')}"
            f"/instances/{quote(instance, safe='')}"
        )
        self._credentials = credentials
        self._token_lock = threading.Lock()

    def _authenticate(self, deadline: RunDeadline) -> None:
        """Refresh the access token of the service account when it is not valid.

        Raises:
            HuntExecutionError: If Google refuses the credentials.
            HuntTimeoutError: If no token is obtained before the run deadline.
        """
        with self._token_lock:
            if self._credentials.valid:
                return
            request = _BoundedAuthRequest(
                deadline.request_timeout(
                    TOKEN_TIMEOUT_SECONDS, "The Google authentication"
                )
            )
            try:
                self._credentials.refresh(request)
            except GoogleAuthError as err:
                # google-auth reports a refresh cut by the deadline as an auth error
                if deadline.expired():
                    raise HuntTimeoutError(
                        "The Google authentication did not complete within the run timeout."
                    ) from err
                raise HuntExecutionError(
                    f"The Google authentication failed: {api_error_message(str(err))}"
                ) from err

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send a request with the access token of the service account."""
        headers = dict(kwargs.pop("headers", None) or {})
        headers["Authorization"] = f"Bearer {self._credentials.token}"
        return super()._raw_request(method, path, headers=headers, **kwargs)

    def udm_search(
        self,
        query: str,
        start: datetime,
        end: datetime,
        max_results: int,
        deadline: RunDeadline,
    ) -> SearchResult:
        """Run a UDM search over a time window.

        Args:
            query: UDM search query.
            start: Start of the time window.
            end: End of the time window.
            max_results: Maximum number of events to fetch.
            deadline: Run deadline.

        Returns:
            The matching UDM events.

        Raises:
            HuntQueryRejectedError: If SecOps rejects the query as invalid.
            HuntExecutionError: If the search fails on SecOps.
            HuntTimeoutError: If the search does not complete before the deadline.
        """
        self._authenticate(deadline)
        answer = self.hunt_request(
            "GET",
            f"{self._instance_path}:udmSearch",
            deadline,
            "The UDM search",
            max_timeout=deadline.remaining(),
            params={
                "query": query,
                "timeRange.startTime": rfc3339(start),
                "timeRange.endTime": rfc3339(end),
                "limit": min(max_results, MAX_RESULTS),
            },
        )
        if not isinstance(answer, dict):
            raise HuntExecutionError("Google SecOps returned an unexpected answer.")
        events = [
            _udm(event)
            for event in answer.get("events") or []
            if isinstance(event, dict)
        ]
        return SearchResult(events, None, bool(answer.get("moreDataAvailable")))

    def run_rule(
        self,
        rule_text: str,
        start: datetime,
        end: datetime,
        max_results: int,
        deadline: RunDeadline,
    ) -> SearchResult:
        """Test a YARA-L rule over a time window (retrohunt without alerting).

        Args:
            rule_text: YARA-L 2.0 rule.
            start: Start of the time window.
            end: End of the time window.
            max_results: Maximum number of detections to fetch.
            deadline: Run deadline.

        Returns:
            The events of the detections, the detection of each event and the
            number of detections.

        Raises:
            HuntQueryRejectedError: If the rule does not compile.
            HuntExecutionError: If the rule fails.
            HuntTimeoutError: If the test does not complete before the deadline.
        """
        self._authenticate(deadline)
        answer = self.hunt_request(
            "POST",
            f"{self._instance_path}/legacy:legacyRunTestRule",
            deadline,
            "The YARA-L rule test",
            max_timeout=deadline.remaining(),
            json={
                "ruleText": rule_text,
                "timeRange": {"startTime": rfc3339(start), "endTime": rfc3339(end)},
                "maxResults": max(1, min(max_results, MAX_RESULTS)),
                "scope": "",
            },
        )
        items = answer if isinstance(answer, list) else [answer]
        events: list[dict[str, Any]] = []
        event_detections: list[str] = []
        detections = 0
        truncated = False
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("ruleCompilationError"):
                raise HuntQueryRejectedError(
                    "The YARA-L rule does not compile: "
                    f"{api_error_message(item['ruleCompilationError'])}"
                )
            if item.get("ruleError"):
                raise HuntExecutionError(
                    f"The YARA-L rule failed: {api_error_message(item['ruleError'])}"
                )
            if item.get("tooManyDetections"):
                truncated = True
            detection = item.get("detection")
            if isinstance(detection, dict):
                detections += 1
                detection_events = _detection_events(detection)
                events.extend(detection_events)
                event_detections.extend(
                    [_detection_label(detection)] * len(detection_events)
                )
        return SearchResult(events, detections, truncated, event_detections)


def _detection_label(detection: dict[str, Any]) -> str:
    """Return a stable label of a YARA-L detection, the same at every run that finds it.

    The id Google SecOps gives the detection, else a digest of its content: the
    label keys the hit across runs, never its position in the answer.
    """
    detection_id = detection.get("id")
    if isinstance(detection_id, str) and detection_id.strip():
        return detection_id.strip()
    canonical = json.dumps(
        detection, sort_keys=True, separators=(",", ":"), default=str
    )
    return f"detection-{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:32]}"


def _udm(event: dict[str, Any]) -> dict[str, Any]:
    """Return the UDM document of a UDM search event."""
    udm = event.get("udm")
    return dict(udm) if isinstance(udm, dict) else dict(event)


def _detection_events(detection: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the UDM events referenced by a YARA-L detection.

    A detection without event references yields one event holding its
    detection time, so that it still counts and dates the hits.
    """
    events: list[dict[str, Any]] = []
    for element in detection.get("collectionElements") or []:
        for reference in element.get("references") or []:
            event = reference.get("event") if isinstance(reference, dict) else None
            if isinstance(event, dict):
                events.append(dict(event))
    if not events:
        events.append({"detectionTime": detection.get("detectionTime")})
    return events
