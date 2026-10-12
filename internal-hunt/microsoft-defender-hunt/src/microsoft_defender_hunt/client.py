"""Microsoft Graph advanced hunting client of the Microsoft Defender XDR hunt connector."""

import json
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import requests
from connectors_sdk.client.exceptions import ApiClientError
from connectors_sdk.connectors.internal_hunt import (
    HuntAccessDeniedError,
    HuntApiClient,
    HuntExecutionError,
    RunDeadline,
    access_denied_message,
    api_error_message,
)

HUNTING_PATH = "/v1.0/security/runHuntingQuery"
"""Advanced hunting endpoint of Microsoft Graph."""

HUNTING_OPERATION = "The Microsoft Defender advanced hunting query"

AUTHENTICATION_OPERATION = "The Microsoft Entra authentication"

QUERY_TIMEOUT_SECONDS = 600.0
"""Longest wait of a single advanced hunting query."""

TOKEN_TIMEOUT_SECONDS = 30.0
"""Longest wait of a single Microsoft Entra token request."""

TOKEN_REFRESH_MARGIN_SECONDS = 300.0
"""An access token is renewed when it expires within this margin."""

RATE_LIMITS: tuple[tuple[int, float], ...] = ((45, 60.0), (1500, 3600.0))
"""Advanced hunting API calls a tenant may send, as (calls, period in seconds)."""

DYNAMIC_TYPES = frozenset({"dynamic", "object"})
"""Advanced hunting column types holding JSON documents."""

ENTRA_REFUSED_HINT = (
    "Microsoft Entra ID refused the credentials of the app registration: check "
    "MICROSOFT_DEFENDER_HUNT_TENANT_ID, MICROSOFT_DEFENDER_HUNT_CLIENT_ID and "
    "MICROSOFT_DEFENDER_HUNT_CLIENT_SECRET, and that the secret has not expired"
)


def iso_time(value: datetime) -> str:
    """Format a datetime as an ISO 8601 UTC time with milliseconds."""
    utc = value.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def timespan(start: datetime, end: datetime) -> str:
    """Return the ``Timespan`` of a run window (``start/end``)."""
    return f"{iso_time(start)}/{iso_time(end)}"


class TokenBucket:
    """Token bucket of one quota: ``capacity`` calls refilled over ``period`` seconds."""

    def __init__(
        self, capacity: int, period: float, clock: Callable[[], float]
    ) -> None:
        """Start with a full bucket.

        Args:
            capacity: Calls allowed per period (the burst size).
            period: Period of the quota in seconds.
            clock: Monotonic clock.
        """
        self.capacity = capacity
        self.period = period
        self._clock = clock
        self._tokens = float(capacity)
        self._updated = clock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        self._tokens = min(
            float(self.capacity), self._tokens + elapsed * self.capacity / self.period
        )
        self._updated = now

    def wait(self) -> float:
        """Return the seconds until a call is allowed (0 when one is)."""
        self._refill()
        if self._tokens >= 1:
            return 0.0
        return (1 - self._tokens) * self.period / self.capacity

    def take(self) -> None:
        """Spend the token of one call."""
        self._refill()
        self._tokens -= 1


class CallRateLimiter:
    """Keeps the advanced hunting calls of the connector within the quotas of the tenant.

    Every call waits for a token of each quota (45 calls per minute and 1,500
    per hour by default), within the deadline of the run sending it.
    """

    def __init__(
        self,
        limits: Sequence[tuple[int, float]] = RATE_LIMITS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create one token bucket per quota.

        Args:
            limits: Quotas as (calls, period in seconds).
            clock: Monotonic clock (injectable for tests).
        """
        self._buckets = [
            TokenBucket(capacity, period, clock) for capacity, period in limits
        ]
        self._lock = threading.Lock()

    def acquire(self, deadline: RunDeadline) -> None:
        """Wait until the quotas allow one more call, then spend it.

        Args:
            deadline: Deadline of the run sending the call.

        Raises:
            HuntExecutionError: If the quotas allow no call before the deadline.
        """
        while True:
            with self._lock:
                wait = max(bucket.wait() for bucket in self._buckets)
                if wait <= 0:
                    for bucket in self._buckets:
                        bucket.take()
                    return
            if wait >= deadline.remaining():
                quotas = ", ".join(
                    f"{bucket.capacity} per {int(bucket.period)} seconds"
                    for bucket in self._buckets
                )
                raise HuntExecutionError(
                    f"{HUNTING_OPERATION} cannot be sent before the run deadline without "
                    f"exceeding the advanced hunting quotas of the tenant ({quotas}): "
                    "run the hunt again later, or with fewer values or rules."
                )
            deadline.sleep(wait)


class EntraTokenClient(HuntApiClient):
    """Client credentials flow of Microsoft Entra ID, issuing the Microsoft Graph tokens."""

    def __init__(
        self,
        login_url: str,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scope: str,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the client.

        Args:
            login_url: Microsoft Entra ID login URL.
            tenant_id: Tenant of the app registration.
            client_id: Client (application) ID of the app registration.
            client_secret: Client secret of the app registration.
            scope: Scope of the tokens (``<graph_url>/.default``).
            clock: Monotonic clock (injectable for tests).
        """
        super().__init__(base_url=login_url)
        self._path = f"/{quote(tenant_id, safe='')}/oauth2/v2.0/token"
        self._form = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        }
        self._clock = clock
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.Lock()

    def access_token(self, deadline: RunDeadline) -> str:
        """Return a valid access token, requested again when it expires soon.

        Args:
            deadline: Deadline of the run needing the token.

        Raises:
            HuntAccessDeniedError: If Microsoft Entra ID refuses the credentials.
            HuntExecutionError: If Microsoft Entra ID returns no token.
            HuntTimeoutError: If no token is obtained before the deadline.
        """
        with self._lock:
            if (
                self._token
                and self._clock() < self._expires_at - TOKEN_REFRESH_MARGIN_SECONDS
            ):
                return self._token
            answer = self.hunt_request(
                "POST",
                self._path,
                deadline,
                AUTHENTICATION_OPERATION,
                max_timeout=TOKEN_TIMEOUT_SECONDS,
                data=self._form,
            )
            token = answer.get("access_token") if isinstance(answer, Mapping) else None
            if not isinstance(token, str) or not token:
                raise HuntExecutionError(
                    f"{AUTHENTICATION_OPERATION} returned no access token."
                )
            try:
                lifetime = float(answer.get("expires_in") or 0)
            except (TypeError, ValueError):
                lifetime = 0.0
            self._token = token
            self._expires_at = self._clock() + lifetime
            return token

    def _retry_delay(self, method: str, attempt: int, error: Exception) -> float | None:
        """Retry the token request like an idempotent call: it changes nothing."""
        return super()._retry_delay("GET", attempt, error)

    def _hunt_error(self, operation: str, error: Exception) -> HuntExecutionError:
        """Name the credentials to check when Microsoft Entra ID refuses them (400 or 401)."""
        if isinstance(error, ApiClientError) and error.status_code in (400, 401):
            return HuntAccessDeniedError(
                access_denied_message(
                    operation,
                    int(error.status_code),
                    ENTRA_REFUSED_HINT,
                    api_error_message(error.response_body),
                )
            )
        return super()._hunt_error(operation, error)


@dataclass(frozen=True)
class HuntingResult:
    """Answer of an advanced hunting query.

    Attributes:
        columns: Names of the columns, in the order of the schema.
        rows: Rows as dictionaries keyed by column name; dynamic columns decoded.
    """

    columns: tuple[str, ...]
    rows: list[dict[str, Any]]


class DefenderHuntingClient(HuntApiClient):
    """Client of the advanced hunting API of Microsoft Graph (``runHuntingQuery``).

    Every query carries a Microsoft Graph token of the app registration and
    waits for the quotas of the tenant; a throttled query (429) is sent again
    after the ``Retry-After`` delay, within the run deadline.
    """

    def __init__(
        self,
        graph_url: str,
        tokens: EntraTokenClient,
        raw_columns: frozenset[str],
        rate_limiter: CallRateLimiter | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            graph_url: Microsoft Graph URL.
            tokens: Issuer of the Microsoft Graph tokens.
            raw_columns: Columns holding raw payloads, never decoded.
            rate_limiter: Quotas of the tenant shared by every run of the connector.
        """
        super().__init__(base_url=graph_url)
        self.tokens = tokens
        self.rate_limiter = rate_limiter or CallRateLimiter()
        self._raw_columns = {name.lower() for name in raw_columns}
        self._run = threading.local()

    def _retry_delay(self, method: str, attempt: int, error: Exception) -> float | None:
        """Retry a query like an idempotent call: advanced hunting only reads."""
        return super()._retry_delay("GET", attempt, error)

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send a query within the quotas of the tenant, with a valid access token."""
        deadline: RunDeadline | None = getattr(self._run, "deadline", None)
        if deadline is not None:
            self.rate_limiter.acquire(deadline)
            headers = dict(kwargs.pop("headers", None) or {})
            headers["Authorization"] = f"Bearer {self.tokens.access_token(deadline)}"
            kwargs["headers"] = headers
            # The waits above count against the timeout set before them
            kwargs["timeout"] = deadline.request_timeout(
                float(kwargs.get("timeout") or QUERY_TIMEOUT_SECONDS), HUNTING_OPERATION
            )
        return super()._raw_request(method, path, **kwargs)

    def run_query(
        self, query: str, query_timespan: str, deadline: RunDeadline
    ) -> HuntingResult:
        """Run an advanced hunting query.

        Args:
            query: KQL query.
            query_timespan: ``Timespan`` of the query (ISO 8601 interval or duration).
            deadline: Run deadline.

        Returns:
            The columns and rows of the answer.

        Raises:
            HuntAccessDeniedError: If the credentials or the permission are refused.
            HuntQueryRejectedError: If advanced hunting rejects the query.
            HuntExecutionError: If the query fails.
            HuntTimeoutError: If the query does not complete before the deadline.
        """
        self._run.deadline = deadline
        try:
            response = self.hunt_request(
                "POST",
                HUNTING_PATH,
                deadline,
                HUNTING_OPERATION,
                max_timeout=QUERY_TIMEOUT_SECONDS,
                json={"Query": query, "Timespan": query_timespan},
            )
        finally:
            self._run.deadline = None
        if not isinstance(response, Mapping):
            raise HuntExecutionError("Advanced hunting returned an unexpected answer.")
        return self._read_answer(response)

    def _read_answer(self, response: Mapping[str, Any]) -> HuntingResult:
        """Read the schema and the rows of an answer, decoding the dynamic columns."""
        schema = _value(response, "schema") or []
        types: dict[str, tuple[str, str]] = {}
        for column in schema if isinstance(schema, list) else []:
            if not isinstance(column, Mapping):
                continue
            name = str(_value(column, "name") or "")
            if name:
                kind = str(_value(column, "type") or "").lower()
                types.setdefault(name.lower(), (name, kind))
        rows: list[dict[str, Any]] = []
        results = _value(response, "results") or []
        for raw_row in results if isinstance(results, list) else []:
            if not isinstance(raw_row, Mapping):
                continue
            row: dict[str, Any] = {}
            for key, value in raw_row.items():
                name, kind = types.get(str(key).lower(), (str(key), ""))
                if kind in DYNAMIC_TYPES and name.lower() not in self._raw_columns:
                    value = _decode_dynamic(value)
                row[name] = value
            rows.append(row)
        columns = tuple(name for name, _ in types.values())
        return HuntingResult(columns=columns, rows=rows)


def _value(document: Mapping[str, Any], key: str) -> Any:
    """Read a property of a Graph document whatever the case of its first letter."""
    if key in document:
        return document[key]
    return document.get(key[:1].upper() + key[1:])


def _decode_dynamic(value: Any) -> Any:
    """Decode the JSON text of a dynamic column (kept as text when not JSON)."""
    if not isinstance(value, str) or not value.strip():
        return value
    try:
        return json.loads(value)
    except ValueError:
        return value
