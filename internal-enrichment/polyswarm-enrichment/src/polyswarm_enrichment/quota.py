"""Read-only account plan and quota visibility.

Reads ``GET /public/accounts`` through ``PolyswarmAPI.account_features()`` at
startup and about once an hour after that (plus at most one more read a minute
after a quota error). It only reads, and a failure to read it is logged and swallowed: it must never break
an enrichment or an import. The account number in the response is never read.

How unlimited and exhausted are told apart (measured on an internal plan, where
``daily_api_limit`` and ``daily_api_remaining`` are both 0 and every feature has
``base_uses`` 0 with ``value`` true):

* A limit of 0 (or less) means no cap is set, so the quota is unlimited.
* A limit above 0 with nothing remaining means the quota is exhausted.
* A feature with ``value`` false is not part of the plan.
"""

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from polyswarm_api import exceptions as polyswarm_exceptions

REFRESH_SECONDS = 3600
# After a failed read, try again sooner than the normal interval.
RETRY_SECONDS = 300
# A quota error forces a fresh read, but never more often than this.
FORCED_REFRESH_MIN_SECONDS = 60

# Features worth logging next to the daily API quota (sandbox and hunt allowances).
QUOTA_FEATURE_TAGS = (
    "sandbox_request",
    "historical_hunt",
    "live_hunt",
    "manual_analysis",
)


@dataclass(frozen=True)
class FeatureQuota:
    """One metered allowance from the account's feature list."""

    tag: str
    name: str
    enabled: bool
    limit: int
    remaining: int

    @property
    def unlimited(self) -> bool:
        return self.enabled and self.limit <= 0

    @property
    def exhausted(self) -> bool:
        return self.enabled and self.limit > 0 and self.remaining <= 0

    def describe(self) -> str:
        if not self.enabled:
            return f"{self.tag}: not on this plan"
        if self.unlimited:
            return f"{self.tag}: unlimited"
        return f"{self.tag}: {self.remaining} of {self.limit} remaining"


@dataclass(frozen=True)
class QuotaStatus:
    """Plan and quota facts read from the account record."""

    plan_name: str | None
    daily_limit: int | None
    daily_remaining: int | None
    window_end: str | None
    plan_period_end: str | None
    is_trial: bool
    is_trial_expired: bool
    features: tuple[FeatureQuota, ...] = ()

    @property
    def daily_unlimited(self) -> bool:
        return self.daily_limit is not None and self.daily_limit <= 0

    @property
    def daily_exhausted(self) -> bool:
        return (
            self.daily_limit is not None
            and self.daily_limit > 0
            and (self.daily_remaining or 0) <= 0
        )

    def daily_text(self) -> str:
        if self.daily_limit is None:
            return "daily API quota not reported"
        if self.daily_unlimited:
            return "daily API quota unlimited"
        return f"daily API calls remaining {self.daily_remaining} of {self.daily_limit}"

    def low_items(self, threshold: int) -> list[str]:
        """Names of the quotas below the warning threshold (0 disables)."""
        if threshold <= 0:
            return []
        low = []
        if (
            self.daily_limit is not None
            and self.daily_limit > 0
            and (self.daily_remaining or 0) < threshold
        ):
            low.append(f"daily API calls ({self.daily_remaining} remaining)")
        for feature in self.features:
            if feature.enabled and feature.limit > 0 and feature.remaining < threshold:
                low.append(f"{feature.tag} ({feature.remaining} remaining)")
        return low

    def summary(self) -> str:
        parts = [f"plan {self.plan_name or 'unknown'}", self.daily_text()]
        parts.extend(feature.describe() for feature in self.features)
        if self.is_trial:
            parts.append("trial expired" if self.is_trial_expired else "trial")
        if self.window_end:
            parts.append(f"usage window ends {self.window_end}")
        return "; ".join(parts)

    def note_lines(self) -> list[str]:
        """Markdown lines for an error note."""
        lines = [f"- Plan: {self.plan_name or 'unknown'}"]
        if self.daily_limit is None:
            lines.append("- Daily API calls remaining: not reported")
        elif self.daily_unlimited:
            lines.append("- Daily API calls: no cap on this account")
        else:
            lines.append(
                f"- Daily API calls remaining: {self.daily_remaining} of "
                f"{self.daily_limit}"
            )
        for feature in self.features:
            if feature.enabled and not feature.unlimited:
                lines.append(
                    f"- {feature.tag} remaining: {feature.remaining} of "
                    f"{feature.limit}"
                )
        if self.window_end:
            lines.append(f"- Usage window ends: {self.window_end}")
        return lines


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_account_features(account: Any) -> QuotaStatus:
    """Build a QuotaStatus from an ``AccountFeatures`` resource (or a look-alike)."""
    features = []
    for item in getattr(account, "features", None) or []:
        if not isinstance(item, dict) or item.get("tag") not in QUOTA_FEATURE_TAGS:
            continue
        features.append(
            FeatureQuota(
                tag=item["tag"],
                name=str(item.get("name") or item["tag"]),
                enabled=bool(item.get("value")),
                limit=_as_int(item.get("base_uses")) or 0,
                remaining=_as_int(item.get("remaining_uses")) or 0,
            )
        )
    return QuotaStatus(
        plan_name=getattr(account, "account_plan_name", None),
        daily_limit=_as_int(getattr(account, "daily_api_limit", None)),
        daily_remaining=_as_int(getattr(account, "daily_api_remaining", None)),
        window_end=_text(getattr(account, "window_end", None)),
        plan_period_end=_text(getattr(account, "plan_period_end", None)),
        is_trial=bool(getattr(account, "is_trial", False)),
        is_trial_expired=bool(getattr(account, "is_trial_expired", False)),
        features=tuple(features),
    )


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def is_quota_exhausted_error(error: BaseException) -> bool:
    """True for the error the SDK raises on HTTP 429 (usage limits exceeded)."""
    return isinstance(error, polyswarm_exceptions.UsageLimitsExceededException)


class QuotaMonitor:
    """Reads the account quota on a schedule and reports it. Never raises."""

    def __init__(
        self,
        api: Any,
        logger: Any,
        warn_below: int = 100,
        refresh_seconds: int = REFRESH_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._api = api
        self._logger = logger
        self.warn_below = max(0, warn_below)
        self._refresh_seconds = refresh_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._next_read = 0.0
        self._last_forced = float("-inf")
        self.status: QuotaStatus | None = None

    def refresh(self, force: bool = False) -> QuotaStatus | None:
        """Read the quota when it is due (or when forced, at most once a minute)."""
        try:
            return self._refresh(force)
        except Exception as error:  # never let quota visibility break the work
            self._safe_log("warning", f"[QUOTA] Quota check failed: {error}")
            return self.status

    def _refresh(self, force: bool) -> QuotaStatus | None:
        with self._lock:
            now = self._clock()
            if force:
                if now - self._last_forced < FORCED_REFRESH_MIN_SECONDS:
                    return self.status
                self._last_forced = now
            elif now < self._next_read:
                return self.status
            try:
                account = self._api.account_features()
                status = parse_account_features(account)
            except Exception as error:
                self._next_read = now + min(RETRY_SECONDS, self._refresh_seconds)
                self._safe_log(
                    "warning",
                    "[QUOTA] Could not read the account plan and quota "
                    f"({type(error).__name__}); continuing without it",
                )
                return self.status
            self._next_read = now + self._refresh_seconds
            self.status = status
        self._report(status)
        return status

    def _report(self, status: QuotaStatus) -> None:
        self._safe_log("info", f"[QUOTA] {status.summary()}")
        low = status.low_items(self.warn_below)
        if low:
            self._safe_log(
                "warning",
                f"[QUOTA] Remaining quota is below {self.warn_below}: "
                + ", ".join(low),
            )

    def exhausted_note_lines(self) -> list[str]:
        """Lines for an error note after a quota-exhausted failure."""
        status = self.refresh(force=True)
        if status is None:
            return ["- Remaining quota could not be read from the account"]
        lines = status.note_lines()
        if status.window_end is None:
            lines.append("- Reset time: not reported by the API")
        return lines

    def _safe_log(self, level: str, message: str) -> None:
        try:
            getattr(self._logger, level)(message)
        except Exception:  # logging must not break the work either
            pass
