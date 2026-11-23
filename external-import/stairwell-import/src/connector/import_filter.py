from __future__ import annotations

from datetime import datetime, timedelta, timezone

_BUCKET_ORDER = (
    "PROBABILITY_LOW",
    "PROBABILITY_MEDIUM",
    "PROBABILITY_HIGH",
    "PROBABILITY_VERY_HIGH",
)


def allowed_buckets(min_bucket: str) -> list[str]:
    """The PROBABILITY_* values at or above `min_bucket` (LOW … VERY_HIGH)."""
    return list(_BUCKET_ORDER[_BUCKET_ORDER.index(f"PROBABILITY_{min_bucket}") :])


def _cel_time(dt: datetime) -> str:
    """CEL timestamp literal, truncated to whole seconds.

    Naive datetimes are UTC; others are converted. Truncation is harmless:
    a window's end and the next window's start come from the same datetime,
    so they truncate to the same second and the windows stay contiguous.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def build_cel_filter(
    cutoff: datetime | None, window_end: datetime | None = None
) -> str:
    """Build the Stairwell ListObjectMetadata CEL filter.

    The window is `cutoff <= global_first_seen_time < window_end`. The upper
    bound keeps every page of a window, including a cursor resumed on a later
    day, to the same objects, so files first seen after the window are left
    for the next one instead of being fetched twice.

    Only the malicious flag and the time bounds go server-side:
    - `mal_eval.probability_bucket` isn't queryable with the `in` operator (the
      API returns 500 "Unable to query objects"), so the minimum-bucket filter
      runs client-side after each page is fetched.
    """
    clauses: list[str] = ["mal_eval.malicious==true"]
    if cutoff is not None:
        clauses.append(f'object.global_first_seen_time >= "{_cel_time(cutoff)}"')
    if window_end is not None:
        clauses.append(f'object.global_first_seen_time < "{_cel_time(window_end)}"')
    return " && ".join(clauses)


def window_start(
    watermark: datetime | None,
    first_run_window: timedelta,
    now: datetime,
) -> datetime:
    """Lower bound of a new import window.

    The committed watermark when there is one; otherwise `now -
    first_run_window`, so the first run is not unbounded.
    """
    if watermark is not None:
        if watermark.tzinfo is None:
            watermark = watermark.replace(tzinfo=timezone.utc)
        return watermark
    return now - first_run_window
