from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_BUCKET_ORDER = (
    "PROBABILITY_LOW",
    "PROBABILITY_MEDIUM",
    "PROBABILITY_HIGH",
    "PROBABILITY_VERY_HIGH",
)

_ISO_DURATION_RE = re.compile(
    r"^P"
    r"(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$"
)


def parse_iso_duration(value: str) -> timedelta:
    """Parse a small subset of ISO 8601 duration strings (no months/years).

    Supports forms like P1D, PT6H, PT5M, PT30S, P1DT12H. Defaults to 1 day on
    parse failure rather than raising — the connector is safer with a default
    period than crashing on a malformed env var.
    """
    if not value:
        return timedelta(days=1)
    text = value.strip()
    match = _ISO_DURATION_RE.match(text)
    # Every component is optional in the pattern, so "P", "PT", and "P2DT"
    # match with nothing after a designator; ISO 8601 requires a component.
    if not match or not any(match.groupdict().values()) or text.endswith("T"):
        return timedelta(days=1)
    parts = {k: int(v) for k, v in match.groupdict(default="0").items()}
    return timedelta(
        days=parts["days"],
        hours=parts["hours"],
        minutes=parts["minutes"],
        seconds=parts["seconds"],
    )


def normalize_min_bucket(value: str | None) -> list[str]:
    """Return the list of acceptable PROBABILITY_* values given a min threshold.

    Inputs (case-insensitive): LOW, MEDIUM, HIGH, VERY_HIGH, or the prefixed
    forms PROBABILITY_*. Default min is HIGH.
    """
    if not value:
        return ["PROBABILITY_HIGH", "PROBABILITY_VERY_HIGH"]
    normalized = value.strip().upper()
    if not normalized.startswith("PROBABILITY_"):
        normalized = f"PROBABILITY_{normalized}"
    if normalized not in _BUCKET_ORDER:
        return ["PROBABILITY_HIGH", "PROBABILITY_VERY_HIGH"]
    idx = _BUCKET_ORDER.index(normalized)
    return list(_BUCKET_ORDER[idx:])


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
    - There is no known per-environment CEL field, so `STAIRWELL_IMPORT_SCOPE` is
      accepted in settings but not applied.
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
