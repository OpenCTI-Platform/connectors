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
    match = _ISO_DURATION_RE.match(value.strip())
    if not match:
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


def build_cel_filter(cutoff: datetime | None) -> str:
    """Build the Stairwell ListObjectMetadata CEL filter.

    Only the malicious flag and the time cutoff go server-side:
    - `mal_eval.probability_bucket` isn't queryable with the `in` operator (the
      API returns 500 "Unable to query objects"), so the minimum-bucket filter
      runs client-side after each page is fetched.
    - There is no known per-environment CEL field, so `import_scope` is
      accepted in settings but not applied.
    """
    clauses: list[str] = ["mal_eval.malicious==true"]
    if cutoff:
        ts = cutoff.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        clauses.append(f'object.global_first_seen_time >= "{ts}"')
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
