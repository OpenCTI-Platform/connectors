"""RiskIQ's utility functions."""
import calendar
from datetime import datetime, timezone


def datetime_to_timestamp(datetime_value: datetime) -> int:
    """Convert datetime to Unix timestamp."""
    # Use calendar.timegm because the time.mktime assumes that the input is in your
    # local timezone.
    return calendar.timegm(datetime_value.timetuple())


def datetime_utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


def timestamp_to_datetime(timestamp: int) -> datetime:
    """Convert Unix timestamp to datetime (UTC)."""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)
