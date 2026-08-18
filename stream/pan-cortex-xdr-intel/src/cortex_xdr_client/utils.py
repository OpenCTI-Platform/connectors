from datetime import datetime, timezone


def datetime_to_utc(dt: datetime) -> datetime:
    """Convert naive or aware datetime to UTC."""
    if dt.tzinfo:
        return dt.astimezone(tz=timezone.utc)
    else:
        return dt.replace(tzinfo=timezone.utc)
