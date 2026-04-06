import uuid
from datetime import datetime, timezone


def normalize_timestamp(ts) -> str:
    """Normalize a timestamp to STIX-compatible Z-suffix format.

    Handles:
    - ISO 8601 strings ("2026-03-04T18:00:00Z")
    - DD-MM-YYYY HH:MM:SS strings ("02-03-2026 17:32:52")
    - Epoch milliseconds (1772649966000)
    - Epoch seconds (1772649966)
    """
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Handle epoch timestamps (int or numeric string)
    if isinstance(ts, (int, float)):
        # Epoch milliseconds if value is unreasonably large for seconds
        if ts > 1e12:
            ts = ts / 1000
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if not isinstance(ts, str):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Handle numeric strings (epoch)
    try:
        epoch = float(ts)
        if epoch > 1e12:
            epoch = epoch / 1000
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Handle DD-MM-YYYY HH:MM:SS format
    try:
        dt = datetime.strptime(ts, "%d-%m-%Y %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Handle ISO 8601
    try:
        ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_deterministic_id(stix_type: str, *args: str) -> str:
    """Generate a deterministic STIX ID from type and seed values."""
    seed = "-".join(str(a) for a in args)
    return f"{stix_type}--{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"
