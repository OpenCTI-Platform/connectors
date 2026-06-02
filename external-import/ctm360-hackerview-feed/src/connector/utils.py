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
        try:
            # Epoch milliseconds if value is unreasonably large for seconds
            epoch = ts / 1000 if ts > 1e12 else ts
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            # Out-of-range epoch — fall back to now, like the other branches.
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not isinstance(ts, str):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Handle numeric strings (epoch)
    try:
        epoch = float(ts)
    except ValueError:
        epoch = None
    if epoch is not None:
        try:
            if epoch > 1e12:
                epoch = epoch / 1000
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

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
        else:
            # Convert aware timestamps with a non-UTC offset to UTC before
            # formatting, so e.g. "20:00+03:00" becomes "17:00Z" not "20:00Z".
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
