from datetime import datetime, timezone


def normalize_timestamp(ts) -> str:
    """Normalize a timestamp to STIX-compatible Z-suffix format.

    Handles:
    - ISO 8601 strings ("2026-03-04T18:00:00Z")
    - DD-MM-YYYY HH:MM:SS AM/PM strings ("04-03-2026 08:52:59 AM")
    - DD-MM-YYYY HH:MM:SS strings ("04-03-2026 18:29:05")
    - Epoch milliseconds (1772614383785)
    - Epoch seconds (1772614383)
    """
    # Use an explicit None/empty-string check so a numeric 0 (a valid epoch,
    # 1970-01-01T00:00:00Z) is handled by the epoch branch below.
    if ts is None or ts == "":
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Handle epoch timestamps (int or float)
    if isinstance(ts, (int, float)):
        try:
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

    # Handle DD-MM-YYYY HH:MM:SS AM/PM format (CBS incidents)
    try:
        dt = datetime.strptime(ts, "%d-%m-%Y %I:%M:%S %p")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Handle DD-MM-YYYY HH:MM:SS format (24-hour)
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
        # Treat naive timestamps as UTC, and convert offset-aware timestamps
        # to UTC before formatting so the trailing "Z" is always accurate
        # (e.g. 18:00+02:00 -> 16:00Z, not 18:00Z).
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
