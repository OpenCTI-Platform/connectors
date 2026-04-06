import re
import uuid
from datetime import datetime, timezone


def normalize_timestamp(ts) -> str:
    """Normalize a timestamp to STIX-compatible Z-suffix format.

    The stix2 library requires timestamps ending with 'Z', not '+00:00'.
    Handles:
    - ISO 8601 strings ("2026-03-04T18:00:00Z")
    - YYYY-MM-DD HH:MM:SS strings ("2026-03-04 20:50:49")
    - Epoch milliseconds (1772657449000)
    - Epoch seconds (1772657449)
    - Common date-only formats
    """
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Handle epoch timestamps (int or float)
    if isinstance(ts, (int, float)):
        if ts > 1e12:
            ts = ts / 1000
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if not isinstance(ts, str):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Handle numeric strings (epoch)
    try:
        epoch = float(ts.strip())
        if epoch > 1e12:
            epoch = epoch / 1000
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Handle ISO 8601 and YYYY-MM-DD HH:MM:SS (fromisoformat handles both)
    try:
        cleaned = ts.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        pass

    # Try common date-only formats
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%b %d, %Y", "%d %b %Y"):
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue

    # Fallback to current time
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_deterministic_id(stix_type: str, *args: str) -> str:
    """Generate a deterministic STIX ID from type and seed values."""
    seed = "-".join(str(a) for a in args)
    return f"{stix_type}--{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


# Compiled regex for CVE extraction — matches CVE-YYYY-NNNNN+ patterns
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cves(text: str) -> list[str]:
    """Extract unique CVE identifiers from text.

    Args:
        text: Free-text string (title, description, etc.)

    Returns:
        Deduplicated list of CVE IDs in uppercase (e.g., ['CVE-2024-12345']).
    """
    if not text:
        return []
    matches = CVE_PATTERN.findall(text)
    # Deduplicate while preserving order, normalize to uppercase
    seen = set()
    result = []
    for cve in matches:
        cve_upper = cve.upper()
        if cve_upper not in seen:
            seen.add(cve_upper)
            result.append(cve_upper)
    return result


def is_newer_than(timestamp, cutoff) -> bool:
    """Check if a timestamp is newer than a cutoff timestamp.

    Used for client-side time filtering when the API does not support
    date-range query parameters.

    Args:
        timestamp: The item's timestamp (str, int/float epoch ms, or None).
        cutoff: The cutoff timestamp (str or None).

    Returns:
        True if the item is newer than the cutoff, or if either value is None.
    """
    if cutoff is None or timestamp is None:
        return True
    try:
        item_ts = normalize_timestamp(timestamp)
        cutoff_ts = normalize_timestamp(cutoff)
        # Parse normalized Z-suffix timestamps for comparison
        item_dt = datetime.strptime(item_ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        cutoff_dt = datetime.strptime(cutoff_ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        return item_dt > cutoff_dt
    except (ValueError, AttributeError):
        # If parsing fails, include the item to be safe
        return True
