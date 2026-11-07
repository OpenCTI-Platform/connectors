"""
Expiration filtering stage.

Rules (see CHANGELOG_IMPLEMENTATION.md, "Expiration filtering rules"):

* Only ``indicator`` objects carry expiration semantics in STIX 2.1, through
  ``valid_until``: "the time at which this Indicator should no longer be
  considered a valid indicator". An indicator is therefore expired when
  ``valid_until <= now`` (UTC). It is still valid strictly before that instant.
* An indicator without ``valid_until`` never expires.
* ``created``, ``modified``, ``valid_from`` and every other timestamp are NOT
  expiration fields and are never used to exclude an object.
* No other object type is subject to expiration filtering. No Luminar-specific
  expiration field is documented, so none is applied.
* An indicator whose ``valid_until`` is present but not a parseable timestamp
  is malformed (it cannot be proven valid or expired) and is reported as such
  so the caller can skip it.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Python's fromisoformat accepts at most microsecond precision; STIX
# timestamps may carry more fractional digits, which are truncated here.
_FRACTION_PATTERN = re.compile(r"(\.\d{6})\d+")


def parse_stix_timestamp(value: Any) -> Optional[datetime]:
    """Parse a STIX/RFC 3339 timestamp into a timezone-aware UTC datetime.

    Returns None when ``value`` is not a string or cannot be parsed. Naive
    timestamps are interpreted as UTC (STIX timestamps are always UTC).
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = _FRACTION_PATTERN.sub(r"\1", value.strip())
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_expired(stix_object: Dict[str, Any], now: datetime) -> bool:
    """Return True when the object is expired according to its own semantics.

    :raises ValueError: when an indicator's ``valid_until`` is present but
        unparseable.
    """
    if stix_object.get("type") != "indicator":
        return False
    valid_until = stix_object.get("valid_until")
    if valid_until is None:
        return False
    valid_until_dt = parse_stix_timestamp(valid_until)
    if valid_until_dt is None:
        raise ValueError(f"unparseable valid_until {valid_until!r}")
    return valid_until_dt <= now
