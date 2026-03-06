import re
import unicodedata
import urllib.parse
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Final, Optional

OBSERVABLE_TYPES: Final = [
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "hostname",
    "url",
    "email-addr",
    "file",
]

IOC_TYPES: Final = {
    "ipv4-addr": "IpAddress",
    "ipv6-addr": "IpAddress",
    "domain-name": "DomainName",
    "hostname": "DomainName",
    "url": "Url",
    "md5": "FileMd5",
    "sha1": "FileSha1",
    "sha256": "FileSha256",
    "x509-certificate": "CertificateThumbprint",
}

FILE_HASH_TYPES_MAPPER: Final = {
    "md5": "md5",
    "sha-1": "sha1",
    "sha1": "sha1",
    "sha-256": "sha256",
    "sha256": "sha256",
}

# Only these indicator types are written to Defender.
# All other types (e.g., WebCategory) are read-only in our connector.
CREATABLE_INDICATOR_TYPES: Final = {
    "DomainName",
    "Url",
    "IpAddress",
    "FileSha1",
    "FileSha256",
    "CertificateThumbprint",
}

_MAX_LEN_FOR_KEY: Final[int] = 800


def is_stix_indicator(data: dict) -> bool:
    """
    Check if data represents a STIX Indicator.
    :param data: Data to check
    :return: True if data represents a STIX Indicator, False otherwise
    """
    return data["type"] == "indicator" and data["pattern_type"].startswith("stix")


def is_observable(data: dict) -> bool:
    """
    Check if data represents a STIX Observable.
    :param data: Data to check
    :return: True if data represents a STIX Observable, False otherwise
    """
    return data["type"] in OBSERVABLE_TYPES


def get_ioc_type(data: dict) -> str | None:
    """
    Get valid IOC type for Defender from data.
    :param data: Data to get IOC type from
    :return: IOC type if found, None otherwise
    """
    data_type = data["type"]
    return IOC_TYPES.get(data_type.lower(), None)


def get_description(data: dict) -> str:
    """
    Return a short description for the indicator.
    Falls back to the indicator value when no explicit description is available.
    """
    desc = data.get("description")
    if isinstance(desc, str) and desc.strip():
        return desc.strip()[:99]  # Defender prefers <=100 chars

    # Fallback: use indicator value if present
    val = data.get("value")
    if isinstance(val, str) and val.strip():
        return val.strip()[:99]

    # Final fallback
    return "Auto-imported from OpenCTI feed"


def _score_from_any(data: dict) -> int:
    s = data.get("x_opencti_score")
    try:
        return int(s) if s is not None else 0
    except Exception:
        return 0


def get_action(data: dict, default_action: str | None = None) -> str:
    """
    Determine the effective action for this observable.
    Precedence:
      1) Per-observable override (__policy_action) if present
      2) Connector-level default_action (if provided)
      3) Existing score-based mapping (unchanged)
    """
    if isinstance(data, dict):
        v = data.get("__policy_action")
        if v:
            return str(v)

    if default_action:
        return str(default_action)

    score = _score_from_any(data)
    action = "Audit"
    if score >= 60:
        action = "Block"
    elif 30 < score < 60:
        action = "Warn"
    elif 0 < score < 30:
        action = "Audit"
    elif score == 0:
        action = "Allowed"
    return action


def get_educate_url(o: dict[str, Any], default_url: Optional[str]) -> Optional[str]:
    """
    Effective educateUrl: override or default.
    """
    if isinstance(o, dict):
        v = o.get("__policy_educate_url")
        if v not in (None, ""):
            return str(v)
    return default_url


def get_expire_days(o: dict[str, Any], default_days: int) -> int:
    """
    Effective expiration (days): override (__policy_expire_time_days) or default_days.
    """
    try:
        v = o.get("__policy_expire_time_days")
        if v is not None:
            return int(v)
    except (TypeError, ValueError, AttributeError):
        # If the override is missing or invalid, fall back to the default.
        return int(default_days)
    return int(default_days)


def get_recommended_actions(
    o: dict[str, Any], default_text: Optional[str]
) -> Optional[str]:
    """
    Effective recommendedActions text: override or default.
    """
    if isinstance(o, dict):
        v = o.get("__policy_recommended_actions")
        if v not in (None, ""):
            return str(v)
    return default_text


def get_severity(data: dict) -> str:
    """
    Get severity according to observable score.
    :param data: Observable data to get action from
    :return: Severity or "unknown"
    """
    score = _score_from_any(data)
    if score >= 60:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    elif score >= 20:
        severity = "Low"
    else:
        severity = "Informational"
    return severity


def get_expiration_datetime(data: dict, expiration_time: int) -> str:
    """
    Get an expiration datetime for an observable.
    Use the earlier of:
      1. The indicator's valid_until field (if present)
      2. now + expiration_time (in days)
    :param data: Observable data to calculate expiration with
    :param expiration_time: Duration after which observable is considered as expired (in days)
    :return: Datetime of observable expiration as ISO8601 string
    """
    now = datetime.now(timezone.utc)
    default_exp = now + timedelta(days=expiration_time)

    # Get valid_until if present
    valid_until = data.get("valid_until")

    if isinstance(valid_until, str) and valid_until:
        vu = valid_until.replace("Z", "+00:00")
        try:
            vu_dt = datetime.fromisoformat(vu)
            return min(default_exp, vu_dt).isoformat()
        except Exception:
            pass

    return default_exp.isoformat()


def get_hash_type(data: dict) -> str | None:
    """
    Get hash type for a file.
    :param data: File data to get hash type for
    :return: Hash type
    """
    if data["type"] != "file":
        raise ValueError("Data type is not file")

    hash_type = None

    # data["hashes"] contains only one item
    for key in data["hashes"]:
        hash_type = FILE_HASH_TYPES_MAPPER[key]

    return hash_type


def is_defender_supported_domain(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip().lower()
    return bool(value) and not value.startswith("_")


_URL_RE: Final = re.compile(r'https?://[^\s"\'<>()]+', re.IGNORECASE)
_AT_RE: Final = re.compile(r"\[at\]|\(at\)", re.IGNORECASE)
_TRAILING_PUNCT_RE: Final = re.compile(r"[.,;!?]+$")
_PLACEHOLDER_DOTS_RE: Final = re.compile(r"\.\.\.+$")
_TRAILING_WHITESPACE_RE: Final = re.compile(r"\s+$")
_BRACKET_TRANS: Final = str.maketrans("", "", "[]")


@lru_cache(maxsize=20000)
def indicator_value(value: str, max_length: int = _MAX_LEN_FOR_KEY) -> str | None:
    """
    Clean, refang, normalize, and truncate an indicator value for Defender API submission.

    - Extracts and sanitizes URLs
    - Refangs common obfuscations
    - Encodes path/query safely
    - Strips trailing garbage and punctuation
    - Limits to Defender's max length
    """
    if not isinstance(value, str):
        return None

    # Normalize Unicode
    value = unicodedata.normalize("NFKC", value)

    value = value.strip()

    # Refang common obfuscations
    value = value.replace("[.]", ".").replace("(.)", ".")
    value = value.replace("hxxp://", "http://").replace("hxxps://", "https://")
    value = _AT_RE.sub("", value)
    value = value.translate(_BRACKET_TRANS)
    value = value.replace("\u2026", "")  # Remove literal ellipsis character

    # Remove common placeholder endings
    value = _PLACEHOLDER_DOTS_RE.sub("", value)

    # Extract valid URL if present
    match = _URL_RE.search(value)
    if match:
        try:
            # We treat this as a URL and sanitize accordingly
            extracted_url = match.group(0).rstrip(".,;!?…")

            parsed = urllib.parse.urlparse(extracted_url)
            if not parsed.scheme or not parsed.netloc:
                return None

            # Normalize host to lowercase
            netloc = parsed.netloc.lower()

            # Decode and normalize
            decoded_path = _sanitize_url_component(
                urllib.parse.unquote(parsed.path or "")
            )
            decoded_query = _sanitize_url_component(
                urllib.parse.unquote(parsed.query or "")
            )

            safe_path = urllib.parse.quote(decoded_path, safe="/")
            safe_query = urllib.parse.quote_plus(decoded_query, safe="=&")

            value = urllib.parse.urlunparse(
                (parsed.scheme, netloc, safe_path, "", safe_query, "")
            )

        except Exception:
            return None
    else:
        # Not a URL and looks like a plain host
        if " " not in value and "." in value and not any(c in value for c in "/:@"):
            value = value.rstrip(".").lower()

    # Collapse trailing whitespace
    # This happens in edge cases and is needed for Defender
    # Copilot incorrectly flags this as an opportunity for improvement
    value = _TRAILING_WHITESPACE_RE.sub("", value)

    # Strip trailing punctuation Defender doesn't like
    value = _TRAILING_PUNCT_RE.sub("", value)

    if not value:
        return None

    # Final length enforcement
    return value[:max_length]


def _sanitize_url_component(text: str) -> str:
    """
    Remove unsafe characters from a decoded URL component.

    Strips:
    - ASCII control characters (< 32)
    - DEL (0x7F)
    - Unicode replacement character (\ufffd)
    """
    if not text:
        return text

    text = unicodedata.normalize("NFKC", text)

    return "".join(c for c in text if 32 <= ord(c) <= 126 and ord(c) != 0xFFFD)


def indicator_title(value: str, max_length: int = 4000) -> str:
    """
    Truncate the indicator title to the maximum allowed length for Defender API.
    :param value: The indicator title string
    :param max_length: Maximum allowed length (default 4000)
    :return: Truncated title if needed
    """
    if value is not None and isinstance(value, str) and len(value) > max_length:
        return value[:max_length]
    return value


__all__ = [
    "OBSERVABLE_TYPES",
    "IOC_TYPES",
    "FILE_HASH_TYPES_MAPPER",
    "CREATABLE_INDICATOR_TYPES",
    "indicator_value",
    "indicator_title",
    "get_action",
    "get_educate_url",
    "get_expire_days",
    "get_recommended_actions",
    "get_severity",
    "get_expiration_datetime",
    "get_hash_type",
]
