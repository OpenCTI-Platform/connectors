import re
import unicodedata
import urllib.parse
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from pycti import OpenCTIConnectorHelper

OBSERVABLE_TYPES = [
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "hostname",
    "url",
    "email-addr",
    "file",
]

IOC_TYPES = {
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

FILE_HASH_TYPES_MAPPER = {
    "md5": "md5",
    "sha-1": "sha1",
    "sha1": "sha1",
    "sha-256": "sha256",
    "sha256": "sha256",
}


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
    Get a description according to observable.
    :param data: Observable data to extract description from
    :return: Observable description summary or "No Description"
    """
    stix_description = OpenCTIConnectorHelper.get_attribute_in_extension(
        "description", data
    )
    return stix_description[0:99] if stix_description is not None else "No description"


def get_action(data: dict) -> str:
    """
    Get an action according to observable score.
    :param data: Observable data to get action from
    :return: Action name or "unknown"
    """
    score = OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
    action = "Audit"
    if score >= 60:
        action = "Block"
    elif 30 < score < 60:
        action = "Alert"
    elif 0 < score < 30:
        action = "Warn"
    elif score == 0:
        action = "Audit"
    return action


def get_severity(data: dict) -> str:
    """
    Get severity according to observable score.
    :param data: Observable data to get action from
    :return: Severity or "unknown"
    """
    score = OpenCTIConnectorHelper.get_attribute_in_extension("score", data)
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
    expire_datetime = now + timedelta(days=expiration_time)

    # Get valid_until if present
    valid_until = OpenCTIConnectorHelper.get_attribute_in_extension("valid_until", data)
    if valid_until:
        valid_until_datetime = datetime.fromisoformat(valid_until)
        # Return the earliest of expire_datetime and valid_until_datetime
        earliest = min(expire_datetime, valid_until_datetime)
        return earliest.isoformat()

    return expire_datetime.isoformat()


def get_tags(data: dict) -> list[str]:
    """
    Get tags for an observable.
    :param data: Observable data to extract tags from
    :return: List of tags
    """
    tags = ["opencti"]
    labels = OpenCTIConnectorHelper.get_attribute_in_extension("labels", data)
    return tags + labels if labels is not None else tags


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


_URL_RE = re.compile(r'https?://[^\s"\'<>()]+', re.IGNORECASE)
_AT_RE = re.compile(r"\[at\]|\(at\)", re.IGNORECASE)
_TRAILING_PUNCT_RE = re.compile(r"[.,;!?]+$")
_PLACEHOLDER_DOTS_RE = re.compile(r"\.\.\.+$")
_WHITESPACE_RE = re.compile(r"\s+")
_BRACKET_TRANS = str.maketrans("", "", "[]")


@lru_cache(maxsize=20000)
def indicator_value(value: str, max_length: int = 800) -> str | None:
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
            extracted_url = match.group(0)

            # Clean trailing punctuation early
            extracted_url = extracted_url.rstrip(".,;!?…")

            parsed = urllib.parse.urlparse(extracted_url)
            if not parsed.scheme or not parsed.netloc:
                return None

            # Decode and normalize
            decoded_path = _sanitize_url_component(
                urllib.parse.unquote(parsed.path or "")
            )
            decoded_query = _sanitize_url_component(
                urllib.parse.unquote(parsed.query or "")
            )

            safe_path = urllib.parse.quote(decoded_path, safe="/")
            safe_query = urllib.parse.quote(decoded_query, safe="-=&")

            value = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, safe_path, "", safe_query, "")
            )

        except Exception:
            return None

    # Collapse trailing whitespace
    value = _WHITESPACE_RE.sub("", value)

    # Strip trailing punctuation Defender doesn't like
    value = _TRAILING_PUNCT_RE.sub("", value)

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
