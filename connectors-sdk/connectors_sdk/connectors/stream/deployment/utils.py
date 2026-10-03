"""Helpers to identify indicators and their observable values in stream data."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"

_PATTERN_COMPARISON = re.compile(
    r"(?P<object_type>[a-z0-9][a-z0-9-]*):(?P<object_path>[\w.'\-]+?)"
    r"\s*=\s*'(?P<value>(?:[^'\\]|\\.)*)'"
)
_URL_PREFIX = re.compile(r"(?P<prefix>[A-Za-z][A-Za-z0-9+.\-]*://[^/?#]*)")

_STIX_TO_OPENCTI_OBSERVABLE_TYPES = {
    "autonomous-system": "Autonomous-System",
    "directory": "Directory",
    "domain-name": "Domain-Name",
    "email-addr": "Email-Addr",
    "hostname": "Hostname",
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "mac-addr": "Mac-Addr",
    "mutex": "Mutex",
    "url": "Url",
    "user-agent": "User-Agent",
    "windows-registry-key": "Windows-Registry-Key",
}


@dataclass(frozen=True, slots=True)
class PatternValue:
    """A single ``<object_type>:<object_path> = '<value>'`` comparison of a STIX pattern.

    Attributes:
        object_type: The STIX cyber observable type, e.g. ``ipv4-addr``.
        object_path: The property path, e.g. ``value`` or ``hashes.'SHA-256'``.
        value: The compared value, unescaped.
    """

    object_type: str
    object_path: str
    value: str

    @property
    def hash_algorithm(self) -> str | None:
        """Return the hash algorithm of a ``file:hashes.<algorithm>`` comparison, if any."""
        if self.object_type != "file" or not self.object_path.startswith("hashes."):
            return None
        return self.object_path[len("hashes.") :].strip("'\"")


def get_opencti_extension(stix_object: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the OpenCTI extension of a STIX object as found in stream events.

    Args:
        stix_object: A STIX object dictionary (stream event ``data``).

    Returns:
        The OpenCTI extension content, or an empty mapping when absent.
    """
    extensions = stix_object.get("extensions")
    if not isinstance(extensions, Mapping):
        return {}
    extension = extensions.get(OPENCTI_EXTENSION_ID)
    return extension if isinstance(extension, Mapping) else {}


def is_stix_indicator(stix_object: Mapping[str, Any]) -> bool:
    """Tell whether a STIX object is an indicator.

    Args:
        stix_object: A STIX object dictionary.

    Returns:
        ``True`` when the object is a STIX ``indicator``.
    """
    return stix_object.get("type") == "indicator"


def get_opencti_indicator_id(stix_object: Mapping[str, Any]) -> str | None:
    """Return the identifier to report for an indicator of a stream event.

    The OpenCTI internal id carried by the OpenCTI extension is preferred; the STIX
    standard id is used otherwise. Both are accepted by the write-back API.

    Args:
        stix_object: A STIX object dictionary (stream event ``data``).

    Returns:
        The OpenCTI internal id, else the STIX id, else ``None``.
    """
    internal_id = get_opencti_extension(stix_object).get("id")
    if isinstance(internal_id, str) and internal_id:
        return internal_id
    stix_id = stix_object.get("id")
    if isinstance(stix_id, str) and stix_id:
        return stix_id
    return None


def extract_pattern_values(pattern: str | None) -> list[PatternValue]:
    """Extract the equality comparisons of a STIX pattern.

    Only ``=`` comparisons with a quoted string are extracted, which covers the
    patterns OpenCTI generates for observables (``[ipv4-addr:value = '1.2.3.4']``,
    ``[file:hashes.'SHA-256' = '...']``, ``[url:value = '...' OR ...]``).

    Args:
        pattern: A STIX 2.1 pattern.

    Returns:
        The comparisons in their order of appearance.
    """
    if not pattern:
        return []
    values = []
    for match in _PATTERN_COMPARISON.finditer(pattern):
        raw_value = match.group("value")
        value = raw_value.replace("\\'", "'").replace("\\\\", "\\")
        values.append(
            PatternValue(
                object_type=match.group("object_type"),
                object_path=match.group("object_path"),
                value=value,
            )
        )
    return values


def pattern_observable_values(pattern: str | None) -> list[dict[str, Any]]:
    """Build the ``observable_values`` OpenCTI computes for an indicator pattern.

    Args:
        pattern: A STIX 2.1 pattern.

    Returns:
        The observable values, one entry per observable, file hashes merged into a
        single ``StixFile`` entry, in the shape found in stream events.
    """
    observable_values: list[dict[str, Any]] = []
    file_hashes: dict[str, str] = {}
    for pattern_value in extract_pattern_values(pattern):
        algorithm = pattern_value.hash_algorithm
        if algorithm:
            file_hashes[algorithm] = pattern_value.value
            continue
        observable_type = _STIX_TO_OPENCTI_OBSERVABLE_TYPES.get(
            pattern_value.object_type
        )
        if observable_type:
            observable_values.append(
                {"type": observable_type, "value": pattern_value.value}
            )
    if file_hashes:
        observable_values.append({"type": "StixFile", "hashes": file_hashes})
    return observable_values


def normalize_value(value: Any) -> str | None:
    """Normalize an observable value or an identifier for matching.

    Only the scheme and the host of a URL are case-insensitive: its path, query and
    fragment keep their case, so ``/Admin`` and ``/admin`` stay two values.

    Args:
        value: Any value.

    Returns:
        The stripped string, lower-cased except the case-sensitive URL parts, or
        ``None`` when empty.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    url = _URL_PREFIX.match(text)
    if url:
        return url.group("prefix").lower() + text[url.end() :]
    return text.lower()


def parse_datetime(value: datetime | str | None) -> datetime | None:
    """Parse an ISO 8601 date into a timezone-aware datetime.

    Args:
        value: A datetime, an ISO 8601 string (``Z`` suffix accepted) or ``None``.

    Returns:
        A timezone-aware datetime (UTC assumed for naive values), or ``None`` when
        the value is empty or cannot be parsed.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = value.strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def format_datetime(value: datetime | str | None) -> str | None:
    """Format a date for the OpenCTI GraphQL API.

    Args:
        value: A datetime, an ISO 8601 string or ``None``.

    Returns:
        An ISO 8601 UTC string with a ``Z`` suffix, the string unchanged when it
        cannot be parsed, or ``None``.
    """
    if value is None:
        return None
    parsed = parse_datetime(value)
    if parsed is None:
        return value if isinstance(value, str) and value.strip() else None
    return (
        parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


def to_stream_indicator(
    exported_indicator: Mapping[str, Any], indicator_id: str
) -> dict[str, Any]:
    """Convert an indicator exported through the API into the stream event shape.

    The STIX export of pycti carries OpenCTI attributes as ``x_opencti_*`` custom
    properties, while stream events carry them in the OpenCTI extension. Stream
    connectors are written against the stream shape, so a re-push during
    reconciliation must hand them an object in that shape.

    Args:
        exported_indicator: The indicator as returned by
            ``helper.api.stix2.get_stix_bundle_or_object_from_entity_id``.
        indicator_id: The OpenCTI internal id of the indicator.

    Returns:
        The indicator with its OpenCTI extension populated (``id``, ``type``,
        ``score``, ``main_observable_type``, ``observable_values``...).
    """
    stix_object = {
        key: value
        for key, value in exported_indicator.items()
        if not key.startswith("x_opencti_")
    }
    extension = dict(get_opencti_extension(exported_indicator))
    for key, value in exported_indicator.items():
        if key.startswith("x_opencti_"):
            extension.setdefault(key[len("x_opencti_") :], value)
    extension.setdefault("extension_type", "property-extension")
    extension.setdefault("id", indicator_id)
    extension.setdefault("type", "Indicator")
    if "observable_values" not in extension:
        observable_values = pattern_observable_values(stix_object.get("pattern"))
        if observable_values:
            extension["observable_values"] = observable_values
    extensions = dict(stix_object.get("extensions") or {})
    extensions[OPENCTI_EXTENSION_ID] = extension
    stix_object["extensions"] = extensions
    return stix_object
