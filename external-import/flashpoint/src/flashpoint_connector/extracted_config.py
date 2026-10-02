import json
from typing import Literal

from .utils import is_domain, is_ipv4, is_ipv6

NetworkKind = Literal["domain", "ipv4", "ipv6", "url"]

# Config keys holding network endpoints. Their casing and spelling vary from one
# malware family to another (`Hosts`, `HOSTS`, `Server`, `host`, `ip`, ...).
NETWORK_KEYS = frozenset(
    {
        "host",
        "hosts",
        "domain",
        "domains",
        "server",
        "servers",
        "ip",
        "ips",
        "gateway",
        "c2",
        "url",
        "urls",
    }
)

URL_SCHEMES = ("http://", "https://", "ftp://")


def parse_extracted_config(raw_value: str | None) -> dict | None:
    """Parse the JSON string carried by an `extracted_config` indicator.

    Args:
        raw_value: Indicator `value`, a JSON-encoded object.

    Returns:
        dict | None: Parsed config, or `None` when the value is not a JSON object.
    """
    if not raw_value:
        return None
    try:
        config = json.loads(raw_value)
    except ValueError:
        return None
    return config if isinstance(config, dict) else None


def _flatten_values(raw: object) -> list[str]:
    """Flatten a config value (string, comma-separated string or list) into strings."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        values: list[str] = []
        for item in raw:
            values.extend(_flatten_values(item))
        return values
    return [part.strip() for part in str(raw).split(",") if part.strip()]


def _classify(value: str) -> tuple[NetworkKind, str] | None:
    """Return the observable kind and normalized value, or `None` if unusable."""
    if value.lower().startswith(URL_SCHEMES):
        return "url", value
    if is_ipv4(value):
        return "ipv4", value
    if is_ipv6(value):
        return "ipv6", value
    if is_domain(value.lower()):
        return "domain", value.lower()
    return None


def extract_network_indicators(config: dict) -> list[tuple[NetworkKind, str]]:
    """Extract deduplicated network endpoints from a parsed config.

    Args:
        config: Parsed `extracted_config` payload.

    Returns:
        list[tuple[NetworkKind, str]]: `(kind, value)` pairs in config order.
    """
    endpoints: list[tuple[NetworkKind, str]] = []
    seen: set[tuple[str, str]] = set()

    for key, raw in config.items():
        if key.lower() not in NETWORK_KEYS:
            continue
        for value in _flatten_values(raw):
            classified = _classify(value)
            if classified is None or classified in seen:
                continue
            seen.add(classified)
            endpoints.append(classified)

    return endpoints


def extract_parameters(config: dict) -> dict[str, str]:
    """Extract non-network parameters (ports, mutex, keys, ...) as strings.

    Args:
        config: Parsed `extracted_config` payload.

    Returns:
        dict[str, str]: Parameters with empty values dropped, lists joined by `, `.
    """
    parameters: dict[str, str] = {}
    for key, raw in config.items():
        if key.lower() in NETWORK_KEYS:
            continue
        values = _flatten_values(raw) if isinstance(raw, (list, tuple)) else [raw]
        text = ", ".join(str(value) for value in values if value not in (None, ""))
        if text.strip():
            parameters[key] = text.strip()
    return parameters
