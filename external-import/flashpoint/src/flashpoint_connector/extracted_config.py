import json
from typing import Literal, NamedTuple
from urllib.parse import urlparse

from flashpoint_connector.utils import is_domain, is_ipv4, is_ipv6

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
        "c2s",
        "dga_c2s",
        "url",
        "urls",
    }
)

# Config keys listing algorithmically generated (short-lived) endpoints.
DGA_KEYS = frozenset({"dga_c2s"})

URL_SCHEMES = ("http://", "https://", "ftp://")


class NetworkIndicator(NamedTuple):
    """A network endpoint found in an extracted config."""

    kind: NetworkKind
    value: str
    is_dga: bool = False


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


def _classify_host(value: str) -> tuple[NetworkKind, str] | None:
    """Classify a bare host as IPv4, IPv6 or domain."""
    if is_ipv4(value):
        return "ipv4", value
    if is_ipv6(value):
        return "ipv6", value
    if is_domain(value.lower()):
        return "domain", value.lower()
    return None


def _classify(value: str) -> tuple[NetworkKind, str] | None:
    """Return the observable kind and normalized value, or `None` if unusable.

    A URL made only of a scheme and a host (no path, query or fragment) carries
    no more information than its host, so it is returned as a domain or an IP.
    """
    if value.lower().startswith(URL_SCHEMES):
        parsed = urlparse(value)
        has_only_host = (
            parsed.path in ("", "/")
            and not parsed.params
            and not parsed.query
            and not parsed.fragment
        )
        if has_only_host:
            return _classify_host(parsed.hostname) if parsed.hostname else None
        return "url", value
    return _classify_host(value)


def extract_network_indicators(config: dict) -> list[NetworkIndicator]:
    """Extract deduplicated network endpoints from a parsed config.

    Args:
        config: Parsed `extracted_config` payload.

    Returns:
        list[NetworkIndicator]: Endpoints in config order. An endpoint listed
        under a DGA key is flagged even when it also appears under another key.
    """
    endpoints: dict[tuple[NetworkKind, str], bool] = {}

    for key, raw in config.items():
        lowered_key = key.lower()
        if lowered_key not in NETWORK_KEYS:
            continue
        is_dga = lowered_key in DGA_KEYS
        for value in _flatten_values(raw):
            classified = _classify(value)
            if classified is None:
                continue
            endpoints[classified] = endpoints.get(classified, False) or is_dga

    return [
        NetworkIndicator(kind, value, is_dga)
        for (kind, value), is_dga in endpoints.items()
    ]


def extract_parameters(config: dict) -> dict[str, str]:
    """Extract non-network parameters (ports, mutex, keys, ...) as strings.

    The result is deterministic for a given config: keys are sorted and list
    values are sorted, so the output does not depend on the order in which the
    API returns them.

    Args:
        config: Parsed `extracted_config` payload.

    Returns:
        dict[str, str]: Parameters with empty values dropped, lists joined by `, `.
    """
    parameters: dict[str, str] = {}
    for key in sorted(config, key=str.lower):
        if key.lower() in NETWORK_KEYS:
            continue
        raw = config[key]
        if isinstance(raw, (list, tuple)):
            values = sorted(_flatten_values(raw))
        else:
            values = [raw]
        text = ", ".join(str(value) for value in values if value not in (None, ""))
        if text.strip():
            parameters[key] = text.strip()
    return parameters
