"""CIM-aware host attribution for Splunk hunt results.

In Splunk, ``host`` is the device that *logged* the event. For network
appliances (firewalls, IDS, proxies, DNS servers) that is the appliance, not
the endpoint involved; for centrally collected endpoint telemetry (Windows
Event Forwarding, EDR API pulls) it is the collector. Attributing hits to
``host`` therefore names the wrong machine for whole classes of data.

This module resolves the endpoint of an event from its sourcetype and CIM
fields. The same rules are produced twice, kept equivalent by the tests:

- ``attributed_host()`` for events the connector reads back (rule hunts);
- ``host_eval_spl()`` for the aggregating indicator lookup, evaluated in Splunk.

The sourcetype classes are seeded from the ``sourcetype_map`` of the
``splunk-search`` connector (network-device and endpoint infrastructure types).
"""

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

NETWORK_SOURCETYPE_PREFIXES: tuple[str, ...] = (
    # From the splunk-search sourcetype_map (firewall / ids / network)
    "pan:",
    "cisco:asa",
    "cisco:firepower",
    "cisco:estreamer",
    "cisco:meraki",
    "cisco:ios",
    "fgt_",
    "fwsnort",
    "snort",
    "suricata",
    "bro:",
    # Cloud flow logs: host is the log group or a placeholder ("serverless")
    "aws:cloudwatchlogs:vpcflow",
    # Common network sourcetypes not yet in that map (proxy / dns / zeek)
    "zeek:",
    "bluecoat",
    "squid",
    "infoblox:",
)
"""Sourcetypes (lowercase prefixes) logged by network appliances."""

ENDPOINT_SOURCETYPE_PREFIXES: tuple[str, ...] = (
    "wineventlog",
    "xmlwineventlog",
    "crowdstrike:event",
    "carbonblack:",
    "bit9:carbonblack",
    "osquery:",
    "linux:audit",
    "linux_secure",
    "symantec:ep:",
)
"""Sourcetypes (lowercase prefixes) of endpoint telemetry."""

ENDPOINT_HOST_FIELDS: tuple[str, ...] = (
    "ComputerName",
    "Computer",
    "dest_nt_host",
    "host",
)
"""Fields naming the endpoint of endpoint telemetry, by preference: the
reporting computer before ``host``, which is the collector under WEF or EDR pulls."""

PRIVATE_NETWORKS: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
"""Internal ranges (RFC 1918): the side of a flow in them is the endpoint."""

HOSTNAME_DOMAIN_RE = r"^(?!\d+\.\d+\.\d+\.\d+$)([^.:\s]+)\..*$"
"""A hostname with a DNS suffix, capturing its first label. IPv4 addresses are
excluded by the lookahead and IPv6 addresses never match (``:`` before any ``.``).
The same PCRE runs in Python ``re`` and in SPL ``replace()``, so both paths agree."""

_HOSTNAME_DOMAIN = re.compile(HOSTNAME_DOMAIN_RE)

_PRIVATE = tuple(ipaddress.ip_network(network) for network in PRIVATE_NETWORKS)

ATTRIBUTED_HOST_FIELD = "octi_attributed_endpoint"
"""Field the connector adds to each event: the endpoint the hit is attributed to."""

EVENT_ADDRESS_FIELD = "octi_event_address"
"""Field the connector adds to each event: ``index:_cd``, unique across indexes."""


def sourcetype_class(sourcetype: str | None) -> str | None:
    """Return ``"network"``, ``"endpoint"`` or ``None`` (unknown) for a sourcetype."""
    value = (sourcetype or "").strip().lower()
    if not value:
        return None
    if value.startswith(NETWORK_SOURCETYPE_PREFIXES):
        return "network"
    if value.startswith(ENDPOINT_SOURCETYPE_PREFIXES):
        return "endpoint"
    return None


def _is_private(value: str | None) -> bool:
    try:
        address = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    return any(address in network for network in _PRIVATE)


def _first(fields: Mapping[str, Any], *names: str) -> str | None:
    lowered = {name.lower(): value for name, value in fields.items()}
    for name in names:
        value = lowered.get(name.lower())
        if isinstance(value, list):
            value = value[0] if value else None
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def normalize_host(value: str | None) -> str | None:
    """Return a hostname without its DNS suffix (``WS-01.corp.local`` -> ``WS-01``).

    Sources name the same endpoint differently: Windows ``ComputerName`` is the
    FQDN while the forwarder ``host`` is usually the short name, so the same
    machine would otherwise be reported as two victims. IP addresses are kept.
    """
    if value is None:
        return None
    return _HOSTNAME_DOMAIN.sub(r"\1", value)


def attributed_host(fields: Mapping[str, Any]) -> str | None:
    """Return the endpoint an event is about, from its sourcetype and CIM fields.

    - Network appliances: the destination of inbound traffic; otherwise the
      internal side of the flow (source first); otherwise the source, then the
      destination; ``host`` (the appliance) only when the event has no peers
      (configuration or system events).
    - Endpoint telemetry: the reporting computer before ``host``.
    - Unknown sourcetypes: ``host``, as before.

    Host names (``host``, ``ComputerName``...) lose their DNS suffix
    (``normalize_host``); network peers (``src``/``dest``) are kept as logged,
    since they may be domains (proxy and DNS destinations).
    """
    kind = sourcetype_class(_first(fields, "sourcetype"))
    host = normalize_host(_first(fields, "host"))
    if kind == "network":
        src = _first(fields, "src_ip", "src")
        dest = _first(fields, "dest_ip", "dest")
        direction = (_first(fields, "direction") or "").lower()
        if direction == "inbound" and dest:
            return dest
        if _is_private(src):
            return src
        if _is_private(dest):
            return dest
        return src or dest or host
    if kind == "endpoint":
        return normalize_host(_first(fields, *ENDPOINT_HOST_FIELDS))
    return host


def _prefix_match(prefixes: tuple[str, ...]) -> str:
    alternatives = "|".join(re.escape(prefix) for prefix in prefixes)
    pattern = f"^({alternatives})".replace("\\", "\\\\").replace('"', '\\"')
    return f'match(lower(sourcetype), "{pattern}")'


def _cidr(field: str) -> str:
    return " OR ".join(
        f'cidrmatch("{network}", {field})' for network in PRIVATE_NETWORKS
    )


def host_eval_spl() -> str:
    """Return the SPL expression equivalent to ``attributed_host()``."""
    host = _normalize_spl("host")
    src = "coalesce(src_ip, src)"
    dest = "coalesce(dest_ip, dest)"
    network = (
        f'case(lower(direction)=="inbound" AND isnotnull({dest}), {dest}, '
        f"{_cidr(src)}, {src}, "
        f"{_cidr(dest)}, {dest}, "
        f"true(), coalesce({src}, {dest}, {host}))"
    )
    endpoint = _normalize_spl(f"coalesce({', '.join(ENDPOINT_HOST_FIELDS)})")
    return (
        f"case({_prefix_match(NETWORK_SOURCETYPE_PREFIXES)}, {network}, "
        f"{_prefix_match(ENDPOINT_SOURCETYPE_PREFIXES)}, {endpoint}, "
        f"true(), {host})"
    )


def _normalize_spl(expression: str) -> str:
    """Return the SPL equivalent of ``normalize_host()`` applied to an expression."""
    pattern, group = _spl_string(HOSTNAME_DOMAIN_RE), _spl_string("\\1")
    return f"replace({expression}, {pattern}, {group})"


def _spl_string(value: str) -> str:
    """Return an SPL string literal (backslashes and quotes escaped)."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def event_address(fields: Mapping[str, Any]) -> str | None:
    """Return ``index:_cd``: ``_cd`` alone repeats across indexes."""
    index, cd = _first(fields, "index"), _first(fields, "_cd")
    return f"{index}:{cd}" if index and cd else None
