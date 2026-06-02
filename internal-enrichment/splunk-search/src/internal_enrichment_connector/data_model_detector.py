from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Regex: extract explicit datamodel= reference from a SPL query string
# ---------------------------------------------------------------------------
_DATAMODEL_RE = re.compile(
    r"\b(?:datamodel\s*=\s*|from\s+datamodel\s*=\s*)([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Sourcetype prefix → CIM Data Model
# Priority: more-specific prefixes listed before generic ones.
# ---------------------------------------------------------------------------
_SOURCETYPE_TO_DATAMODEL: list[tuple[str, str]] = [
    # Authentication / Identity
    ("ms:aad:signin", "Authentication"),
    ("ms:aad", "Authentication"),
    ("ms:o365:azure:ad", "Authentication"),
    ("okta:system", "Authentication"),
    ("okta:user", "Authentication"),
    ("cisco:ise", "Authentication"),
    ("wineventlog:security", "Authentication"),
    ("wineventlog:microsoft-windows-security-auditing", "Authentication"),
    ("ldap:audit", "Change"),
    # Email
    ("ms:o365:email", "Email"),
    ("ms:o365:reporting:messagetrace", "Email"),
    ("proofpoint:mail", "Email"),
    ("proofpoint:tap", "Email"),
    ("gsuite:gmail", "Email"),
    ("mimecast:email", "Email"),
    # DNS / Network Resolution
    ("bro:dns", "Network_Resolution"),
    ("zeek:dns", "Network_Resolution"),
    ("pan:dns", "Network_Resolution"),
    ("cisco:umbrella:dns", "Network_Resolution"),
    # Network Traffic
    ("pan:traffic", "Network_Traffic"),
    ("pan:firewall", "Network_Traffic"),
    ("pan:threat", "Network_Traffic"),
    ("cisco:asa", "Network_Traffic"),
    ("cisco:fwsm", "Network_Traffic"),
    ("cisco:ios", "Network_Traffic"),
    ("juniper:junos", "Network_Traffic"),
    ("checkpoint:firewall", "Network_Traffic"),
    ("bro:conn", "Network_Traffic"),
    ("zeek:conn", "Network_Traffic"),
    ("aws:vpcflow", "Network_Traffic"),
    ("azure:nsg:flowlogs", "Network_Traffic"),
    # Web
    ("iis", "Web"),
    ("ms:iis", "Web"),
    ("apache:access", "Web"),
    ("nginx:plus:kv", "Web"),
    ("aws:cloudfront:accesslogs", "Web"),
    ("pan:url", "Web"),
    ("squid:access", "Web"),
    # Endpoint (general — EventCode determines sub-model)
    ("xmlwindeventlog:microsoft-windows-sysmon/operational", "Endpoint"),
    ("sysmon", "Endpoint"),
    ("wineventlog:system", "Endpoint"),
    ("xmlwindeventlog:microsoft-windows-powershell/operational", "Endpoint"),
    # Change / Active Directory
    ("wineventlog:active directory", "Change"),
]

# ---------------------------------------------------------------------------
# CIM field-name signatures: ordered from most-specific to least-specific.
# A row must match at least _MIN_FIELD_MATCHES fields to be classified.
# ---------------------------------------------------------------------------
_FIELD_SIGNATURES: list[tuple[str, frozenset[str]]] = [
    # Registry (very specific field names)
    (
        "Endpoint.Registry",
        frozenset({"registry_hive", "registry_key_name", "registry_value_name"}),
    ),
    # Filesystem
    (
        "Endpoint.Filesystem",
        frozenset({"file_path", "file_name", "file_hash", "file_create_time"}),
    ),
    # Processes
    (
        "Endpoint.Processes",
        frozenset(
            {"process_name", "process_id", "parent_process", "parent_process_id"}
        ),
    ),
    # Email
    (
        "Email",
        frozenset({"message_id", "src_user", "recipient", "subject"}),
    ),
    # DNS
    (
        "Network_Resolution",
        frozenset({"query", "query_type", "record_type", "answer"}),
    ),
    # Web (http-specific fields)
    (
        "Web",
        frozenset({"url", "http_user_agent", "http_method", "status", "bytes"}),
    ),
    # Network Traffic (byte and port fields)
    (
        "Network_Traffic",
        frozenset({"bytes_in", "bytes_out", "transport", "dest_port", "src_port"}),
    ),
    # Authentication (action + identity fields)
    (
        "Authentication",
        frozenset({"action", "user", "src", "dest", "app"}),
    ),
    # Change / Active Directory
    (
        "Change",
        frozenset({"object_category", "object_path", "dvc", "change_type"}),
    ),
]

_MIN_FIELD_MATCHES = 2


def detect_data_model(
    row: dict,
    spl_query: Optional[str] = None,
) -> Optional[str]:
    """Detect the Splunk CIM Data Model for a search result row.

    Detection is attempted in this priority order:

    1. **SPL query** — if *spl_query* contains ``datamodel=<Name>`` or
       ``from datamodel=<Name>``, that name is returned immediately.
    2. **Sourcetype prefix** — the ``sourcetype`` field in *row* is matched
       against a built-in prefix table.
    3. **Field signature heuristic** — the field names present in *row* are
       compared against per-model signatures; the first model whose signature
       produces at least two matches is returned.

    Returns the CIM Data Model name (e.g. ``"Authentication"``,
    ``"Network_Traffic"``) or ``None`` when the model cannot be determined.
    """
    # 1. Explicit datamodel= in the SPL string
    if spl_query:
        m = _DATAMODEL_RE.search(spl_query)
        if m:
            return m.group(1)

    # 2. Sourcetype prefix match (exact → prefix fallback)
    sourcetype = str(row.get("sourcetype") or "").strip().lower()
    if sourcetype:
        for prefix, model in _SOURCETYPE_TO_DATAMODEL:
            if sourcetype == prefix or sourcetype.startswith(prefix + ":"):
                return model

    # 3. Field-name signature heuristic
    row_keys = frozenset(k.lower() for k in row)
    for model, signature in _FIELD_SIGNATURES:
        if len(signature & row_keys) >= _MIN_FIELD_MATCHES:
            return model

    return None
