"""Advanced hunting lookups of the values of indicator hunts.

Each observable type is looked up in the Defender XDR advanced hunting tables
and columns that hold it: the device tables of Defender for Endpoint, the email
tables of Defender for Office 365, the sign-ins of Microsoft Entra ID, the
logons of Defender for Identity and the activities of Defender for Cloud Apps.
A type no column holds is not looked up, and its values are reported not
searched.

The tables of a type are searched by one query, a fuzzy union: a table the
tenant does not hold (no Defender for Office 365 license, for instance) is left
out of the query instead of failing it. Each table keeps the columns naming its
event (``ReportId``, ``DeviceId``, ``NetworkMessageId``, ``Timestamp``), its
machine and its user, and the columns searched, with its name in ``SourceTable``.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass

from connectors_sdk.connectors.internal_hunt import HuntTimeWindow, IocBatch
from microsoft_defender_hunt.client import iso_time

SOURCE_TABLE_COLUMN = "SourceTable"
"""Column naming the table of each row of a lookup."""

_DEVICE_CONTEXT = (
    "Timestamp",
    "DeviceId",
    "DeviceName",
    "ReportId",
    "ActionType",
    "InitiatingProcessAccountDomain",
    "InitiatingProcessAccountName",
    "InitiatingProcessFileName",
    "InitiatingProcessFolderPath",
    "InitiatingProcessCommandLine",
)
_INITIATING_HASHES = (
    "InitiatingProcessSHA1",
    "InitiatingProcessSHA256",
    "InitiatingProcessMD5",
)
_FILE_COLUMNS = ("FileName", "FolderPath", "SHA1", "SHA256", "MD5")

TABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    "DeviceNetworkEvents": (
        *_DEVICE_CONTEXT,
        "RemoteIP",
        "RemotePort",
        "RemoteUrl",
        "LocalIP",
        "LocalPort",
        "Protocol",
        *_INITIATING_HASHES,
    ),
    "DeviceProcessEvents": (
        *_DEVICE_CONTEXT,
        "AccountDomain",
        "AccountName",
        *_FILE_COLUMNS,
        "ProcessCommandLine",
        *_INITIATING_HASHES,
    ),
    "DeviceFileEvents": (
        *_DEVICE_CONTEXT,
        *_FILE_COLUMNS,
        "FileOriginUrl",
        "FileOriginReferrerUrl",
        "FileOriginIP",
        *_INITIATING_HASHES,
    ),
    "DeviceImageLoadEvents": (*_DEVICE_CONTEXT, *_FILE_COLUMNS, *_INITIATING_HASHES),
    "DeviceEvents": (
        *_DEVICE_CONTEXT,
        "AccountDomain",
        "AccountName",
        *_FILE_COLUMNS,
        "RemoteIP",
        "RemotePort",
        "RemoteUrl",
        "FileOriginUrl",
        "FileOriginIP",
        *_INITIATING_HASHES,
    ),
    "DeviceLogonEvents": (
        *_DEVICE_CONTEXT,
        "AccountDomain",
        "AccountName",
        "LogonType",
        "RemoteIP",
        "RemoteDeviceName",
    ),
    "EmailEvents": (
        "Timestamp",
        "NetworkMessageId",
        "ReportId",
        "SenderFromAddress",
        "SenderMailFromAddress",
        "SenderFromDomain",
        "SenderMailFromDomain",
        "SenderIPv4",
        "SenderIPv6",
        "RecipientEmailAddress",
        "EmailDirection",
        "DeliveryAction",
        "ThreatTypes",
    ),
    "EmailUrlInfo": (
        "Timestamp",
        "NetworkMessageId",
        "ReportId",
        "Url",
        "UrlDomain",
        "UrlLocation",
    ),
    "EmailAttachmentInfo": (
        "Timestamp",
        "NetworkMessageId",
        "ReportId",
        "SenderFromAddress",
        "RecipientEmailAddress",
        "FileName",
        "FileType",
        "SHA256",
        "ThreatTypes",
    ),
    "UrlClickEvents": (
        "Timestamp",
        "NetworkMessageId",
        "ReportId",
        "AccountUpn",
        "ActionType",
        "Url",
        "IPAddress",
        "Workload",
    ),
    "AADSignInEventsBeta": (
        "Timestamp",
        "ReportId",
        "AccountUpn",
        "AccountObjectId",
        "Application",
        "IPAddress",
        "Country",
        "DeviceName",
        "ErrorCode",
        "LogonType",
    ),
    "IdentityLogonEvents": (
        "Timestamp",
        "ReportId",
        "AccountUpn",
        "AccountName",
        "AccountDomain",
        "ActionType",
        "DeviceName",
        "IPAddress",
        "DestinationDeviceName",
        "DestinationIPAddress",
        "Protocol",
    ),
    "CloudAppEvents": (
        "Timestamp",
        "ReportId",
        "AccountDisplayName",
        "AccountObjectId",
        "Application",
        "ActionType",
        "IPAddress",
        "CountryCode",
        "UserAgent",
    ),
}
"""Columns each table keeps in a lookup: its event, machine and user, and the columns searched."""


@dataclass(frozen=True)
class TableLookup:
    """How one table is searched for the values of one observable type.

    Attributes:
        table: Advanced hunting table.
        columns: Columns holding the values.
        match: ``exact`` (the whole value, case-insensitive), ``domain`` (a host
            name column holding the domain or a subdomain), ``url_domain`` (a URL
            or host name column holding the domain or a subdomain), ``url_host``
            (a URL or host name column holding the host itself) or ``substring``
            (the value within the column, case-sensitive).
    """

    table: str
    columns: tuple[str, ...]
    match: str = "exact"


_URL_COLUMNS: tuple[TableLookup, ...] = (
    TableLookup("DeviceNetworkEvents", ("RemoteUrl",), "substring"),
    TableLookup("DeviceEvents", ("RemoteUrl", "FileOriginUrl"), "substring"),
    TableLookup(
        "DeviceFileEvents", ("FileOriginUrl", "FileOriginReferrerUrl"), "substring"
    ),
    TableLookup("EmailUrlInfo", ("Url",), "substring"),
    TableLookup("UrlClickEvents", ("Url",), "substring"),
)

LOOKUPS: dict[str, tuple[TableLookup, ...]] = {
    "IPv4-Addr": (
        TableLookup("DeviceNetworkEvents", ("RemoteIP", "LocalIP")),
        TableLookup("DeviceLogonEvents", ("RemoteIP",)),
        TableLookup("DeviceEvents", ("RemoteIP",)),
        TableLookup("DeviceFileEvents", ("FileOriginIP",)),
        TableLookup("EmailEvents", ("SenderIPv4",)),
        TableLookup("AADSignInEventsBeta", ("IPAddress",)),
        TableLookup("IdentityLogonEvents", ("IPAddress", "DestinationIPAddress")),
        TableLookup("CloudAppEvents", ("IPAddress",)),
    ),
    "IPv6-Addr": (
        TableLookup("DeviceNetworkEvents", ("RemoteIP", "LocalIP")),
        TableLookup("DeviceLogonEvents", ("RemoteIP",)),
        TableLookup("DeviceEvents", ("RemoteIP",)),
        TableLookup("DeviceFileEvents", ("FileOriginIP",)),
        TableLookup("EmailEvents", ("SenderIPv6",)),
        TableLookup("AADSignInEventsBeta", ("IPAddress",)),
        TableLookup("IdentityLogonEvents", ("IPAddress", "DestinationIPAddress")),
        TableLookup("CloudAppEvents", ("IPAddress",)),
    ),
    "Domain-Name": (
        TableLookup("DeviceNetworkEvents", ("RemoteUrl",), "url_domain"),
        TableLookup("DeviceEvents", ("RemoteUrl", "FileOriginUrl"), "url_domain"),
        TableLookup(
            "DeviceFileEvents", ("FileOriginUrl", "FileOriginReferrerUrl"), "url_domain"
        ),
        TableLookup("EmailUrlInfo", ("UrlDomain",), "domain"),
        TableLookup(
            "EmailEvents", ("SenderFromDomain", "SenderMailFromDomain"), "domain"
        ),
        TableLookup("UrlClickEvents", ("Url",), "url_domain"),
    ),
    "Hostname": (
        TableLookup("DeviceNetworkEvents", ("RemoteUrl",), "url_host"),
        TableLookup("DeviceEvents", ("RemoteUrl",), "url_host"),
        TableLookup("EmailUrlInfo", ("UrlDomain",)),
        TableLookup("UrlClickEvents", ("Url",), "url_host"),
    ),
    "Url": _URL_COLUMNS,
    "Email-Addr": (
        TableLookup(
            "EmailEvents",
            ("SenderFromAddress", "SenderMailFromAddress", "RecipientEmailAddress"),
        ),
    ),
}
"""Tables and columns searched for each observable type, file hashes aside."""

_HASH_TABLES = (
    "DeviceProcessEvents",
    "DeviceFileEvents",
    "DeviceImageLoadEvents",
    "DeviceEvents",
)

HASH_COLUMNS: dict[str, str] = {"MD5": "MD5", "SHA-1": "SHA1", "SHA-256": "SHA256"}
"""Column of each hash algorithm (advanced hunting stores no other algorithm)."""


def _hash_lookups(column: str) -> tuple[TableLookup, ...]:
    """Return the lookups of the hashes of one algorithm: files, their processes, attachments."""
    lookups = [
        TableLookup(table, (column, f"InitiatingProcess{column}"))
        for table in _HASH_TABLES
    ]
    lookups.append(TableLookup("DeviceNetworkEvents", (f"InitiatingProcess{column}",)))
    if column == "SHA256":
        lookups.append(TableLookup("EmailAttachmentInfo", ("SHA256",)))
    return tuple(lookups)


def batch_lookups(batch: IocBatch) -> tuple[TableLookup, ...] | None:
    """Return the tables searched for a batch, or ``None`` when no column holds its type.

    Args:
        batch: Values of one observable type (and hash algorithm).

    Returns:
        The table lookups of its values.
    """
    if batch.observable_type == "StixFile":
        column = HASH_COLUMNS.get(batch.hash_algorithm or "")
        return _hash_lookups(column) if column else None
    return LOOKUPS.get(batch.observable_type)


def kql_string(value: str) -> str:
    """Quote a value as a KQL string literal."""
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return '"' + "".join(char for char in escaped if char >= " ") + '"'


def kql_regex(pattern: str) -> str:
    """Write a regular expression as a KQL verbatim string literal."""
    return '@"' + pattern.replace('"', '""') + '"'


_REGEX_SPECIAL = re.compile(r"([\\.^$|?*+()\[\]{}/])")


def _regex_text(value: str) -> str:
    """Escape a value matched literally inside a regular expression (RE2)."""
    return _REGEX_SPECIAL.sub(r"\\\1", value)


def _column_filter(column: str, match: str, values: Sequence[str]) -> str:
    """Return the KQL condition finding one of the values in a column."""
    literals = ", ".join(kql_string(value) for value in values)
    if match == "exact":
        return f"{column} in~ ({literals})"
    if match == "substring":
        return (
            "("
            + " or ".join(
                f"{column} contains_cs {kql_string(value)}" for value in values
            )
            + ")"
        )
    alternatives = "|".join(_regex_text(value) for value in values)
    if match == "domain":
        pattern = f"(?i)(^|\\.)({alternatives})$"
    elif match == "url_domain":
        pattern = f"(?i)(^|[/.@])({alternatives})(:[0-9]+)?([/?#]|$)"
    else:
        pattern = f"(?i)(^|[/@])({alternatives})(:[0-9]+)?([/?#]|$)"
    # has_any reads the term index of the column, the regular expression keeps the exact matches
    return f"({column} has_any ({literals}) and {column} matches regex {kql_regex(pattern)})"


_STRING_COLUMNS = {"ReportId": "ReportId = tostring(ReportId)"}
"""Columns typed differently across tables, cast to strings: a union of a long
and a string column splits it into ``ReportId_long`` and ``ReportId_string``."""


def time_filter(window: HuntTimeWindow) -> str:
    """Return the KQL condition keeping the events of a run window."""
    return (
        f"Timestamp between (datetime({iso_time(window.start)}) .. "
        f"datetime({iso_time(window.end)}))"
    )


def build_kql_lookup(
    batch: IocBatch,
    lookups: Sequence[TableLookup],
    window: HuntTimeWindow | None = None,
) -> str:
    """Build the advanced hunting query finding the events holding a value of a batch.

    Args:
        batch: Values of one observable type.
        lookups: Tables searched for the type.
        window: Run window, filtered on ``Timestamp`` in each table (the
            ``Timespan`` of the query restricts it as well).

    Returns:
        One query: a fuzzy union of one filtered and projected leg per table.
    """
    legs = []
    for lookup in lookups:
        steps = [lookup.table]
        if window is not None:
            steps.append(f"| where {time_filter(window)}")
        condition = " or ".join(
            _column_filter(column, lookup.match, batch.values)
            for column in lookup.columns
        )
        steps.append(f"| where {condition}")
        columns = dict.fromkeys((*TABLE_COLUMNS[lookup.table], *lookup.columns))
        steps.append(
            "| project "
            + ", ".join(_STRING_COLUMNS.get(column, column) for column in columns)
        )
        steps.append(f'| extend {SOURCE_TABLE_COLUMN} = "{lookup.table}"')
        legs.append("(" + "\n".join(steps) + ")")
    return "union isfuzzy=true\n" + ",\n".join(legs)
