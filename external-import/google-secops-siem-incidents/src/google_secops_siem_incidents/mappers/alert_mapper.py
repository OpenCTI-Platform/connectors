"""Map alert fields to observables based on their stringVal values."""

import ipaddress
import re
from typing import Any

from connectors_sdk.models import (
    URL,
    DomainName,
    EmailAddress,
    Hostname,
    IPV4Address,
    IPV6Address,
    MACAddress,
    UserAccount,
)
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.enums import AccountType
from google_secops_siem_incidents.models.rule_alert_response import AlertField

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")
_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$"
)

_NAME_HINTS: dict[str, str] = {
    "ip": "ipv4",
    "hostname": "hostname",
    "host": "hostname",
    "domain": "domain",
    "email": "email",
    "url": "url",
    "mac": "mac",
    "user": "user_account",
}


def _classify_value(value: str) -> str | None:
    """Classify a string value into an observable type key by pattern matching.

    Returns:
        Observable kind string, or None if the value cannot be classified.
    """
    try:
        addr = ipaddress.ip_address(value)
        return "ipv6" if addr.version == 6 else "ipv4"
    except ValueError:
        pass

    if _URL_RE.match(value):
        return "url"

    if _EMAIL_RE.match(value):
        return "email"

    if _MAC_RE.match(value):
        return "mac"

    if _HOSTNAME_RE.match(value):
        return "hostname"

    return None


def _classify_by_name(name: str) -> str | None:
    """Try to infer observable type from the alert field name.

    Returns:
        Observable kind string, or None if no hint matches.
    """
    name_lower = name.lower()
    for hint, kind in _NAME_HINTS.items():
        if hint in name_lower:
            return kind
    return None


def _classify(field: AlertField) -> str | None:
    """Classify an alert field into an observable type.

    Value-based pattern matching takes priority; the field name is used as a
    fallback when the value alone is ambiguous.

    Returns:
        Observable kind string, or None if the field cannot be classified.
    """
    value = field.string_val.strip()
    kind = _classify_value(value)
    if kind is not None:
        return kind
    return _classify_by_name(field.name)


def _infer_account_type(uid: str) -> AccountType:
    """Infer AccountType from the shape of the user identifier string."""
    if "\\" in uid:
        return AccountType.WINDOWS_DOMAIN
    if "@" in uid:
        return AccountType.LDAP
    return AccountType.UNIX


def _make_observable(
    kind: str,
    value: str,
    *,
    author: Any,
    tlp_marking: Any,
) -> BaseObservableEntity:
    """Instantiate the appropriate observable model for *kind*."""
    common: dict[str, Any] = {"author": author, "markings": [tlp_marking]}

    if kind == "ipv4":
        return IPV4Address(value=value, **common)
    if kind == "ipv6":
        return IPV6Address(value=value, **common)
    if kind == "url":
        return URL(value=value, **common)
    if kind == "email":
        return EmailAddress(value=value, **common)
    if kind == "mac":
        return MACAddress(value=value, **common)
    if kind == "domain":
        return DomainName(value=value, **common)
    if kind == "user_account":
        return UserAccount(
            user_id=value,
            account_login=value,
            account_type=_infer_account_type(value),
            **common,
        )
    # hostname (default)
    return Hostname(value=value, **common)


def map_alert_fields(
    fields: list[AlertField],
    *,
    author: Any,
    tlp_marking: Any,
) -> list[BaseObservableEntity]:
    """Create observables from every alert field that has a valid stringVal.

    Each field's value is classified (by pattern, then by field name) and
    converted to the matching connectors-sdk observable model.  Duplicate
    (kind, value) pairs are silently deduplicated.

    Args:
        fields: List of alert fields to inspect.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        Deduplicated list of observable model instances (may be empty).
    """
    seen: set[tuple[str, str]] = set()
    result: list[BaseObservableEntity] = []

    for field in fields:
        if not field.string_val or not field.string_val.strip():
            continue

        value = field.string_val.strip()
        kind = _classify(field)
        if kind is None:
            continue

        key = (kind, value)
        if key in seen:
            continue
        seen.add(key)

        result.append(
            _make_observable(kind, value, author=author, tlp_marking=tlp_marking)
        )

    return result
