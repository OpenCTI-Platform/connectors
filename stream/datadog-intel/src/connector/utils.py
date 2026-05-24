#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase

from datetime import datetime, timezone

from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

STIX_TYPE_TO_INDICATOR_TYPE: dict[str, str] = {
    "IPv4-Addr": "ip_address",
    "IPv6-Addr": "ip_address",
    "Domain-Name": "domain",
    "StixFile": "sha256",
}


def main_observable_type_from_event(data: dict) -> str | None:
    """Extract the main observable type from a STIX event's extensions.

    Iterates over the event's ``extensions`` dict values looking for a
    ``main_observable_type`` field (e.g. ``IPv4-Addr``, ``Domain-Name``).

    Args:
        data: A STIX-formatted event payload.

    Returns:
        The first ``main_observable_type`` found, or ``None`` if absent.
    """

    extensions = data.get("extensions") or {}
    if not isinstance(extensions, dict):
        return None
    for ext in extensions.values():
        if isinstance(ext, dict):
            main_observable_type = ext.get("main_observable_type")
            if main_observable_type is not None:
                return main_observable_type
    return None


def indicator_id_from_event(data: dict) -> str | None:
    """Extract the indicator ID from a STIX event's extensions.

    Args:
        data: A STIX-formatted event payload.

    Returns:
        The first ``id`` found inside an extension dict, or ``None``.
    """
    extensions = data.get("extensions") or {}
    if not isinstance(extensions, dict):
        return None
    for ext in extensions.values():
        if isinstance(ext, dict):
            indicator_id = ext.get("id")
            if indicator_id is not None:
                return indicator_id
    return None


def indicator_type_for_event(data: dict) -> str | None:
    """Return the indicator_type key for an event based on its STIX observable type.

    Args:
        data: A STIX-formatted event payload.

    Returns:
        One of ``"ip_address"``, ``"domain"``, ``"sha256"``, or ``None``.
    """
    stix_type = main_observable_type_from_event(data)
    return STIX_TYPE_TO_INDICATOR_TYPE.get(stix_type) if stix_type else None


def normalize_event_type(data: dict) -> str:
    """Normalize the event type, treating initial-load messages as creates.

    Events from the initial SSE load either lack an ``event_type`` or carry
    the generic ``"message"`` type; both are mapped to ``"create"``.

    Args:
        data: A STIX-formatted event payload.

    Returns:
        One of ``"create"``, ``"update"``, ``"delete"``, or the raw
        ``event_type`` value.
    """
    is_initial = not data.get("event_type") or data.get("event_type") == "message"
    return "create" if is_initial else data.get("event_type")


def _parse_valid_until(value: str) -> datetime | None:
    """Parse a STIX ``valid_until`` timestamp to a UTC-aware ``datetime``.

    OpenCTI / STIX stream payloads commonly serialise ``valid_until``
    as an RFC3339 string with a trailing ``Z`` (e.g.
    ``2024-04-29T12:33:20.098Z``). ``datetime.fromisoformat`` only
    learned to accept that ``Z`` suffix in Python 3.11 — on older
    runtimes the call raises ``ValueError`` and crashes the
    stream callback for the offending event.

    Normalise a trailing ``Z`` to ``+00:00`` first, then coerce
    timezone-naive values to UTC so the downstream
    ``< datetime.now(timezone.utc)`` comparison never raises
    ``TypeError`` on aware-vs-naive operands. Returns ``None`` for
    inputs we cannot parse so the caller can decide how to treat
    them (current contract: do not drop the event on parse failure;
    just skip the expiry check).
    """
    normalised = value.strip()
    if normalised.endswith("Z"):
        normalised = normalised[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_valid_event(
    data: dict, helper: OpenCTIConnectorHelper, config: ConnectorSettings
) -> bool:
    """Determine whether an event should be forwarded to the Datadog API.

    An event is valid when it represents a STIX indicator with an allowed
    observable type, a recognized event type (create/update/delete), and a
    ``valid_until`` date that has not yet passed.

    ``delete`` events are exempt from the ``valid_until`` check: even
    if the indicator has expired, the delete still needs to reach
    Datadog so a previously-forwarded indicator is dropped from the
    remote feed instead of remaining stale (the pre-fix shape
    silently swallowed the delete and left Datadog out of sync with
    OpenCTI).

    Args:
        data: A STIX-formatted event payload.
        helper: The helper of the connector. Used for logs.
        config: The configuration of the connector. Used to get the indicator type.

    Returns:
        ``True`` if the event should be forwarded, ``False`` otherwise.
    """

    # Check if the event is an indicator and a STIX event
    entity_type = data.get("type")
    pattern_type = data.get("pattern_type", "")
    if entity_type != "indicator" or not pattern_type.startswith("stix"):
        helper.connector_logger.debug(
            "Skipping non-indicator or non-STIX message",
            meta={"entity_type": entity_type, "pattern_type": pattern_type},
        )
        return False

    # Normalize and check the event type (initial-load messages are mapped to create)
    effective_event_type = normalize_event_type(data)

    if effective_event_type not in ("create", "update", "delete"):
        helper.connector_logger.debug(
            "Skipping unknown event type",
            meta={"event_type": effective_event_type},
        )
        return False

    # Check if the indicator type is allowed
    indicator_type = indicator_type_for_event(data)
    if indicator_type not in config.datadog_intel.indicator_type:
        helper.connector_logger.debug(
            "Skipping indicator with no allowed type",
            meta={"type": indicator_type},
        )
        return False

    # Check if the indicator has expired. The expiry filter must NOT
    # drop ``delete`` events: even an expired indicator's delete
    # event needs to reach Datadog so a previously-forwarded record
    # is removed from the remote feed.
    valid_until = data.get("valid_until")
    if valid_until and effective_event_type != "delete":
        parsed_valid_until = _parse_valid_until(valid_until)
        if parsed_valid_until is not None and parsed_valid_until < datetime.now(
            timezone.utc
        ):
            helper.connector_logger.debug(
                "Skipping expired indicator",
                meta={"valid_until": valid_until, "id": data.get("id")},
            )
            return False

    return True
