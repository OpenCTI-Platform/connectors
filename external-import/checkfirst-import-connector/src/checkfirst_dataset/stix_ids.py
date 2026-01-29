from __future__ import annotations

"""Deterministic STIX identifier helpers.

OpenCTI connectors should generate stable STIX IDs to avoid duplicates across
re-runs. This module uses UUIDv5 (name-based) with a normalized join of key
fields, then formats the STIX identifier as `<type>--<uuid>`.
"""

import uuid


def _norm(value: str) -> str:
    """Normalize ID components to make UUIDv5 generation stable."""
    return (value or "").strip().lower()


def _uuid5(*parts: str) -> uuid.UUID:
    """Create a UUIDv5 from normalized parts."""
    joined = "|".join(_norm(p) for p in parts)
    return uuid.uuid5(uuid.NAMESPACE_URL, joined)


def stix_id(stix_type: str, *parts: str) -> str:
    """Create a STIX identifier for `stix_type` using UUIDv5 over `parts`."""
    if not stix_type:
        raise ValueError("stix_type is required")
    return f"{stix_type}--{_uuid5(stix_type, *parts)}"


def identity_id(name: str) -> str:
    """Deterministic ID for an `identity` object."""
    return stix_id("identity", name)


def channel_id(name: str) -> str:
    """Deterministic ID for a `channel` (custom) object."""
    return stix_id("channel", name)


def media_content_id(url: str) -> str:
    """Deterministic ID for a `media-content` (custom) object."""
    return stix_id("media-content", url)


def url_observable_id(value: str) -> str:
    """Deterministic ID for a URL SCO (`url`)."""
    return stix_id("url", value)


def relationship_id(
    relationship_type: str,
    source_ref: str,
    target_ref: str,
    start_time: str | None = None,
) -> str:
    """Deterministic ID for a STIX `relationship`.

    `start_time` is included only when provided so that callers can opt into a
    time-scoped relationship identity without breaking existing IDs.
    """
    # Include start_time only when provided, to preserve deterministic stability.
    parts = [relationship_type, source_ref, target_ref]
    if start_time:
        parts.append(start_time)
    return stix_id("relationship", *parts)
