from __future__ import annotations

import uuid


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def _uuid5(*parts: str) -> uuid.UUID:
    joined = "|".join(_norm(p) for p in parts)
    return uuid.uuid5(uuid.NAMESPACE_URL, joined)


def stix_id(stix_type: str, *parts: str) -> str:
    if not stix_type:
        raise ValueError("stix_type is required")
    return f"{stix_type}--{_uuid5(stix_type, *parts)}"


def identity_id(name: str) -> str:
    return stix_id("identity", name)


def channel_id(name: str) -> str:
    return stix_id("channel", name)


def media_content_id(url: str) -> str:
    return stix_id("media-content", url)


def url_observable_id(value: str) -> str:
    return stix_id("url", value)


def relationship_id(
    relationship_type: str,
    source_ref: str,
    target_ref: str,
    start_time: str | None = None,
) -> str:
    # Include start_time only when provided, to preserve deterministic stability.
    parts = [relationship_type, source_ref, target_ref]
    if start_time:
        parts.append(start_time)
    return stix_id("relationship", *parts)
