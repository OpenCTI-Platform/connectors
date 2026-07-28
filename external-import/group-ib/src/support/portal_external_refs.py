from __future__ import annotations

import functools
from typing import Any

from ciaops import TICollections, generate_portal_link
from support.text_normalize import normalize_description as _norm

PortalExternalRefRow = tuple[str | None, str, str]


@functools.lru_cache(maxsize=1)
def _string_prefix_index() -> tuple[tuple[str, str], ...]:
    pairs = [
        (n, t) for n, t in TICollections.PORTAL_LINKS.items() if isinstance(t, str)
    ]
    return tuple(sorted(pairs, key=lambda x: len(x[1]), reverse=True))


def _merge_description(
    extra_short: str | None,
    extra_long: str | None,
) -> str:
    parts = [p for p in (_norm(extra_short), _norm(extra_long)) if p]
    return "\n\n".join(parts)


def portal_link_tuple(
    link: str | None,
    extra_short: str | None = None,
    extra_long: str | None = None,
) -> PortalExternalRefRow | None:
    """Build (record_id, url, description) from a portal_link string.

    ``link`` is always a plain URL string at this point — the mapping.json
    ``__concatenate`` directive is resolved into a string by ciaops's
    ``Parser._concatenate`` before the event reaches the connector.
    """
    if not isinstance(link, str):
        return None
    raw = link.strip()
    if not raw:
        return None
    collection = None
    record_id = None
    for coll, prefix in _string_prefix_index():
        if raw.startswith(prefix):
            collection = coll
            record_id = raw[len(prefix) :].split("&", 1)[0].split("#", 1)[0] or None
            break
    canonical = (
        generate_portal_link(collection, record_id=record_id)
        if collection and record_id
        else None
    )
    url = canonical or raw
    desc = _merge_description(extra_short, extra_long)
    return (record_id, url, desc)


def portal_link_row(
    collection: str,
    *,
    record_id: str | None = None,
    fields: dict[str, str] | None = None,
) -> PortalExternalRefRow | None:
    url = generate_portal_link(collection, record_id=record_id, fields=fields)
    if not url:
        return None
    return (
        str(record_id) if record_id else None,
        url,
        "",
    )


def chat_portal_link_row(
    platform: str, chat_id: Any, msg_id: Any
) -> PortalExternalRefRow | None:
    if not chat_id or not msg_id:
        return None
    if platform == "discord":
        return portal_link_row(
            "compromised/discord",
            fields={"channel.id": str(chat_id), "id": str(msg_id)},
        )
    return portal_link_row(
        "compromised/messenger",
        fields={"chatStat.id": str(chat_id), "id": str(msg_id)},
    )


def portal_external_ref_rows(
    obj: dict[str, Any] | list[Any],
) -> list[PortalExternalRefRow]:
    rows: list[PortalExternalRefRow] = []
    if isinstance(obj, list):
        for item in obj:
            if not isinstance(item, dict):
                continue
            t = portal_link_tuple(
                item.get("portal_link"),
                item.get("short_description") or item.get("shortDescription"),
                item.get("description"),
            )
            if t:
                rows.append(t)
        return rows
    if isinstance(obj, dict):
        t = portal_link_tuple(
            obj.get("portal_link"),
            obj.get("short_description") or obj.get("shortDescription"),
            obj.get("description"),
        )
        return [t] if t else []
    return []
