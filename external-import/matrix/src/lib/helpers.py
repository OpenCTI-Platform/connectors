"""Pure-Python helpers used by the Matrix connector.

This module is intentionally dependency-free of ``matrix-nio`` and the
asyncio runtime so its contracts (TLP normalisation, deterministic
``media-content`` id derivation, channel-name fallback, event timestamp
coercion) can be unit-tested on any CI runner without ``libolm`` being
installed.
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

import stix2
from pycti import CustomObservableMediaContent

# ``stix2`` exposes constants for TLP_WHITE / GREEN / AMBER / RED.
# ``TLP:AMBER+STRICT`` is an OpenCTI-specific marking and is not
# exported as a constant, so we keep its canonical id here.
_TLP_AMBER_STRICT_ID = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"

TLP_MAP: Dict[str, str] = {
    "CLEAR": stix2.TLP_WHITE.id,
    "WHITE": stix2.TLP_WHITE.id,
    "GREEN": stix2.TLP_GREEN.id,
    "AMBER": stix2.TLP_AMBER.id,
    "AMBER_STRICT": _TLP_AMBER_STRICT_ID,
    "AMBER+STRICT": _TLP_AMBER_STRICT_ID,
    "RED": stix2.TLP_RED.id,
}


def resolve_tlp(name: Any) -> str:
    """Return the marking-definition id for ``name`` (case-insensitive).

    Accepted forms (also accepted with any combination of upper/lower
    case, surrounding whitespace, and either ``_`` / space / ``-`` as
    the word separator on the strict variant):

    * ``CLEAR`` / ``WHITE`` (alias of ``CLEAR``)
    * ``GREEN``
    * ``AMBER``
    * ``AMBER_STRICT`` / ``AMBER+STRICT`` (also accepted as
      ``AMBER STRICT`` / ``AMBER-STRICT``)
    * ``RED``

    Anything else raises :class:`ValueError` listing every supported
    alias verbatim, derived from :data:`TLP_MAP` so the error message
    can never drift from the runtime behaviour.
    """
    # Collapse ``-`` and `` `` (space) to ``_`` so users typing
    # ``AMBER-STRICT`` / ``amber strict`` get the same answer as
    # ``AMBER_STRICT``. ``+`` is preserved so the canonical
    # ``AMBER+STRICT`` form keeps working.
    text = name if isinstance(name, str) else ""
    normalised = text.strip().upper().replace(" ", "_").replace("-", "_")
    try:
        return TLP_MAP[normalised]
    except KeyError as exc:
        valid = ", ".join(sorted(TLP_MAP))
        raise ValueError(
            f"Unsupported MATRIX_TLP value '{name}'. Expected one of {valid}."
        ) from exc


def media_content_id(event_id: str) -> str:
    """Return the deterministic STIX id for the ``media-content`` observable.

    ``CustomObservableMediaContent`` derives its ``id`` from the
    ``url`` value, so a stub instance is enough to compute it without
    a round-trip through OpenCTI. This lets the connector link a
    thread reply to the deterministic id of its root post even when
    that root was ingested in a previous run.
    """
    stub = CustomObservableMediaContent(url=event_id, allow_custom=True)
    return stub["id"]


def channel_display_name(room_id: str, room_name: Optional[str]) -> str:
    """Return the human-friendly name to use for a Matrix room.

    The Matrix ``room_id`` (e.g. ``!abcdef:matrix.example.org``) is an
    opaque identifier — operators looking at the *Channels* list in
    OpenCTI expect to see the room display name (``#general``) instead.
    Falls back to the raw ``room_id`` when the display name is empty
    or :data:`None` so the Channel SDO is always queryable. The
    deterministic ``standard_id`` is still computed from ``room_id``
    so dedup is unaffected by the name we pick here.
    """
    name = (room_name or "").strip()
    return name or room_id


def publication_date_from_event(
    event: Any, log_warning: Callable[[str], None]
) -> datetime:
    """Return a timezone-aware UTC ``datetime`` for ``event.server_timestamp``.

    Matrix events normally carry a millisecond Unix timestamp, but
    malformed / synthetic events may have a missing or non-numeric
    ``server_timestamp``. Rather than letting the resulting
    ``TypeError`` cascade through the connector's outer ``except`` block
    (which would silently drop the event), we fall back to "now" and
    call ``log_warning`` so operators can see that something is off
    without losing the row.

    ``log_warning`` is injected so this helper can be unit-tested
    without a live ``OpenCTIConnectorHelper`` — the connector passes
    ``self.helper.log_warning`` at runtime.
    """
    ts = getattr(event, "server_timestamp", None)
    # ``bool`` is a subclass of ``int``; reject it explicitly so a
    # synthetic event carrying ``server_timestamp=True`` does not get
    # parsed as a millisecond timestamp of 1ms past the epoch.
    if isinstance(ts, bool):
        ts = None
    if isinstance(ts, (int, float)) and ts > 0:
        return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
    event_id = getattr(event, "event_id", "<unknown>")
    log_warning(
        f"Event {event_id} has no usable server_timestamp ({ts!r}); "
        "falling back to current time."
    )
    return datetime.now(tz=timezone.utc)


__all__ = (
    "TLP_MAP",
    "resolve_tlp",
    "media_content_id",
    "channel_display_name",
    "publication_date_from_event",
)
