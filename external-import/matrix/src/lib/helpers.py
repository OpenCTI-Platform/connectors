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
from pycti import MarkingDefinition as PyctiMarkingDefinition


def _make_tlp_marking(definition: str) -> stix2.MarkingDefinition:
    """Return a ``stix2.MarkingDefinition`` for an OpenCTI-specific TLP value.

    Used for ``TLP:CLEAR`` and ``TLP:AMBER+STRICT`` which the platform
    represents as custom marking-definition objects (the STIX 2.1
    library only exposes built-in constants for ``TLP_WHITE`` /
    ``TLP_GREEN`` / ``TLP_AMBER`` / ``TLP_RED``). Building a real
    ``stix2.MarkingDefinition`` lets the connector ship the marking
    object in every bundle, which is what
    ``connectors-sdk.models.tlp_marking`` and the rest of the
    external-import family do.
    """
    return stix2.MarkingDefinition(
        id=PyctiMarkingDefinition.generate_id("TLP", definition),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition=definition,
    )


# ``TLP:CLEAR`` and ``TLP:AMBER+STRICT`` are OpenCTI-specific markings
# and are not exposed as ``stix2`` constants. They are materialised as
# real ``stix2.MarkingDefinition`` objects so the connector can ship
# the marking object itself in every emitted bundle (alongside the
# data referencing it), which is what registers the OpenCTI-specific
# markings with the platform.
#
# ``CLEAR`` is **not** an alias of ``stix2.TLP_WHITE``: although
# ``pycti.MarkingDefinition.generate_id("TLP", "TLP:CLEAR")`` happens
# to derive the same canonical id as ``stix2.TLP_WHITE.id`` (the STIX
# 2.1 derivation is deterministic on the marking name), the
# **marking-definition object** the connector emits is different —
# it carries ``x_opencti_definition='TLP:CLEAR'`` so the OpenCTI UI
# shows the modern ``TLP:CLEAR`` label rather than the legacy
# ``TLP:WHITE`` label. Operators who explicitly configure
# ``MATRIX_TLP=WHITE`` still get the legacy ``stix2.TLP_WHITE``
# marking object.
TLP_MAP: Dict[str, stix2.MarkingDefinition] = {
    "CLEAR": _make_tlp_marking("TLP:CLEAR"),
    "WHITE": stix2.TLP_WHITE,
    "GREEN": stix2.TLP_GREEN,
    "AMBER": stix2.TLP_AMBER,
    "AMBER_STRICT": _make_tlp_marking("TLP:AMBER+STRICT"),
    "AMBER+STRICT": _make_tlp_marking("TLP:AMBER+STRICT"),
    "RED": stix2.TLP_RED,
}


def resolve_tlp(name: Any) -> stix2.MarkingDefinition:
    """Return the ``stix2.MarkingDefinition`` for ``name`` (case-insensitive).

    Accepted forms (also accepted with any combination of upper/lower
    case, surrounding whitespace, and either ``_`` / space / ``-`` as
    the word separator on the strict variant):

    * ``CLEAR`` (OpenCTI-specific ``TLP:CLEAR`` marking)
    * ``WHITE`` (legacy ``stix2.TLP_WHITE`` marking)
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
    # parsed as a millisecond timestamp of 1ms past the epoch. We keep
    # the raw value in ``ts`` so the fallback warning below logs the
    # exact value carried by the event (``True`` / ``False`` / ...)
    # instead of a normalised ``None``, which makes diagnosing
    # malformed events much easier.
    if not isinstance(ts, bool) and isinstance(ts, (int, float)) and ts > 0:
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
