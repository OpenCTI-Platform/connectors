"""Pure-Python helpers used by the Matrix connector.

This module is intentionally dependency-free of ``matrix-nio`` and the
asyncio runtime so its contracts (TLP normalisation, deterministic
``media-content`` id derivation) can be unit-tested on any CI runner
without ``libolm`` being installed.
"""

from typing import Any, Dict

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


__all__ = ("TLP_MAP", "resolve_tlp", "media_content_id")
