"""Parsing of Malanta's namespaced labels.

Malanta emits attribution as flat, namespaced label strings on Indicators, for
example ``apt:APT44``. This module turns those strings into a clean list of
threat-actor names.

Three quirks of the live feed drive the implementation:

- A single token may carry several comma-joined actors (``apt:APT17,APT5``).
  This is an upstream data bug; both actors usually also appear as their own
  tokens on the same object, so splitting must be followed by de-duplication.
- Actor names may contain spaces (``apt:Earth Lusca``), so whitespace is never
  a separator.
- Casing is inconsistent across the feed (``apt:turla`` and ``apt:Turla``).
  Matching is case-insensitive, but the first spelling seen is kept for display
  so the entity name stays human-readable.
"""

from typing import Any, Iterable, Sequence

DEFAULT_PREFIX = "apt:"
DEFAULT_SEPARATORS = (",",)


def extract_label_values(entity: dict[str, Any]) -> list[str]:
    """Return an entity's labels as plain strings.

    The live stream is not consistent about label shape: STIX objects carry
    ``labels`` as a list of strings, while some OpenCTI payloads use a list of
    ``{"value": ...}`` dicts. Both are accepted here so callers do not have to
    care which one they received.

    :param entity: Entity payload from a stream event.
    :return: Label values as strings, in their original order.
    """
    raw_labels = entity.get("labels") or []
    values: list[str] = []
    for label in raw_labels:
        if isinstance(label, str):
            values.append(label)
        elif isinstance(label, dict):
            value = label.get("value")
            if isinstance(value, str):
                values.append(value)
    return values


def parse_actor_labels(
    labels: Iterable[str],
    prefix: str = DEFAULT_PREFIX,
    separators: Sequence[str] = DEFAULT_SEPARATORS,
) -> list[str]:
    """Extract threat-actor names from namespaced labels.

    Labels not carrying ``prefix`` are ignored, which is what keeps the other
    Malanta namespaces (``source:``, ``redistributed-by:``) and the flat labels
    (``IOC``, ``IOPA``, ``domain``, ``attack-infrastructure``) out of the result.

    :param labels: Label values to inspect.
    :param prefix: Namespace marking a label as attribution, e.g. ``apt:``.
    :param separators: Characters that split several actors inside one token.
    :return: De-duplicated actor names, in first-seen order.

    >>> parse_actor_labels(["IOC", "apt:APT44", "source:malanta"])
    ['APT44']
    >>> parse_actor_labels(["apt:APT17", "apt:APT17,APT5"])
    ['APT17', 'APT5']
    >>> parse_actor_labels(["apt:Earth Lusca"])
    ['Earth Lusca']
    """
    if not prefix:
        raise ValueError("prefix must not be empty")

    normalised_prefix = prefix.lower()
    actors: list[str] = []
    seen: set[str] = set()

    for label in labels:
        if not isinstance(label, str):
            continue
        if not label.lower().startswith(normalised_prefix):
            continue

        value = label[len(prefix) :]
        for name in _split_on_any(value, separators):
            name = name.strip()
            if not name:
                continue
            # Case-insensitive de-duplication, but keep the first spelling seen:
            # the feed mixes `apt:turla` and `apt:Turla` for the same actor and
            # they must not become two Intrusion Sets.
            key = name.casefold()
            if key in seen:
                continue
            seen.add(key)
            actors.append(name)

    return actors


def _split_on_any(value: str, separators: Sequence[str]) -> list[str]:
    """Split ``value`` on every separator in ``separators``.

    :param value: The string to split.
    :param separators: Characters to split on. Empty means no splitting.
    :return: The resulting parts, unstripped.
    """
    parts = [value]
    for separator in separators:
        if not separator:
            continue
        parts = [piece for part in parts for piece in part.split(separator)]
    return parts
