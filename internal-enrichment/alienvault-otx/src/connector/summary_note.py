"""Markdown summary of an OTX `general` answer, the content of the enrichment note.

The module is pure: it reads an `OtxGeneral` and returns text, with no network call and
no import of the processor. The text is a function of the OTX data only, so the same
data gives the same note content, whatever the order of the pulses.
"""

import re
from collections.abc import Callable, Iterable

from otx_client import OTX_SECTIONS, OtxGeneral, OtxPulse

NOTE_TITLE = "AlienVault OTX Enrichment Results"

# Only the IPv4 section of OTX carries a reputation and a geolocation
_IPV4_SECTION = OTX_SECTIONS["IPv4-Addr"]

# Characters that Markdown reads as formatting, links, HTML or table cells
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_\[\]<>|#])")


def _collapse_whitespace(text: str) -> str:
    """Replace every run of whitespace (newlines and tabs included) by one space.

    A value that holds a line break would end its bullet or start a new Markdown block.
    """
    return " ".join(text.split())


def _escape_markdown(text: str) -> str:
    """Backslash-escape the characters that Markdown would interpret.

    Args:
        text: A value read from OTX.

    Returns:
        The text that renders literally, `\\`, `` ` ``, `*`, `_`, `[`, `]`, `<`, `>`,
        `|` and `#` being prefixed with a backslash.
    """
    return _MARKDOWN_SPECIAL.sub(r"\\\1", text)


def _union(
    pulses: Iterable[OtxPulse], field: Callable[[OtxPulse], list[str]]
) -> list[str]:
    """Merge one list field of the pulses into a deterministic list.

    Inner whitespace is collapsed first, then items that differ only by case are one
    item, shown with the smallest of the spellings seen. The result is sorted case-insensitively, so it does not depend on
    the order of the pulses.
    """
    variants: dict[str, str] = {}
    for pulse in pulses:
        for raw_item in field(pulse):
            item = _collapse_whitespace(raw_item)
            if not item:
                continue
            key = item.casefold()
            variants[key] = min(variants.get(key, item), item)
    return sorted(variants.values(), key=lambda item: (item.casefold(), item))


def _fields(rows: list[tuple[str, str | int | None]]) -> list[str]:
    """Render the `- **Label**: value` lines of the rows that have a value."""
    cleaned = [
        (label, _collapse_whitespace(str(value)))
        for label, value in rows
        if value is not None
    ]
    return [
        f"- **{label}**: {_escape_markdown(value)}" for label, value in cleaned if value
    ]


def _bullets(items: list[str]) -> list[str]:
    cleaned = (_collapse_whitespace(item) for item in items)
    return [f"- {_escape_markdown(item)}" for item in cleaned if item]


def render_summary(section: str, general: OtxGeneral) -> str:
    """Render the Markdown content of the enrichment note.

    One `##` heading per non-empty section, in this order: General (the OTX section that
    answered, and the reputation), Geolocation, Tags, Malware families, MITRE ATT&CK
    IDs and Targeted industries. The reputation and the geolocation exist for IPv4
    addresses only, and only the fields OTX has are shown (a reputation of 0 is shown).
    The lists are the union over the pulses. The targeted countries and the indicator
    value are not rendered, and the title is not repeated.

    Args:
        section: OTX API section that answered (`IPv4`, `domain`, `hostname` or `url`).
        general: The `general` section that answered.

    Returns:
        The Markdown text, with no trailing newline.
    """
    is_ipv4 = section == _IPV4_SECTION
    pulses = general.pulse_info.pulses

    blocks: list[tuple[str, list[str]]] = [
        (
            "General",
            _fields(
                [
                    ("Type", section),
                    ("OTX reputation", general.reputation if is_ipv4 else None),
                ]
            ),
        ),
        (
            "Geolocation",
            _fields(
                [
                    ("City", general.city if is_ipv4 else None),
                    ("Region", general.region if is_ipv4 else None),
                    ("Country", general.country_name if is_ipv4 else None),
                ]
            ),
        ),
        ("Tags", _bullets(_union(pulses, lambda pulse: pulse.tags))),
        (
            "Malware families",
            _bullets(_union(pulses, lambda pulse: pulse.malware_families)),
        ),
        (
            "MITRE ATT&CK IDs",
            _bullets(_union(pulses, lambda pulse: pulse.attack_ids)),
        ),
        (
            "Targeted industries",
            _bullets(_union(pulses, lambda pulse: pulse.industries)),
        ),
    ]
    return "\n\n".join(
        "\n".join([f"## {title}", "", *lines]) for title, lines in blocks if lines
    )
