"""MITRE ATT&CK techniques detected by rules.

Every rule Indicator gets an ``indicates`` relationship to the Attack
Pattern of each technique it detects. The target id is
``pycti.AttackPattern.generate_id`` keyed on the MITRE id, which is the
standard id of the technique imported from the MITRE ATT&CK dataset. The
platform is asked once per run which techniques it already holds: those
are referenced only, so the import never renames or re-attributes them;
the others are created under the name the vendor gives, or their MITRE id.
"""

import re
from collections.abc import Iterable

import stix2
from pycti import AttackPattern, OpenCTIConnectorHelper

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
# Free text: an uppercase id standing alone (``T1059``, ``T1059.001``).
_TECHNIQUE_IN_TEXT_RE = re.compile(
    r"(?<![A-Za-z0-9_.])(T\d{4})(?:\.(\d{3}))?(?![A-Za-z0-9_]|\.\d)"
)
# ATT&CK website links: ``attack.mitre.org/techniques/T1059/001``.
_TECHNIQUE_URL_RE = re.compile(
    r"attack\.mitre\.org/techniques/(T\d{4})(?:/(\d{3}))?", re.IGNORECASE
)

# Ids per GraphQL ``ids`` filter: keeps each query small and bounded.
_LOOKUP_BATCH_SIZE = 100


def normalize_technique_id(value: object) -> str | None:
    """Return the uppercase technique id ``value`` holds, ``None`` otherwise."""
    if value is None:
        return None
    candidate = str(value).strip()
    return candidate.upper() if _TECHNIQUE_ID_RE.match(candidate) else None


def extract_technique_ids(*texts: str | None) -> list[str]:
    """Extract technique ids written in free text, in order of appearance.

    Only standalone uppercase ids (``T1059``, ``T1059.001``) and ATT&CK
    website links count, so words, hashes or version numbers never match.
    """
    found: list[str] = []
    for text in texts:
        if not text:
            continue
        links = list(_TECHNIQUE_URL_RE.finditer(text))
        matches = [(link.start(), link.group(1), link.group(2)) for link in links]
        matches.extend(
            (match.start(), match.group(1), match.group(2))
            for match in _TECHNIQUE_IN_TEXT_RE.finditer(text)
            if not any(link.start() <= match.start() < link.end() for link in links)
        )
        for _, technique, sub_technique in sorted(matches):
            mitre_id = technique.upper() + (
                f".{sub_technique}" if sub_technique else ""
            )
            if mitre_id not in found:
                found.append(mitre_id)
    return found


def attack_pattern_id(mitre_id: str) -> str:
    """Return the deterministic STIX id of the technique ``mitre_id``."""
    return AttackPattern.generate_id(name=mitre_id, x_mitre_id=mitre_id)


class AttackPatternResolver:
    """Decide which Attack Pattern objects a bundle must carry."""

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        self.helper = helper
        self._known: set[str] = set()

    def load(self, mitre_ids: Iterable[str]) -> None:
        """Fetch which of ``mitre_ids`` the platform already holds.

        Errors propagate: without the lookup the connector cannot tell an
        existing technique from a missing one, and guessing would either
        rename techniques or reference missing ones.
        """
        self._known = set()
        wanted = sorted({attack_pattern_id(mitre_id) for mitre_id in mitre_ids})
        for start in range(0, len(wanted), _LOOKUP_BATCH_SIZE):
            batch = wanted[start : start + _LOOKUP_BATCH_SIZE]
            entities = self.helper.api.attack_pattern.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "ids", "values": batch}],
                    "filterGroups": [],
                },
                first=len(batch) * 2,
                customAttributes="standard_id x_opencti_stix_ids",
            )
            requested = set(batch)
            for entity in entities or []:
                known_ids = {entity.get("standard_id")} | set(
                    entity.get("x_opencti_stix_ids") or []
                )
                self._known.update(known_ids & requested)

    def is_known(self, mitre_id: str) -> bool:
        """Tell whether the platform already holds ``mitre_id``."""
        return attack_pattern_id(mitre_id) in self._known

    def build(
        self,
        mitre_id: str,
        name: str | None,
        author_id: str,
        marking_id: str,
    ) -> stix2.AttackPattern | None:
        """Return the Attack Pattern to create, ``None`` when already held."""
        if self.is_known(mitre_id):
            return None
        return stix2.AttackPattern(
            id=attack_pattern_id(mitre_id),
            name=name or mitre_id,
            created_by_ref=author_id,
            object_marking_refs=[marking_id],
            custom_properties={"x_mitre_id": mitre_id},
        )
