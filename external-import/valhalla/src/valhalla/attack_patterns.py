"""Attack Patterns referenced by the ATT&CK tags of Valhalla YARA rules.

Every rule Indicator gets an ``indicates`` relationship to the Attack
Pattern of each technique in its tags. The target id is
``pycti.AttackPattern.generate_id`` keyed on the MITRE id, which is the
standard id of the technique already imported from the MITRE ATT&CK
dataset. The platform is asked once per run which techniques it already
holds: those are referenced only, so the import never renames or
re-attributes them; the others are created under their MITRE ATT&CK name.
"""

import re
from collections.abc import Iterable

import stix2
from pycti import AttackPattern, OpenCTIConnectorHelper

# ``T1059`` or ``T1059.001``; Valhalla tags are matched as a whole.
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

# Ids per GraphQL ``ids`` filter: keeps each query small and bounded.
_LOOKUP_BATCH_SIZE = 100


def technique_id(tag: str) -> str | None:
    """Return the uppercase technique id of ``tag``, ``None`` for other tags."""
    tag = (tag or "").strip()
    return tag.upper() if _TECHNIQUE_ID_RE.match(tag) else None


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
        existing technique from a missing one.
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
        self.helper.connector_logger.info(
            "Resolved ATT&CK techniques against the platform",
            {"techniques": len(wanted), "known": len(self._known)},
        )

    def is_known(self, mitre_id: str) -> bool:
        """Tell whether the platform already holds ``mitre_id``."""
        return attack_pattern_id(mitre_id) in self._known

    def build(
        self,
        mitre_id: str,
        name: str | None,
        author: stix2.Identity,
        marking: stix2.MarkingDefinition,
    ) -> stix2.AttackPattern | None:
        """Return the Attack Pattern to create, ``None`` when already held.

        ``name`` is the MITRE ATT&CK name of the technique when known; the
        technique is otherwise created under its MITRE id, and the MITRE
        ATT&CK connector gives it its real name when it imports it.
        """
        if self.is_known(mitre_id):
            return None
        return stix2.AttackPattern(
            id=attack_pattern_id(mitre_id),
            name=name or mitre_id,
            created_by_ref=author.id,
            object_marking_refs=[marking.id],
            custom_properties={"x_mitre_id": mitre_id},
        )
