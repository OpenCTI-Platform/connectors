"""Attack Patterns referenced by the ATT&CK tags of Sigma rules.

Every rule Indicator gets an ``indicates`` relationship to the Attack
Pattern of each technique in its tags. The target id is
``pycti.AttackPattern.generate_id`` keyed on the MITRE id, which is the
standard id of the technique already imported from the MITRE ATT&CK
dataset. Sending an Attack Pattern named after its bare MITRE id would
rename that technique on upsert, so the platform is asked once per run
which techniques it already holds, and under which name.
"""

from collections.abc import Iterable

import stix2
from pycti import AttackPattern, OpenCTIConnectorHelper

# Ids per GraphQL ``ids`` filter: keeps each query small and bounded.
_LOOKUP_BATCH_SIZE = 100


def attack_pattern_id(mitre_id: str) -> str:
    """Return the deterministic STIX id of the technique ``mitre_id``."""
    return AttackPattern.generate_id(name=mitre_id, x_mitre_id=mitre_id)


class AttackPatternResolver:
    """Build the Attack Pattern objects the ``indicates`` edges point to.

    A technique known by the platform is sent under its current name and
    without author or marking, so the upsert changes nothing on it. A
    technique the platform does not hold yet is created under its MITRE
    id, attributed and marked like the rest of the bundle; the MITRE
    ATT&CK connector gives it its real name when it imports it.
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        self.helper = helper
        self._platform_names: dict[str, str] = {}

    def load(self, mitre_ids: Iterable[str]) -> None:
        """Fetch the platform name of every technique in ``mitre_ids``.

        Errors propagate: without the lookup the connector cannot tell an
        existing technique from a missing one, and guessing would either
        rename techniques or drop relationships.
        """
        self._platform_names = {}
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
                customAttributes="standard_id x_opencti_stix_ids name",
            )
            requested = set(batch)
            for entity in entities or []:
                known_ids = {entity.get("standard_id")} | set(
                    entity.get("x_opencti_stix_ids") or []
                )
                for stix_id in known_ids & requested:
                    self._platform_names[stix_id] = entity["name"]
        self.helper.connector_logger.info(
            "[CONNECTOR] Resolved ATT&CK techniques against the platform",
            {"techniques": len(wanted), "known": len(self._platform_names)},
        )

    def platform_name(self, mitre_id: str) -> str | None:
        """Return the platform name of ``mitre_id``, ``None`` when unknown."""
        return self._platform_names.get(attack_pattern_id(mitre_id))

    def build(
        self,
        mitre_id: str,
        author: stix2.Identity,
        marking: stix2.MarkingDefinition,
    ) -> stix2.AttackPattern:
        """Return the Attack Pattern object for ``mitre_id`` (uppercase)."""
        platform_name = self.platform_name(mitre_id)
        if platform_name is not None:
            return stix2.AttackPattern(
                id=attack_pattern_id(mitre_id),
                name=platform_name,
                custom_properties={"x_mitre_id": mitre_id},
            )
        return stix2.AttackPattern(
            id=attack_pattern_id(mitre_id),
            name=mitre_id,
            created_by_ref=author.id,
            object_marking_refs=[marking.id],
            custom_properties={"x_mitre_id": mitre_id},
        )
