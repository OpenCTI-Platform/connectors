"""Resolve CrowdStrike ATT&CK labels to MITRE's own AttackPattern objects."""

import dataclasses
import json
import logging
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import stix2
from crowdstrike_indicators.entities.ids import indicates_id
from crowdstrike_indicators.entities.stix import CrowdStrikeIndicatorBundle
from crowdstrike_indicators.transform.step02_add_malware import crowdstrike_id
from stix2.exceptions import STIXError
from stix2.v21 import AttackPattern, Relationship

from shared.errors import ItemConversionError
from shared.transformer import AbstractTransformer

LOGGER = logging.getLogger(__name__)

MITRE_KILL_CHAIN = "mitre-attack"
MITRE_SOURCE_NAME = "mitre-attack"
ATTACK_LABEL_PREFIX = "MitreATTCK"


def match_key(text: str) -> str:
    """Return the letters and digits of ``text``, lowercased.

    ``PowerShell``, ``Power Shell`` and ``powershell`` share one key, and so
    do ``RegistryRunKeysStartupFolder`` and
    ``Registry Run Keys / Startup Folder``.
    """
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _is_live(obj: Mapping[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


class AttackPatternCatalog:
    """The live techniques of a MITRE ATT&CK Enterprise STIX bundle.

    Built once from data already in memory or from a local file; it never
    downloads anything. Revoked and deprecated AttackPatterns are left out.
    The objects are MITRE's, parsed with stix2 and otherwise unchanged.
    """

    def __init__(self, bundle: Mapping[str, Any]) -> None:
        """Index the live AttackPatterns of ``bundle``.

        :raises ValueError: if ``bundle`` is not a STIX bundle.
        """
        if not isinstance(bundle, Mapping) or bundle.get("type") != "bundle":
            raise ValueError("not a STIX bundle: expected an object of type 'bundle'")
        objects = bundle.get("objects")
        if not isinstance(objects, list):
            raise ValueError("not a STIX bundle: 'objects' is not a list")
        self._by_name: dict[str, list[AttackPattern]] = {}
        for obj in objects:
            if (
                isinstance(obj, Mapping)
                and obj.get("type") == "attack-pattern"
                and _is_live(obj)
            ):
                pattern = stix2.parse(dict(obj), allow_custom=True)
                self._by_name.setdefault(match_key(pattern.name), []).append(pattern)

    @classmethod
    def from_file(cls, path: Path) -> "AttackPatternCatalog":
        """Load the catalog from a local STIX bundle file.

        :raises ValueError: if the file is not a JSON STIX bundle; the message
            names the file.
        """
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            return cls(data)
        except ValueError as error:
            raise ValueError(f"{path}: {error}") from error

    def __len__(self) -> int:
        return sum(len(patterns) for patterns in self._by_name.values())

    def resolve(self, tactic: str, technique: str) -> AttackPattern | None:
        """Return the one live AttackPattern a CrowdStrike label names, if any.

        ``technique`` is matched on letters and digits. When several
        techniques share that name, ``tactic`` keeps those having a
        ``mitre-attack`` kill chain phase of the same name. The result is the
        single remaining technique, or ``None`` when none or several remain.
        """
        candidates = self._by_name.get(match_key(technique), [])
        if len(candidates) > 1:
            tactic_key = match_key(tactic)
            candidates = [
                pattern
                for pattern in candidates
                if any(
                    phase.kill_chain_name == MITRE_KILL_CHAIN
                    and match_key(phase.phase_name) == tactic_key
                    for phase in pattern.get("kill_chain_phases", [])
                )
            ]
        return candidates[0] if len(candidates) == 1 else None


def light_attack_pattern(pattern: AttackPattern) -> AttackPattern:
    """Return a light copy of a MITRE AttackPattern.

    It keeps MITRE's ``id``, dates and ``name``, and in
    ``external_references`` only the ``mitre-attack`` reference (T-id and
    link). Everything else is left out: ``description``,
    ``kill_chain_phases``, ``x_mitre_*`` properties, other references, and
    ``created_by_ref`` and ``object_marking_refs``, whose targets (MITRE's
    identity and marking) are not in the bundle.
    """
    references = [
        dict(reference)
        for reference in pattern.get("external_references", [])
        if reference.get("source_name") == MITRE_SOURCE_NAME
    ]
    optional = {"external_references": references} if references else {}
    return AttackPattern(
        id=pattern.id,
        created=pattern.created,
        modified=pattern.modified,
        name=pattern.name,
        **optional,
    )


class CrowdStrikeAddAttackPatterns(
    AbstractTransformer[CrowdStrikeIndicatorBundle, CrowdStrikeIndicatorBundle]
):
    """Add the MITRE AttackPatterns an indicator's ATT&CK labels name.

    Each label ``MitreATTCK/<tactic>/<technique>`` is resolved with the
    catalog. Every distinct technique found adds a light copy of MITRE's
    AttackPattern (see :func:`light_attack_pattern`), shared by every bundle,
    and an ``indicates`` relationship from the indicator, dated like the
    indicator. Unresolved labels add nothing and stay on the
    indicator. Objects already in the bundle are kept. No network call is
    made: the catalog is loaded beforehand.
    """

    def __init__(self, catalog: AttackPatternCatalog) -> None:
        self.catalog = catalog
        self._light: dict[str, AttackPattern] = {}

    def _light_copy(self, pattern: AttackPattern) -> AttackPattern:
        if pattern.id not in self._light:
            self._light[pattern.id] = light_attack_pattern(pattern)
        return self._light[pattern.id]

    def _resolve_labels(
        self, bundle: CrowdStrikeIndicatorBundle
    ) -> list[AttackPattern]:
        found: dict[str, AttackPattern] = {}
        for label in bundle.indicator.get("labels", []):
            parts = label.split("/")
            if len(parts) != 3 or parts[0] != ATTACK_LABEL_PREFIX:
                continue
            pattern = self.catalog.resolve(parts[1], parts[2])
            if pattern is None:
                LOGGER.debug(
                    "Indicator %s: no single ATT&CK technique for %r",
                    crowdstrike_id(bundle.indicator),
                    label,
                )
                continue
            found.setdefault(pattern.id, self._light_copy(pattern))
        return list(found.values())

    def convert(self, item: CrowdStrikeIndicatorBundle) -> CrowdStrikeIndicatorBundle:
        """Return ``item`` with its AttackPatterns and their relationships added.

        :raises ItemConversionError: if stix2 rejects a relationship.
        """
        indicator = item.indicator
        known = {pattern.id for pattern in item.attack_patterns}
        patterns = [p for p in self._resolve_labels(item) if p.id not in known]
        try:
            relationships = [
                Relationship(
                    id=indicates_id(indicator.id, pattern.id),
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=pattern.id,
                    created=indicator.created,
                    modified=indicator.modified,
                )
                for pattern in patterns
            ]
        except STIXError as error:
            raise ItemConversionError(crowdstrike_id(indicator), str(error)) from error
        return dataclasses.replace(
            item,
            attack_patterns=[*item.attack_patterns, *patterns],
            relationships=[*item.relationships, *relationships],
        )
