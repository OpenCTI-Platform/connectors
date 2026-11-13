"""Resolve CrowdStrike ATT&CK labels to MITRE's own AttackPattern objects."""

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import stix2
from stix2.v21 import AttackPattern

MITRE_KILL_CHAIN = "mitre-attack"


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
