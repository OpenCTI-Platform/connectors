"""ATT&CK Enterprise technique lookup.

This module loads the MITRE ATT&CK Enterprise STIX dataset once (typically at connector startup)
and provides fast lookups from technique name -> MITRE external ID (e.g., "T1059").

We use this to ensure Attack Pattern objects created from CrowdStrike labels can be assigned
the same deterministic IDs as the MITRE ATT&CK external import connector (source of truth).

Design goals:
- Enterprise-only (per connector scope)
- No network calls during label parsing; load once and pass the lookup around
- Minimal normalization (trim + lowercase); CrowdStrike labels are treated as canonical
- Degraded mode: if dataset can't be loaded, caller can decide to skip creating attack patterns
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple
from urllib.error import HTTPError


def build_enterprise_attack_url(attack_version: str) -> str:
    """Build the raw GitHub URL for the MITRE ATT&CK Enterprise STIX dataset for a given version.

    This connector uses the `mitre-attack/attack-stix-data` repository and the versioned
    Enterprise bundle filenames (e.g. `enterprise-attack-17.1.json`).

    Expected inputs:
      - "v17.1" -> https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack-17.1.json
      - "17.1"  -> same

    Notes:
      * We intentionally pin to a specific versioned dataset file to keep mappings deterministic.
    """
    v = (attack_version or "").strip()
    if not v:
        raise ValueError("attack_version must be a non-empty string")

    # Accept versions like "v17.1" or "17.1".
    if v.lower().startswith("v"):
        v = v[1:]

    return (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/"
        f"enterprise-attack/enterprise-attack-{v}.json"
    )


def normalize_technique_name(name: str) -> str:
    """Normalize a technique name for lookup.

    CrowdStrike ATT&CK labels already use canonical MITRE technique names,
    so normalization is intentionally minimal (trim + lowercase only).
    """

    if not name:
        return ""
    return str(name).strip().lower()


@dataclass(frozen=True)
class AttackTechnique:
    name: str
    mitre_id: str  # external_id, e.g. "T1059"


class AttackTechniqueLookup:
    """In-memory lookup from normalized technique name -> MITRE technique external_id (T####)."""

    def __init__(self, by_name: Dict[str, AttackTechnique], source: str):
        self._by_name = by_name
        self.source = source

    @property
    def technique_count(self) -> int:
        return len(self._by_name)

    def lookup_mitre_id(self, technique_name: str) -> Optional[str]:
        """Return the MITRE technique ID (external_id) for a given technique name."""

        key = normalize_technique_name(technique_name)
        if not key:
            return None
        t = self._by_name.get(key)
        return t.mitre_id if t else None

    def lookup(self, technique_name: str) -> Optional[AttackTechnique]:
        key = normalize_technique_name(technique_name)
        if not key:
            return None
        return self._by_name.get(key)

    @staticmethod
    def _extract_techniques(objects: Iterable[dict]) -> Dict[str, AttackTechnique]:
        """Extract techniques from STIX bundle objects."""

        by_name: Dict[str, AttackTechnique] = {}

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "attack-pattern":
                continue

            name = obj.get("name")
            if not name:
                continue

            # Find the ATT&CK external ID (T####) from external_references.
            ext_refs = obj.get("external_references") or []
            mitre_id: Optional[str] = None
            for ref in ext_refs:
                if not isinstance(ref, dict):
                    continue
                # MITRE usually provides source_name "mitre-attack".
                # We primarily care about external_id like "T1059".
                external_id = ref.get("external_id")
                if (
                    external_id
                    and isinstance(external_id, str)
                    and external_id.upper().startswith("T")
                ):
                    mitre_id = external_id.strip()
                    break

            if not mitre_id:
                continue

            key = normalize_technique_name(str(name))
            if not key:
                continue

            # Prefer the first one encountered; duplicates should be rare.
            if key not in by_name:
                by_name[key] = AttackTechnique(name=str(name), mitre_id=mitre_id)

        return by_name

    @classmethod
    def from_stix_json(cls, stix: dict, source: str) -> "AttackTechniqueLookup":
        objects = stix.get("objects") or []
        by_name = cls._extract_techniques(objects)
        return cls(by_name=by_name, source=source)

    @classmethod
    def load_from_url(
        cls,
        url: str,
        timeout_seconds: int = 30,
        user_agent: str = "opencti-crowdstrike-connector",
    ) -> "AttackTechniqueLookup":
        """Download the enterprise dataset and build the lookup.

        Caller should handle exceptions and decide whether to run in degraded mode.
        """

        req = urllib.request.Request(
            url,
            headers={"User-Agent": user_agent},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            raw = resp.read()

        stix = json.loads(raw.decode("utf-8"))
        return cls.from_stix_json(stix, source=url)

    @classmethod
    def load_enterprise(
        cls,
        attack_version: str,
        url_override: Optional[str] = None,
        timeout_seconds: int = 30,
    ) -> Tuple[str, "AttackTechniqueLookup"]:
        """Load the enterprise technique lookup using a configured version.

        Returns (resolved_url, lookup).
        """

        MASTER_URL = (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/"
            "enterprise-attack/enterprise-attack.json"
        )

        url = (url_override or "").strip() or build_enterprise_attack_url(
            attack_version
        )
        # If the user explicitly overrides the URL, do not attempt fallbacks.
        if (url_override or "").strip():
            lookup = cls.load_from_url(url=url, timeout_seconds=timeout_seconds)
            return url, lookup

        try:
            lookup = cls.load_from_url(url=url, timeout_seconds=timeout_seconds)
            return url, lookup
        except HTTPError as e:
            if e.code != 404:
                raise

        # Fallback to the generic enterprise bundle if the versioned file does not exist.
        lookup = cls.load_from_url(url=MASTER_URL, timeout_seconds=timeout_seconds)
        return MASTER_URL, lookup
