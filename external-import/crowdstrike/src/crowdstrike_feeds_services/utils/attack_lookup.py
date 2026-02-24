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

from dataclasses import dataclass

import requests

DEFAULT_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/"
    "enterprise-attack/enterprise-attack.json"
)


class AttackTechniqueLookupError(Exception):
    """Custom exception for ATT&CK lookup errors."""


@dataclass(frozen=True)
class AttackTechnique:
    """Represents a MITRE ATT&CK technique with its name and external ID."""

    name: str
    mitre_id: str  # external_id, e.g. "T1059"


class AttackTechniqueLookup:
    """In-memory lookup from normalized technique name -> MITRE technique external_id (T####)."""

    def __init__(
        self,
        attack_version: str,
        enterprise_attack_url: str | None = None,
        timeout_seconds: int = 30,
    ):
        self.attack_version = attack_version
        self.enterprise_attack_url = (
            enterprise_attack_url or self._build_enterprise_attack_url()
        )
        self.timeout_seconds = timeout_seconds

        # Load attack_techniques on initialization
        # If it fails, the connector can choose to run in degraded mode without ATT&CK lookups.
        self.attack_techniques = self._load_enterprise_attack_techniques()

    def lookup_mitre_id(self, technique_name: str) -> str | None:
        """Return the MITRE technique ID (external_id) for a given technique name."""

        key = self._normalize_technique_name(technique_name)
        if not key:
            return None

        attack_technique = self.attack_techniques.get(key)
        return attack_technique.mitre_id if attack_technique else None

    def _build_enterprise_attack_url(self) -> str:
        """Build the raw GitHub URL for the MITRE ATT&CK Enterprise STIX dataset for a given version.

        This connector uses the `mitre-attack/attack-stix-data` repository and the versioned
        Enterprise bundle filenames (e.g. `enterprise-attack-17.1.json`).

        Notes:
        * We intentionally pin to a specific versioned dataset file to keep mappings deterministic.
        """
        return (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/"
            f"enterprise-attack/enterprise-attack-{self.attack_version}.json"
        )

    def _load_from_url(self, url: str) -> dict[str, AttackTechnique]:
        """Download the enterprise dataset and build the lookup.

        Caller should handle exceptions and decide whether to run in degraded mode.
        """
        response = requests.get(
            url,
            headers={"User-Agent": "opencti-crowdstrike-connector"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()

        return self._parse_attack_json(response.json())

    def _parse_attack_json(self, data: dict) -> dict[str, AttackTechnique]:
        """Parse techniques from STIX bundle."""

        attack_techniques: dict[str, AttackTechnique] = {}

        objects = data.get("objects") or []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "attack-pattern":
                continue

            name = obj.get("name")
            if not name:
                continue

            # Find the ATT&CK external ID (T####) from external_references.
            mitre_id = None
            ext_refs = obj.get("external_references") or []
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

            # Prefer the first key encountered; duplicates should be rare.
            key = self._normalize_technique_name(name)
            if key and key not in attack_techniques:
                attack_techniques[key] = AttackTechnique(name=name, mitre_id=mitre_id)

        return attack_techniques

    def _load_enterprise_attack_techniques(self) -> dict[str, AttackTechnique]:
        """Load the enterprise technique lookup using a configured version.

        Returns (resolved_url, lookup).
        """
        # If the user did not explicitly override the URL, attempt to load the versioned file first.
        if self.enterprise_attack_url == self._build_enterprise_attack_url():
            try:
                return self._load_from_url(url=self.enterprise_attack_url)
            except requests.RequestException as e:
                if e.response and e.response.status_code == 404:
                    # Versioned file not found; will attempt fallback to generic URL.
                    pass
                else:
                    raise AttackTechniqueLookupError(
                        f"Error while fetching ATT&CK data: {str(e)}"
                    ) from e

            # Fallback to the generic enterprise bundle if the versioned file does not exist.
            return self._load_from_url(url=DEFAULT_ATTACK_URL)

        # If the user explicitly overrides the URL, do not attempt fallbacks.
        return self._load_from_url(url=self.enterprise_attack_url)

    @staticmethod
    def _normalize_technique_name(name: str) -> str:
        """Normalize a technique name for lookup.

        CrowdStrike ATT&CK labels already use canonical MITRE technique names,
        so normalization is intentionally minimal (trim + lowercase only).
        """
        if name:
            return str(name).strip().lower()

        return ""
