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
from typing import Literal

from crowdstrike_feeds_services.utils.json_retriever import (
    JsonRetrievalError,
    JsonRetriever,
)
from pydantic import BaseModel, ConfigDict, ValidationError

DEFAULT_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/"
    "enterprise-attack/enterprise-attack.json"
)


def normalize_mitre_id(mitre_id: str | None) -> str | None:
    """Return a MITRE ATT&CK external ID in its canonical form (e.g. "t1059.001" -> "T1059.001").

    Return None when there is no ID (None, empty or blank).
    """

    if not mitre_id:
        return None
    return mitre_id.strip().upper() or None


class AttackTechniqueLookupError(Exception):
    """Custom exception for ATT&CK lookup errors."""


class StixObjectEnvelope(BaseModel):
    """A STIX object, checked only for its `type`; the other fields are kept as they are."""

    model_config = ConfigDict(extra="allow")

    type: str


class StixBundleEnvelope(BaseModel):
    """The envelope of a STIX bundle: `{"type": "bundle", "objects": [...]}`.

    Only the envelope is checked; extra fields are allowed.
    """

    model_config = ConfigDict(extra="allow")

    type: Literal["bundle"]
    objects: list[StixObjectEnvelope]


@dataclass(frozen=True)
class AttackTechnique:
    """Represents a MITRE ATT&CK technique with its name and external ID."""

    name: str
    mitre_id: str  # external_id in its canonical form, e.g. "T1059"


class AttackTechniqueLookup:
    """In-memory lookup from normalized technique name -> MITRE technique external_id (T####)."""

    def __init__(self, retrieval_urls: list[str]):
        """Load the dataset from the first of `retrieval_urls` that provides it.

        Args:
            retrieval_urls: the URLs of the ATT&CK Enterprise dataset, in the order to try them.
        """
        self.retrievers = [JsonRetriever(url=url) for url in retrieval_urls]
        self.retrieval_errors: list[str] = []

        # Load attack_techniques on initialization
        # If it fails, the connector can choose to run in degraded mode without ATT&CK lookups.
        retrieved = self._retrieve_attack_json()
        if retrieved is None:
            raise AttackTechniqueLookupError(
                "Unable to retrieve the ATT&CK Enterprise dataset: "
                + "; ".join(self.retrieval_errors)
            )
        self.enterprise_attack_url, bundle = retrieved
        # Several techniques can share a name (sub-techniques such as "Cloud Accounts"
        # exist under several parents): the name lookup keeps the first one, the
        # external ID lookup keeps them all.
        self.attack_techniques: dict[str, AttackTechnique] = {}
        self.attack_techniques_by_mitre_id: dict[str, AttackTechnique] = {}
        for technique in self._parse_attack_bundle(bundle):
            self.attack_techniques.setdefault(
                self._normalize_technique_name(technique.name), technique
            )
            self.attack_techniques_by_mitre_id.setdefault(technique.mitre_id, technique)

    def lookup_technique_by_name(self, technique_name: str) -> AttackTechnique | None:
        """Return the MITRE technique (canonical name and external ID) for a technique name."""

        key = self._normalize_technique_name(technique_name)
        if not key:
            return None

        return self.attack_techniques.get(key)

    def lookup_technique_by_mitre_id(
        self, mitre_id: str | None
    ) -> AttackTechnique | None:
        """Return the MITRE technique (canonical name and external ID) for an external ID."""

        key = normalize_mitre_id(mitre_id)
        if not key:
            return None

        return self.attack_techniques_by_mitre_id.get(key)

    def _retrieve_attack_json(self) -> tuple[str, StixBundleEnvelope] | None:
        """Try the retrievers in order.

        Returns the URL and the STIX bundle of the first retriever that provides a valid one,
        or None if all of them fail (the failures are kept in `retrieval_errors`).
        """
        for retriever in self.retrievers:
            try:
                data = retriever.retrieve()
            except JsonRetrievalError as e:
                self.retrieval_errors.append(str(e))
                continue

            try:
                return retriever.url, StixBundleEnvelope.model_validate(data)
            except ValidationError as e:
                problems = "; ".join(
                    f"{'.'.join(map(str, error['loc'])) or 'payload'}: {error['msg']}"
                    for error in e.errors()
                )
                self.retrieval_errors.append(
                    f"Payload from {retriever.url} is not a STIX bundle: {problems}"
                )

        return None

    def _parse_attack_bundle(self, bundle: StixBundleEnvelope) -> list[AttackTechnique]:
        """Parse the techniques of a STIX bundle, leaving out the revoked ones.

        The MITRE ATT&CK connector does not import revoked objects either, so a revoked
        technique must not give its name to an Attack Pattern.
        """

        attack_techniques: list[AttackTechnique] = []
        for stix_object in bundle.objects:
            if stix_object.type != "attack-pattern":
                continue

            obj = stix_object.model_extra or {}
            if obj.get("revoked") is True:
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
                    mitre_id = normalize_mitre_id(external_id)
                    break

            if not mitre_id:
                continue

            attack_techniques.append(AttackTechnique(name=name, mitre_id=mitre_id))

        return attack_techniques

    @staticmethod
    def _normalize_technique_name(name: str) -> str:
        """Normalize a technique name for lookup.

        CrowdStrike ATT&CK labels already use canonical MITRE technique names,
        so normalization is intentionally minimal (trim + lowercase only).
        """
        if name:
            return str(name).strip().lower()

        return ""


class GithubAttackTechniqueLookup(AttackTechniqueLookup):
    """Lookup built from the MITRE ATT&CK Enterprise dataset published on GitHub.

    Tries the dataset of the given version first, then the generic one. "latest" (the
    default) and an empty version use the generic dataset, the latest release, which the
    MITRE ATT&CK connector imports by default.
    """

    def __init__(self, attack_version: str):
        self.attack_version = attack_version
        retrieval_urls = [DEFAULT_ATTACK_URL]
        if attack_version and attack_version.lower() != "latest":
            retrieval_urls.insert(0, self._build_versioned_attack_url(attack_version))
        super().__init__(retrieval_urls=retrieval_urls)

    @staticmethod
    def _build_versioned_attack_url(attack_version: str) -> str:
        """Build the raw GitHub URL of the Enterprise dataset of a given ATT&CK version.

        This connector uses the `mitre-attack/attack-stix-data` repository and the versioned
        Enterprise bundle filenames (e.g. `enterprise-attack-17.1.json`), to keep mappings
        deterministic.
        """
        return (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/"
            f"enterprise-attack/enterprise-attack-{attack_version}.json"
        )


class CustomAttackTechniqueLookup(AttackTechniqueLookup):
    """Lookup built from an ATT&CK Enterprise dataset at a custom URL (mirror, air-gapped host).

    Only the given URL is tried.
    """

    def __init__(self, enterprise_attack_url: str):
        super().__init__(retrieval_urls=[enterprise_attack_url])
