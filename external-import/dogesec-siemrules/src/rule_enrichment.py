"""Rule metadata and ATT&CK links for the Sigma rules of SIEM Rules bundles.

SIEM Rules returns, per rule, a STIX bundle where the rule Indicator
(``pattern_type: sigma``) is linked to the MITRE ATT&CK objects with
``related-to`` relationships and carries its Sigma level and status as
``x_sigma_*`` properties. This module adds, on every Sigma rule Indicator:

- ``x_opencti_rule_status``, ``x_opencti_rule_level`` and
  ``x_opencti_rule_logsource`` read from the rule itself;
- one ``indicates`` relationship per ATT&CK technique or sub-technique tag
  (``attack.t1059``, ``attack.t1059.001``), targeting the Attack Pattern
  whose id is derived from the MITRE id.

The bundle is otherwise forwarded untouched.
"""

import json
import re
from collections.abc import Iterable
from typing import Any

import stix2
import yaml
from pycti import AttackPattern, OpenCTIConnectorHelper, StixCoreRelationship

_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_RULE_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
_RULE_LEVELS = {"informational", "low", "medium", "high", "critical"}
_LOGSOURCE_KEYS = ("category", "product", "service")

# Ids per GraphQL ``ids`` filter: keeps each query small and bounded.
_LOOKUP_BATCH_SIZE = 100


def attack_pattern_id(mitre_id: str) -> str:
    """Return the deterministic STIX id of the technique ``mitre_id``."""
    return AttackPattern.generate_id(name=mitre_id, x_mitre_id=mitre_id)


def parse_sigma_rule(pattern: str) -> dict[str, Any] | None:
    """Return the Sigma rule document of ``pattern``, ``None`` if not a mapping."""
    try:
        document = yaml.safe_load(pattern)
    except yaml.YAMLError:
        return None
    return document if isinstance(document, dict) else None


def technique_ids(sigma_rule: dict[str, Any]) -> list[str]:
    """Return the uppercase ATT&CK technique ids tagged on ``sigma_rule``."""
    ids: list[str] = []
    for tag in sigma_rule.get("tags") or []:
        match = _TECHNIQUE_TAG_RE.match(str(tag).strip())
        if match and match.group(1).upper() not in ids:
            ids.append(match.group(1).upper())
    return ids


def _first_in(vocabulary: set[str], *candidates: Any) -> str | None:
    """Return the first candidate that, lowercased, belongs to ``vocabulary``."""
    for candidate in candidates:
        value = str(candidate or "").strip().lower()
        if value in vocabulary:
            return value
    return None


def rule_metadata(
    sigma_rule: dict[str, Any], indicator: dict[str, Any]
) -> dict[str, Any]:
    """Return the ``x_opencti_rule_*`` properties of a Sigma rule Indicator.

    The rule document is authoritative; SIEM Rules' ``x_sigma_status`` /
    ``x_sigma_level`` fill in what the document does not state. Values out
    of the Sigma vocabularies are dropped.
    """
    metadata: dict[str, Any] = {}
    status = _first_in(
        _RULE_STATUSES, sigma_rule.get("status"), indicator.get("x_sigma_status")
    )
    if status:
        metadata["x_opencti_rule_status"] = status
    level = _first_in(
        _RULE_LEVELS, sigma_rule.get("level"), indicator.get("x_sigma_level")
    )
    if level:
        metadata["x_opencti_rule_level"] = level
    logsource = sigma_rule.get("logsource")
    if isinstance(logsource, dict):
        values = {
            key: str(logsource[key]).lower()
            for key in _LOGSOURCE_KEYS
            if logsource.get(key)
        }
        if values:
            metadata["x_opencti_rule_logsource"] = values
    return metadata


def mitre_technique_names(objects: Iterable[dict[str, Any]]) -> dict[str, str]:
    """Return the MITRE ATT&CK names of the Attack Patterns in a bundle."""
    names: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not obj.get("name"):
            continue
        for reference in obj.get("external_references") or []:
            source = str(reference.get("source_name", ""))
            external_id = str(reference.get("external_id", ""))
            if source.startswith("mitre-") and external_id.upper().startswith("T"):
                names[external_id.upper()] = obj["name"]
    return names


def _to_dict(stix_object: Any) -> dict[str, Any]:
    return json.loads(stix_object.serialize())


class RuleEnricher:
    """Add rule metadata and ATT&CK ``indicates`` links to SIEM Rules bundles.

    The platform is asked which techniques it already holds (cached for the
    run): those are referenced only, so the import never renames or
    re-attributes them; the others are created under their MITRE ATT&CK
    name when the bundle carries it, under their MITRE id otherwise. When
    the platform cannot be asked, a technique is only created when the
    bundle carries its MITRE ATT&CK name, and referenced otherwise.
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        self.helper = helper
        # Attack Pattern id -> held by the platform (``None``: lookup failed).
        self._known: dict[str, bool | None] = {}

    def reset(self) -> None:
        """Forget the platform lookups of the previous run."""
        self._known = {}

    def _resolve(self, mitre_ids: Iterable[str]) -> None:
        wanted = sorted(
            {attack_pattern_id(mitre_id) for mitre_id in mitre_ids} - set(self._known)
        )
        for start in range(0, len(wanted), _LOOKUP_BATCH_SIZE):
            batch = wanted[start : start + _LOOKUP_BATCH_SIZE]
            try:
                entities = self.helper.api.attack_pattern.list(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "ids", "values": batch}],
                        "filterGroups": [],
                    },
                    first=len(batch) * 2,
                    customAttributes="standard_id x_opencti_stix_ids",
                )
            except Exception as err:  # noqa: BLE001 - degraded mode, see class doc
                self.helper.connector_logger.warning(
                    "[SIEMRULES] Could not resolve ATT&CK techniques against the platform",
                    {"error": str(err)},
                )
                for stix_id in batch:
                    self._known[stix_id] = None
                continue
            found: set[str] = set()
            for entity in entities or []:
                found.add(entity.get("standard_id"))
                found.update(entity.get("x_opencti_stix_ids") or [])
            for stix_id in batch:
                self._known[stix_id] = stix_id in found

    def _must_create(self, target_id: str, name: str | None) -> bool:
        known = self._known.get(target_id)
        if known is None:
            return name is not None
        return not known

    def enrich(self, objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return ``objects`` with the rule metadata and ``indicates`` links."""
        rules: list[tuple[dict[str, Any], list[str]]] = []
        for obj in objects:
            if obj.get("type") != "indicator" or obj.get("pattern_type") != "sigma":
                continue
            sigma_rule = parse_sigma_rule(obj.get("pattern") or "")
            if sigma_rule is None:
                self.helper.connector_logger.warning(
                    "[SIEMRULES] Sigma rule pattern could not be parsed",
                    {"indicator_id": obj.get("id")},
                )
                continue
            obj.update(rule_metadata(sigma_rule, obj))
            rules.append((obj, technique_ids(sigma_rule)))

        self._resolve(mitre_id for _, ids in rules for mitre_id in ids)
        names = mitre_technique_names(objects)
        existing_ids = {obj.get("id") for obj in objects}
        added: list[dict[str, Any]] = []
        for indicator, ids in rules:
            for mitre_id in ids:
                target_id = attack_pattern_id(mitre_id)
                if target_id not in existing_ids and self._must_create(
                    target_id, names.get(mitre_id)
                ):
                    added.append(
                        _to_dict(
                            stix2.AttackPattern(
                                id=target_id,
                                name=names.get(mitre_id, mitre_id),
                                created_by_ref=indicator.get("created_by_ref"),
                                object_marking_refs=indicator.get(
                                    "object_marking_refs"
                                ),
                                custom_properties={"x_mitre_id": mitre_id},
                            )
                        )
                    )
                    existing_ids.add(target_id)
                relationship_id = StixCoreRelationship.generate_id(
                    "indicates", indicator["id"], target_id
                )
                if relationship_id in existing_ids:
                    continue
                added.append(
                    _to_dict(
                        stix2.Relationship(
                            id=relationship_id,
                            relationship_type="indicates",
                            source_ref=indicator["id"],
                            target_ref=target_id,
                            created_by_ref=indicator.get("created_by_ref"),
                            object_marking_refs=indicator.get("object_marking_refs"),
                        )
                    )
                )
                existing_ids.add(relationship_id)
        return objects + added
