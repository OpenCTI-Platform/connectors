"""Detect intrusion-set merge/split candidates by comparing alias ownership."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set


def normalize_identifier(value: str) -> str:
    return (value or "").strip().casefold()


def identifiers_from_api_item(item: Dict[str, Any]) -> FrozenSet[str]:
    out: Set[str] = set()
    name = item.get("name")
    if name:
        out.add(normalize_identifier(str(name)))
    for alias in item.get("aliases") or []:
        if alias:
            out.add(normalize_identifier(str(alias)))
    return frozenset(out)


def identifiers_from_opencti(entity: Dict[str, Any]) -> FrozenSet[str]:
    out: Set[str] = set()
    name = entity.get("name")
    if name:
        out.add(normalize_identifier(str(name)))
    for alias in entity.get("aliases") or []:
        if alias:
            out.add(normalize_identifier(str(alias)))
    return frozenset(out)


def build_identifier_index(
    items: Iterable[Dict[str, Any]],
    *,
    sid_key: str = "standard_id",
    from_opencti: bool = False,
) -> Dict[str, Set[str]]:
    """Map normalized name/alias -> set of standard_ids that claim it."""
    index: Dict[str, Set[str]] = {}
    id_fn = identifiers_from_opencti if from_opencti else identifiers_from_api_item
    for item in items:
        sid = item.get(sid_key)
        if not sid:
            continue
        for ident in id_fn(item):
            index.setdefault(ident, set()).add(sid)
    return index


@dataclass
class SplitCandidate:
    """OpenCTI intrusion set spans aliases owned by multiple upstream objects."""

    opencti_entity: Dict[str, Any]
    keep_api_item: Optional[Dict[str, Any]]
    aliases_to_remove: List[str]
    split_off_api_items: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class MergeCandidate:
    """Multiple OpenCTI intrusion sets should fuse into one upstream survivor."""

    target_api_item: Dict[str, Any]
    opencti_entities_to_merge: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class MergeSplitPlan:
    splits: List[SplitCandidate] = field(default_factory=list)
    merges: List[MergeCandidate] = field(default_factory=list)


def analyze_intrusion_set_merge_split(
    api_items: List[Dict[str, Any]],
    opencti_entities: List[Dict[str, Any]],
) -> MergeSplitPlan:
    """Compare catalogue vs OpenCTI and classify split/merge/normal paths."""
    plan = MergeSplitPlan()
    api_by_sid: Dict[str, Dict[str, Any]] = {}
    for item in api_items:
        sid = item.get("standard_id")
        if sid:
            api_by_sid[sid] = item

    opencti_by_sid: Dict[str, Dict[str, Any]] = {
        e["standard_id"]: e for e in opencti_entities if e.get("standard_id")
    }

    api_index = build_identifier_index(api_items)
    oc_index = build_identifier_index(opencti_entities, from_opencti=True)

    split_seen: Set[str] = set()
    merge_seen: Set[tuple] = set()

    for oc in opencti_entities:
        oc_sid = oc.get("standard_id")
        if not oc_sid:
            continue
        oc_ids = identifiers_from_opencti(oc)
        if not oc_ids:
            continue

        primary_api = api_by_sid.get(oc_sid)
        primary_ids = (
            identifiers_from_api_item(primary_api) if primary_api else frozenset()
        )

        conflicting_aliases: Set[str] = set()
        split_off_sids: Set[str] = set()

        for ident in oc_ids:
            api_owners = api_index.get(ident, set())
            if not api_owners:
                continue
            if oc_sid in api_owners and len(api_owners) == 1:
                continue
            other_owners = api_owners - {oc_sid}
            if other_owners:
                if ident not in primary_ids:
                    raw = _raw_alias_value(oc, ident)
                    if raw:
                        conflicting_aliases.add(raw)
                for owner_sid in other_owners:
                    split_off_sids.add(owner_sid)

        if not conflicting_aliases and not split_off_sids:
            continue
        if oc_sid in split_seen:
            continue

        split_off_items = [
            api_by_sid[s]
            for s in sorted(split_off_sids)
            if s in api_by_sid and s != oc_sid
        ]
        if not conflicting_aliases and not split_off_items:
            continue

        plan.splits.append(
            SplitCandidate(
                opencti_entity=oc,
                keep_api_item=primary_api,
                aliases_to_remove=sorted(conflicting_aliases),
                split_off_api_items=split_off_items,
            )
        )
        split_seen.add(oc_sid)

    for api_sid, api_item in api_by_sid.items():
        api_ids = identifiers_from_api_item(api_item)
        if not api_ids:
            continue

        oc_duplicates: Dict[str, Dict[str, Any]] = {}
        for ident in api_ids:
            for oc_sid in oc_index.get(ident, set()):
                if oc_sid == api_sid:
                    continue
                entity = opencti_by_sid.get(oc_sid)
                if entity:
                    oc_duplicates[oc_sid] = entity

        if not oc_duplicates:
            continue

        merge_key = (api_sid, tuple(sorted(oc_duplicates)))
        if merge_key in merge_seen:
            continue
        merge_seen.add(merge_key)

        plan.merges.append(
            MergeCandidate(
                target_api_item=api_item,
                opencti_entities_to_merge=list(oc_duplicates.values()),
            )
        )

    return plan


def _raw_alias_value(entity: Dict[str, Any], normalized_ident: str) -> Optional[str]:
    name = entity.get("name")
    if name and normalize_identifier(str(name)) == normalized_ident:
        return str(name)
    for alias in entity.get("aliases") or []:
        if alias and normalize_identifier(str(alias)) == normalized_ident:
            return str(alias)
    return None


def opencti_alias_count(entity: Dict[str, Any]) -> int:
    """Count aliases on an OpenCTI intrusion set (name is not counted)."""
    return len([a for a in (entity.get("aliases") or []) if a])


def pick_opencti_merge_survivor(
    api_standard_id: str,
    candidates: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Choose the OpenCTI entity that should survive a fusion merge.
    """
    unique: Dict[str, Dict[str, Any]] = {}
    for entity in candidates:
        sid = entity.get("standard_id")
        if sid:
            unique[sid] = entity
    if not unique:
        return None

    def sort_key(entity: Dict[str, Any]) -> tuple:
        sid = entity.get("standard_id") or ""
        return (
            opencti_alias_count(entity),
            1 if sid == api_standard_id else 0,
            len(identifiers_from_opencti(entity)),
            sid,
        )

    return max(unique.values(), key=sort_key)
