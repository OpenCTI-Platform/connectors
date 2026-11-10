"""Turn PolySwarm TAXII pages into STIX 2.1 objects ready to send to OpenCTI.

Each item of a PolySwarm TAXII page is itself a STIX bundle describing one
sample (malware family and variant, file, hash indicators, one
malware-analysis per engine, relationships, and ATT&CK attack-patterns in
some feeds). `FeedConverter` flattens those per-sample bundles into a single
list of STIX objects (plain dicts), keeping PolySwarm's object ids, and:

    - sets `created_by_ref` to the PolySwarm author and
      `object_marking_refs` to the configured TLP marking on every object;
    - sets each indicator's `valid_until` to import time plus the configured
      number of days, never earlier than its `valid_from`;
    - gives indicators that share one id inside a sample (the feed serves the
      MD5, SHA-1 and SHA-256 indicators of a sample under the same id) their
      own deterministic id, and rewires relationships to them;
    - drops references to objects that are not part of the sample;
    - drops objects already converted earlier in the run (by id);
    - skips and logs malformed items instead of failing the whole page.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from itertools import product
from typing import Any

from pycti import Indicator, StixCoreRelationship

# Reference properties that are handled separately and never filtered.
_UNTOUCHED_REF_PROPERTIES = {"created_by_ref", "object_marking_refs"}
_ANALYSIS_RELATIONSHIP_TYPES = {"av-analysis-of", "dynamic-analysis-of"}


class MalformedItemError(ValueError):
    """A TAXII page item cannot be converted."""


def _format_timestamp(value: datetime) -> str:
    """Format a datetime as a STIX timestamp (UTC, microseconds, `Z` suffix)."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a STIX timestamp, or return None when it cannot be parsed."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _is_stix_object(obj: Any) -> bool:
    """Whether `obj` looks like a STIX object we can import."""
    if not isinstance(obj, dict):
        return False
    obj_type = obj.get("type")
    obj_id = obj.get("id")
    return (
        isinstance(obj_type, str)
        and obj_type != "bundle"
        and isinstance(obj_id, str)
        and obj_id.startswith(f"{obj_type}--")
    )


def _iter_refs(obj: dict[str, Any]):
    """Yield every id referenced by a STIX object, except author and markings."""
    for key, value in obj.items():
        if key in _UNTOUCHED_REF_PROPERTIES:
            continue
        if key.endswith("_ref") and isinstance(value, str):
            yield value
        elif key.endswith("_refs") and isinstance(value, list):
            yield from (ref for ref in value if isinstance(ref, str))


class FeedConverter:
    """Convert PolySwarm TAXII pages to STIX objects for one connector run.

    A new converter must be created for each run: it remembers the objects
    already converted during the run to drop duplicates.
    """

    def __init__(
        self,
        author: dict[str, Any],
        tlp_marking: dict[str, Any],
        indicator_valid_days: int,
        logger: Any,
        now: datetime | None = None,
    ) -> None:
        """Initialize the converter.

        Args:
            author: The PolySwarm organization identity, as a STIX dict.
            tlp_marking: The TLP marking definition, as a STIX dict.
            indicator_valid_days: Indicators are valid until `now` plus this.
            logger: The connector logger.
            now: Import time (defaults to the current UTC time).
        """
        self._author_id = author["id"]
        self._marking_id = tlp_marking["id"]
        self._valid_days = timedelta(days=indicator_valid_days)
        self._logger = logger
        self._now = now or datetime.now(tz=timezone.utc)
        self._seen: dict[str, dict[str, Any]] = {}
        self.skipped_items = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def convert_page(self, items: list[Any]) -> list[dict[str, Any]]:
        """Convert the items of one TAXII page.

        Args:
            items: The `objects` list of a TAXII page (one bundle per sample).

        Returns:
            The STIX objects to send for this page: objects not sent earlier in
            the run, plus copies of earlier objects they reference so that the
            page's bundle stays self-contained.
        """
        page_objects: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(items):
            try:
                sample_objects = self.convert_item(item)
            except MalformedItemError as err:
                self.skipped_items += 1
                self._logger.warning(
                    "Skipping malformed PolySwarm feed item",
                    {"item_index": index, "error": str(err)},
                )
                continue
            for obj in sample_objects:
                page_objects.setdefault(obj["id"], obj)

        new_objects = [
            obj for obj_id, obj in page_objects.items() if obj_id not in self._seen
        ]
        new_ids = {obj["id"] for obj in new_objects}

        carried: dict[str, dict[str, Any]] = {}
        for obj in new_objects:
            for ref in _iter_refs(obj):
                if ref not in new_ids and ref in self._seen:
                    carried.setdefault(ref, self._seen[ref])

        for obj in new_objects:
            self._seen[obj["id"]] = obj
        return new_objects + list(carried.values())

    def convert_item(self, item: Any) -> list[dict[str, Any]]:
        """Flatten one page item (a per-sample bundle) into STIX objects.

        Raises:
            MalformedItemError: When the item is not a bundle or STIX object.
        """
        raw_objects = self._extract_objects(item)

        groups: dict[str, list[dict[str, Any]]] = {}
        invalid = 0
        for obj in raw_objects:
            if not _is_stix_object(obj):
                invalid += 1
                continue
            groups.setdefault(obj["id"], []).append(obj)
        if invalid:
            self._logger.debug(
                "Skipped invalid objects in PolySwarm feed item",
                {"invalid_objects": invalid},
            )

        objects: dict[str, dict[str, Any]] = {}
        remapped: dict[str, list[str]] = {}
        for obj_id, group in groups.items():
            if len(group) > 1 and all(self._is_pattern_indicator(o) for o in group):
                remapped[obj_id] = []
                for indicator in group:
                    new_id = Indicator.generate_id(indicator["pattern"])
                    if new_id not in objects:
                        objects[new_id] = {**copy.deepcopy(indicator), "id": new_id}
                    if new_id not in remapped[obj_id]:
                        remapped[obj_id].append(new_id)
            else:
                objects[obj_id] = copy.deepcopy(group[0])

        result: dict[str, dict[str, Any]] = {}
        for obj in objects.values():
            if obj["type"] == "relationship":
                resolved = self._resolve_relationship(obj, objects, remapped)
            else:
                resolved = [self._resolve_refs(obj, objects, remapped)]
            for item in resolved:
                result.setdefault(item["id"], item)

        self._fit_analyses(result)
        return [self._decorate(obj) for obj in result.values()]

    def _fit_analyses(self, objects: dict[str, dict[str, Any]]) -> None:
        """Shape the sample's analyses and relationships the way OpenCTI stores them.

        OpenCTI links a malware analysis to its sample through `sample_ref`, not
        through relationships, and refuses the feed's `av-analysis-of` and
        `dynamic-analysis-of` relationships. It also needs `result_name`, and it
        merges analyses with the same product, result name and submission date,
        so each analysis gets its own `submitted` date to stay per sample. A
        `variant-of` between two malware objects with the same name would become
        a relationship from an object to itself once OpenCTI merges them, which
        it refuses, so those are dropped.
        """
        default_sample = next(
            (
                obj["sample_refs"][0]
                for obj in objects.values()
                if obj["type"] == "malware" and obj.get("sample_refs")
            ),
            None,
        )
        for obj_id, obj in list(objects.items()):
            if obj["type"] != "relationship":
                continue
            relationship_type = obj.get("relationship_type")
            source = objects.get(obj.get("source_ref"), {})
            target = objects.get(obj.get("target_ref"), {})
            if relationship_type in _ANALYSIS_RELATIONSHIP_TYPES:
                # Some feeds point the sandbox analysis at the family, which
                # has no sample, so fall back to the sample's file.
                samples = target.get("sample_refs") or [default_sample]
                if source.get("type") == "malware-analysis" and samples[0]:
                    source.setdefault("sample_ref", samples[0])
                del objects[obj_id]
            elif relationship_type == "variant-of":
                source_name = str(source.get("name", "")).strip().lower()
                target_name = str(target.get("name", "")).strip().lower()
                if source_name and source_name == target_name:
                    del objects[obj_id]

        for obj in objects.values():
            if obj["type"] != "malware-analysis":
                continue
            if not obj.get("result_name"):
                obj["result_name"] = obj.get("result") or "no result"
            if not obj.get("submitted") and obj.get("created"):
                obj["submitted"] = obj["created"]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_objects(item: Any) -> list[Any]:
        """Return the STIX objects carried by a page item."""
        if not isinstance(item, dict):
            raise MalformedItemError(f"item is a {type(item).__name__}, not an object")
        if item.get("type") == "bundle":
            objects = item.get("objects", [])
            if not isinstance(objects, list):
                raise MalformedItemError("bundle 'objects' is not a list")
            return objects
        if _is_stix_object(item):
            return [item]
        raise MalformedItemError("item is neither a STIX bundle nor a STIX object")

    @staticmethod
    def _is_pattern_indicator(obj: dict[str, Any]) -> bool:
        return obj["type"] == "indicator" and isinstance(obj.get("pattern"), str)

    @staticmethod
    def _resolve(
        ref: Any, objects: dict[str, Any], remapped: dict[str, list[str]]
    ) -> list[str]:
        """Ids a reference points to inside the sample (empty when dangling)."""
        if not isinstance(ref, str):
            return []
        if ref in remapped:
            return remapped[ref]
        return [ref] if ref in objects else []

    def _resolve_relationship(
        self,
        relationship: dict[str, Any],
        objects: dict[str, Any],
        remapped: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        """Keep, rewire or drop a relationship depending on its endpoints."""
        source_ref = relationship.get("source_ref")
        target_ref = relationship.get("target_ref")
        sources = self._resolve(source_ref, objects, remapped)
        targets = self._resolve(target_ref, objects, remapped)
        if not sources or not targets:
            self._logger.debug(
                "Dropping relationship with an endpoint outside the sample",
                {"relationship_id": relationship["id"]},
            )
            return []
        if source_ref not in remapped and target_ref not in remapped:
            return [relationship]

        rewired = []
        for source, target in product(sources, targets):
            rewired.append(
                {
                    **relationship,
                    "id": StixCoreRelationship.generate_id(
                        relationship.get("relationship_type"), source, target
                    ),
                    "source_ref": source,
                    "target_ref": target,
                }
            )
        return rewired

    def _resolve_refs(
        self,
        obj: dict[str, Any],
        objects: dict[str, Any],
        remapped: dict[str, list[str]],
    ) -> dict[str, Any]:
        """Rewrite or drop `*_ref`/`*_refs` properties pointing outside the sample."""
        for key in list(obj.keys()):
            if key in _UNTOUCHED_REF_PROPERTIES:
                continue
            value = obj[key]
            if key.endswith("_refs") and isinstance(value, list):
                resolved: list[str] = []
                dropped = 0
                for ref in value:
                    targets = self._resolve(ref, objects, remapped)
                    if not targets:
                        dropped += 1
                    for target in targets:
                        if target not in resolved:
                            resolved.append(target)
                if dropped:
                    self._logger.debug(
                        "Dropped references to objects outside the sample",
                        {"object_id": obj["id"], "property": key, "dropped": dropped},
                    )
                if resolved:
                    obj[key] = resolved
                else:
                    del obj[key]
            elif key.endswith("_ref") and isinstance(value, str):
                targets = self._resolve(value, objects, remapped)
                if targets:
                    obj[key] = targets[0]
                else:
                    del obj[key]
        return obj

    def _decorate(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Set author, marking and, for indicators, `valid_until`."""
        obj["created_by_ref"] = self._author_id
        obj["object_marking_refs"] = [self._marking_id]
        if obj["type"] == "indicator":
            obj["valid_until"] = self._valid_until(obj.get("valid_from"))
            pattern = obj.get("pattern")
            if isinstance(pattern, str) and pattern.startswith("[file:"):
                obj.setdefault("x_opencti_main_observable_type", "StixFile")
        return obj

    def _valid_until(self, valid_from: Any) -> str:
        """Import time plus the validity period, never before `valid_from`."""
        valid_until = self._now + self._valid_days
        start = _parse_timestamp(valid_from)
        if start is not None and valid_until <= start:
            valid_until = start + self._valid_days
        return _format_timestamp(valid_until)
