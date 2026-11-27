import json
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import requests
from connector.confidence import (
    confidence_value,
    make_sync_record,
    upstream_confidence_from_record,
)
from connector.converter_to_stix import ConverterToStix
from connector.merge_split import (
    MergeCandidate,
    SplitCandidate,
    analyze_merge_split,
    pick_opencti_merge_survivor,
)
from connector.settings import ConnectorSettings
from connector.utils import ThreatObjectType
from pycti import OpenCTIConnectorHelper
from rst_threat_library_client import ThreatLibraryClient

_OPENCTI_MERGE_SOURCE_BATCH = 3
_SPLIT_FAILURE_SKIP_THRESHOLD = 3
_SPLIT_FAILURES_STATE_KEY = "split_failures"
_MERGE_SURVIVOR_READ_ATTEMPTS = 8
_MERGE_SURVIVOR_READ_DELAY_S = 2.0
_OPENCTI_RETRY_MIN_DELAY_S = 1
_MERGE_SPLIT_CATALOGUE_WARN = 10_000
_MERGE_SPLIT_TYPES = frozenset(
    {
        ThreatObjectType.INTRUSION_SETS,
        ThreatObjectType.MALWARE,
        ThreatObjectType.TOOLS,
        ThreatObjectType.CAMPAIGNS,
    }
)


@dataclass
class UpsertPrep:
    skip: bool
    api_item: Dict[str, Any]
    opencti_entity: Optional[Dict[str, Any]] = None
    skip_reason: str = ""
    # When True, skip is due to a transient/error condition (e.g. OpenCTI read
    # failure). Cursor must not advance so the item remains retryable.
    retryable: bool = False


class OpenCTIReadError(RuntimeError):
    """Raised when an OpenCTI entity read fails (transport/API), not when missing."""


class RSTThreatLibrary:
    """Threat Library sync engine used by SDK ``BaseDataProcessor`` instances.

    Scheduling, work lifecycle, and ``last_run`` persistence are owned by
    ``connectors_sdk.ExternalImportConnector``. This class keeps collect /
    transform / merge-split business logic.
    """

    def __init__(
        self, *, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper
        self.converter = ConverterToStix(
            helper=self.helper,
            tlp_level=str(self.config.connector.tlp_level),
        )

        tl = self.config.rst_threat_library

        self.object_types = [str(t).strip() for t in tl.object_types if str(t).strip()]
        self.import_from_date = tl.import_from_date or ""

        self._client_config = {
            "baseurl": str(tl.baseurl),
            "apikey": tl.apikey.get_secret_value(),
            "auth_header": tl.auth_header,
            "contimeout": int(tl.contimeout),
            "readtimeout": int(tl.readtimeout),
            "retry": int(tl.retry),
            "ssl_verify": bool(tl.ssl_verify),
            "page_size": int(tl.page_size),
            "order_by": tl.order_by,
            "order_mode": tl.order_mode,
            "proxy": tl.proxy or "",
        }

        self._max_retries = int(tl.max_retries)
        self._retry_delay = int(tl.retry_delay)
        self._retry_backoff_multiplier = float(tl.retry_backoff_multiplier)
        self._opencti_batch_size = max(1, int(tl.opencti_batch_size))

        self._sync_labels = [str(x).strip() for x in tl.sync_labels if str(x).strip()]
        self._reconcile_exclude_labels = [
            str(x).strip() for x in tl.reconcile_exclude_labels if str(x).strip()
        ]
        self._reconcile_allow_created_by = [
            str(x).strip() for x in tl.reconcile_allow_created_by if str(x).strip()
        ]

        self.merge_split_enabled = bool(tl.merge_split)
        self.respect_user_edits = bool(tl.respect_user_edits)
        self._intrusion_set_default_confidence = tl.intrusion_set_default_confidence

        # Optional hooks injected by SDK processors (WorkManager + ConnectorState).
        self._state_persist: Optional[Callable[[Dict[str, Any]], None]] = None
        self._send_bundle: Optional[Callable[[List[Any], str], bool]] = None

    def build_client(self) -> ThreatLibraryClient:
        """Construct an API client from connector settings."""
        return ThreatLibraryClient(
            self.helper,
            base_url=self._client_config["baseurl"],
            api_key=self._client_config["apikey"],
            auth_header=self._client_config["auth_header"],
            connect_timeout=self._client_config["contimeout"],
            read_timeout=self._client_config["readtimeout"],
            retry=self._client_config["retry"],
            ssl_verify=self._client_config["ssl_verify"],
            page_size=self._client_config["page_size"],
            order_by=self._client_config["order_by"],
            order_mode=self._client_config["order_mode"],
            proxy=self._client_config["proxy"],
        )

    def log_startup_config(self) -> None:
        """Log connector behaviour flags once at process start."""
        self.helper.connector_logger.info("Starting RST Threat Library connector")
        self.helper.connector_logger.info(
            f"OpenCTI push: send_stix2_bundle "
            f"(batch_size={self._opencti_batch_size}, "
            f"tlp_level={self.config.connector.tlp_level})"
        )
        if self._sync_labels:
            self.helper.connector_logger.info(
                f"Sync labels merged on import: {self._sync_labels}"
            )
        if self._reconcile_exclude_labels:
            self.helper.connector_logger.info(
                "Reconcile exclude-labels (excluded from merge/split): "
                f"{self._reconcile_exclude_labels}"
            )
        if self._reconcile_allow_created_by:
            self.helper.connector_logger.info(
                "Reconcile createdBy allowlist (merge/split only these authors): "
                f"{self._reconcile_allow_created_by}"
            )
        self.helper.connector_logger.info(
            "Alias merge/split at import "
            "(intrusion sets, malware, tools, campaigns): "
            f"enabled={self.merge_split_enabled}"
        )
        self.helper.connector_logger.info(
            "Retain local user edits (confidence lock): "
            f"enabled={self.respect_user_edits}"
        )
        if self.respect_user_edits:
            self.helper.connector_logger.info(
                "User-edit policy: preserve OpenCTI content when its confidence "
                "exceeds Threat Library confidence; otherwise connector overrides"
            )
        if self._intrusion_set_default_confidence is not None:
            self.helper.connector_logger.info(
                "Intrusion-set import confidence override: "
                f"{self._intrusion_set_default_confidence}"
            )
        if self.merge_split_enabled:
            self.helper.connector_logger.info(
                "Duplicates use OpenCTI stix.merge (relationships, "
                "sightings, notes preserved) for intrusion sets, malware, "
                "tools, and campaigns; merge/split runs after delta import."
            )
        duration_period_s = self.config.connector.duration_period.total_seconds()
        self.helper.connector_logger.info(
            f"Scheduled execution period: {duration_period_s}s"
        )

    def _seed_cursor(self) -> str:
        s = (self.import_from_date or "").strip()
        if not s:
            return ""
        try:
            datetime.strptime(s, "%Y-%m-%d")
        except ValueError:
            self.helper.connector_logger.warning(
                f"Invalid import_from_date '{s}' (expected YYYY-MM-DD); ignoring."
            )
            return ""
        return f"{s}T00:00:00.000Z"

    def _persist_state(self, state: Dict[str, Any]) -> None:
        """Persist mutable state via SDK hook or legacy helper.set_state."""
        if self._state_persist is not None:
            self._state_persist(state)
            return
        self.helper.set_state(state)

    @staticmethod
    def _entity_label_values(entity: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        ol = entity.get("objectLabel")
        if not ol:
            return out
        if isinstance(ol, dict) and ol.get("edges") is not None:
            for edge in ol.get("edges") or []:
                if not isinstance(edge, dict):
                    continue
                node = edge.get("node")
                if isinstance(node, dict) and node.get("value"):
                    out.append(str(node["value"]))
            return out
        if isinstance(ol, list):
            for x in ol:
                if isinstance(x, dict):
                    v = x.get("value")
                    if v:
                        out.append(str(v))
                elif isinstance(x, str):
                    out.append(x)
        return out

    @staticmethod
    def _created_by_standard_id(entity: Dict[str, Any]) -> Optional[str]:
        cb = entity.get("createdBy")
        if not cb or not isinstance(cb, dict):
            return None
        sid = cb.get("standard_id")
        return str(sid) if sid else None

    def _sync_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        return state.setdefault("fingerprints", {})

    def _get_sync_record(
        self, state: Dict[str, Any], obj_type_path: str, standard_id: str
    ) -> Optional[Dict[str, Any]]:
        type_map = self._sync_state(state).get(obj_type_path) or {}
        rec = type_map.get(standard_id)
        return rec if isinstance(rec, dict) else None

    def _set_sync_record(
        self,
        state: Dict[str, Any],
        obj_type_path: str,
        standard_id: str,
        record: Dict[str, Any],
    ) -> None:
        type_map = self._sync_state(state).setdefault(obj_type_path, {})
        type_map[standard_id] = record

    def _record_sync_state(
        self,
        state: Dict[str, Any],
        obj_type_path: str,
        api_items: List[Dict[str, Any]],
    ) -> None:
        if not self.respect_user_edits:
            return
        for item in api_items:
            sid = item.get("standard_id")
            if not sid:
                continue
            self._set_sync_record(
                state,
                obj_type_path,
                sid,
                make_sync_record(item),
            )

    def _analyst_locks_entity(
        self,
        opencti_entity: Dict[str, Any],
        *,
        obj_type_path: str,
        state: Dict[str, Any],
        api_item: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if not self.respect_user_edits:
            return False
        sid = opencti_entity.get("standard_id")
        if not sid:
            return False
        if api_item is not None:
            api_item = self._normalize_api_item(obj_type_path, api_item)
        record = self._get_sync_record(state, obj_type_path, sid)
        return self._analyst_confidence_wins(
            opencti_entity,
            obj_type_path=obj_type_path,
            api_item=api_item,
            stored_record=record,
        )

    def _upstream_confidence_for_lock(
        self,
        obj_type_path: str,
        *,
        api_item: Optional[Dict[str, Any]] = None,
        stored_record: Optional[Dict[str, Any]] = None,
    ) -> int:
        if api_item is not None:
            return confidence_value(api_item)
        if (
            obj_type_path == ThreatObjectType.INTRUSION_SETS
            and self._intrusion_set_default_confidence is not None
        ):
            return self._intrusion_set_default_confidence
        stored = upstream_confidence_from_record(stored_record)
        return stored if stored is not None else 0

    def _analyst_confidence_wins(
        self,
        opencti_entity: Dict[str, Any],
        *,
        obj_type_path: str,
        api_item: Optional[Dict[str, Any]] = None,
        stored_record: Optional[Dict[str, Any]] = None,
    ) -> bool:
        opencti_conf = confidence_value(opencti_entity)
        upstream_conf = self._upstream_confidence_for_lock(
            obj_type_path,
            api_item=api_item,
            stored_record=stored_record,
        )
        return opencti_conf > upstream_conf

    def _prepare_upsert_item(
        self,
        obj_type_path: str,
        api_item: Dict[str, Any],
        state: Dict[str, Any],
    ) -> UpsertPrep:
        api_item = self._normalize_api_item(obj_type_path, api_item)
        if not self.respect_user_edits:
            return UpsertPrep(skip=False, api_item=api_item)

        sid = api_item.get("standard_id")
        if not sid:
            return UpsertPrep(skip=False, api_item=api_item)

        try:
            opencti_entity = self._read_opencti_entity(obj_type_path, sid)
        except OpenCTIReadError as ex:
            # Do not treat API failures as "missing" — that would overwrite
            # analyst edits when respect_user_edits is enabled.
            return UpsertPrep(
                skip=True,
                api_item=api_item,
                skip_reason=f"OpenCTI read failed: {ex}",
                retryable=True,
            )
        if not opencti_entity:
            return UpsertPrep(skip=False, api_item=api_item)

        if self._analyst_locks_entity(
            opencti_entity,
            obj_type_path=obj_type_path,
            state=state,
            api_item=api_item,
        ):
            oc_conf = confidence_value(opencti_entity)
            api_conf = confidence_value(api_item)
            return UpsertPrep(
                skip=True,
                api_item=api_item,
                opencti_entity=opencti_entity,
                skip_reason=(
                    "OpenCTI confidence "
                    f"({oc_conf}) exceeds Threat Library confidence "
                    f"({api_conf}) retains analyst edits"
                ),
            )

        oc_conf = confidence_value(opencti_entity)
        api_conf = confidence_value(api_item)
        if oc_conf < api_conf:
            self.helper.connector_logger.info(
                f"[{obj_type_path}] connector override for {sid} "
                f"(name={api_item.get('name')}) — OpenCTI confidence "
                f"({oc_conf}) is below Threat Library confidence ({api_conf})"
            )

        return UpsertPrep(
            skip=False,
            api_item=api_item,
            opencti_entity=opencti_entity,
        )

    def _upsert_sdo_from_prep(
        self, obj_type_path: str, prep: UpsertPrep
    ) -> Optional[Any]:
        if prep.skip:
            return None
        return self._item_to_sdo(prep.api_item, obj_type_path)

    def _read_opencti_entity(
        self, obj_type_path: str, standard_id: str
    ) -> Optional[Dict[str, Any]]:
        """Read an OpenCTI entity by standard_id.

        Returns:
            The entity dict, or ``None`` when OpenCTI reports it as missing.

        Raises:
            OpenCTIReadError: On transport/API failures (not a missing entity).
        """
        api = self.helper.api
        try:
            if obj_type_path == ThreatObjectType.INTRUSION_SETS:
                return api.intrusion_set.read(id=standard_id) or None
            if obj_type_path == ThreatObjectType.MALWARE:
                return api.malware.read(id=standard_id) or None
            if obj_type_path == ThreatObjectType.TOOLS:
                return api.tool.read(id=standard_id) or None
            if obj_type_path == ThreatObjectType.CAMPAIGNS:
                return api.campaign.read(id=standard_id) or None
        except OpenCTIReadError:
            raise
        except Exception as ex:
            self.helper.connector_logger.warning(
                f"[{obj_type_path}] read {standard_id} failed: {ex}"
            )
            raise OpenCTIReadError(
                f"[{obj_type_path}] read {standard_id} failed: {ex}"
            ) from ex
        return None

    def _wait_for_opencti_entity(
        self,
        obj_type_path: str,
        standard_id: str,
        *,
        attempts: int = _MERGE_SURVIVOR_READ_ATTEMPTS,
        delay_s: float = _MERGE_SURVIVOR_READ_DELAY_S,
        context: str = "merge",
    ) -> Optional[Dict[str, Any]]:
        """Read an entity, retrying while bundle-mode workers run.

        Distinguishes successful "not found" (``None``) from read errors
        (``OpenCTIReadError``). Retries both; re-raises if every attempt failed
        with an error and no successful miss was observed.
        """
        if not standard_id:
            return None

        total_attempts = max(attempts, 1)
        saw_successful_miss = False
        last_error: Optional[OpenCTIReadError] = None

        for attempt in range(1, total_attempts + 1):
            try:
                entity = self._read_opencti_entity(obj_type_path, standard_id)
            except OpenCTIReadError as ex:
                last_error = ex
                self.helper.connector_logger.info(
                    f"[{obj_type_path}] {context}: read error for {standard_id} "
                    f"(attempt {attempt}/{total_attempts}): {ex}"
                )
            else:
                if entity:
                    if attempt > 1:
                        self.helper.connector_logger.info(
                            f"[{obj_type_path}] {context}: {standard_id} "
                            f"readable after wait (attempt {attempt}/"
                            f"{total_attempts})"
                        )
                    return entity
                saw_successful_miss = True

            if attempt < total_attempts:
                self.helper.connector_logger.info(
                    f"[{obj_type_path}] {context}: waiting for {standard_id} "
                    f"in OpenCTI (attempt {attempt + 1}/{total_attempts}, "
                    f"delay={delay_s:.1f}s)"
                )
                time.sleep(delay_s)

        if last_error is not None and not saw_successful_miss:
            raise last_error
        return None

    def _is_entity_user_edited(
        self,
        obj_type_path: str,
        entity: Dict[str, Any],
        state: Dict[str, Any],
        api_item: Optional[Dict[str, Any]] = None,
    ) -> bool:
        return self._analyst_locks_entity(
            entity,
            obj_type_path=obj_type_path,
            state=state,
            api_item=api_item,
        )

    def _entity_has_exclude_label(self, entity: Dict[str, Any]) -> bool:
        """True when entity carries a label listed in RECONCILE_EXCLUDE_LABELS."""
        if not self._reconcile_exclude_labels:
            return False
        labels = self._entity_label_values(entity)
        return any(block in labels for block in self._reconcile_exclude_labels)

    def _should_allow_reconcile_delete(self, entity: Dict[str, Any]) -> bool:
        """Return False if this entity is protected from merge/split fusion."""
        if self._entity_has_exclude_label(entity):
            self.helper.connector_logger.debug(
                "Merge/split skip fusion (exclude-label): "
                f"standard_id={entity.get('standard_id')}"
            )
            return False

        allow = self._reconcile_allow_created_by
        if allow:
            cb = self._created_by_standard_id(entity)
            if not cb or cb not in allow:
                self.helper.connector_logger.debug(
                    "Merge/split skip fusion (createdBy not in allowlist): "
                    f"standard_id={entity.get('standard_id')} createdBy={cb}"
                )
                return False

        return True

    def _normalize_api_item(
        self, obj_type_path: str, item: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply connector defaults to upstream API payloads before sync."""
        if (
            obj_type_path != ThreatObjectType.INTRUSION_SETS
            or self._intrusion_set_default_confidence is None
        ):
            return item
        out = dict(item)
        out["confidence"] = self._intrusion_set_default_confidence
        return out

    def _list_opencti_domain_objects(self, obj_type_path: str) -> List[Dict[str, Any]]:
        api = self.helper.api
        try:
            if obj_type_path == "intrusion-sets":
                data = api.intrusion_set.list(getAll=True)
            elif obj_type_path == "malware":
                data = api.malware.list(getAll=True)
            elif obj_type_path == "tools":
                data = api.tool.list(getAll=True)
            elif obj_type_path == "campaigns":
                data = api.campaign.list(getAll=True)
            else:
                return []
            return list(data) if data else []
        except Exception as ex:
            self.helper.connector_logger.error(
                f"[{obj_type_path}] reconcile OpenCTI list failed: {ex}"
            )
            return []

    def _opencti_entities_for_merge_split(
        self,
        obj_type_path: str,
        state: Dict[str, Any],
        api_items: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Entities to compare with the API catalogue for merge/split.

        Only connector-owned entities are included (sync labels or managed IDs).
        Name/alias overlap alone is not treated as ownership, so unrelated
        OpenCTI objects cannot be pulled into fusion via a shared alias.
        ``api_items`` is accepted for call-site compatibility; ownership does
        not use catalogue identifier overlap.
        """
        _ = api_items
        managed = set((state.get("managed_ids") or {}).get(obj_type_path, []))

        out: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for entity in self._list_opencti_domain_objects(obj_type_path):
            sid = entity.get("standard_id")
            if not sid or sid in seen:
                continue
            if self._entity_has_exclude_label(entity):
                self.helper.connector_logger.debug(
                    f"[{obj_type_path}] merge/split: skip "
                    f"{entity.get('standard_id')} (exclude-label)"
                )
                continue

            labels = self._entity_label_values(entity)
            include = False
            if self._sync_labels and any(sl in labels for sl in self._sync_labels):
                include = True
            elif sid in managed:
                include = True
            if include:
                out.append(entity)
                seen.add(sid)
        return out

    def _split_failure_fingerprint(self, split: SplitCandidate) -> str:
        aliases = sorted(str(a) for a in (split.aliases_to_remove or []) if a)
        split_off = sorted(
            str(item.get("standard_id") or "")
            for item in (split.split_off_api_items or [])
            if item.get("standard_id")
        )
        return "|".join(aliases) + "#" + ",".join(split_off)

    def _get_split_failure_entry(
        self, state: Dict[str, Any], obj_type: str, oc_sid: str
    ) -> Dict[str, Any]:
        failures = state.setdefault(_SPLIT_FAILURES_STATE_KEY, {})
        by_type = failures.setdefault(obj_type, {})
        entry = by_type.get(oc_sid)
        if not isinstance(entry, dict):
            entry = {"count": 0, "fingerprint": "", "skipped": False}
            by_type[oc_sid] = entry
        return entry

    def _clear_split_failure(
        self, state: Dict[str, Any], obj_type: str, oc_sid: str
    ) -> None:
        failures = state.get(_SPLIT_FAILURES_STATE_KEY) or {}
        by_type = failures.get(obj_type) or {}
        if oc_sid in by_type:
            del by_type[oc_sid]
            if not by_type:
                failures.pop(obj_type, None)
            if not failures:
                state.pop(_SPLIT_FAILURES_STATE_KEY, None)
            self._persist_state(state)

    def _should_skip_split_after_failures(
        self,
        split: SplitCandidate,
        obj_type: str,
        state: Dict[str, Any],
    ) -> bool:
        """True when this split continues to fail."""
        oc = split.opencti_entity
        oc_sid = oc.get("standard_id")
        if not oc_sid:
            return False

        fingerprint = self._split_failure_fingerprint(split)
        entry = self._get_split_failure_entry(state, obj_type, oc_sid)
        if entry.get("fingerprint") != fingerprint:
            entry["count"] = 0
            entry["fingerprint"] = fingerprint
            entry["skipped"] = False
            self._persist_state(state)
            return False

        return bool(entry.get("skipped"))

    def _record_split_failure(
        self,
        split: SplitCandidate,
        obj_type: str,
        state: Dict[str, Any],
        *,
        reason: str,
    ) -> None:
        """Track consecutive split failures"""
        oc = split.opencti_entity
        oc_sid = oc.get("standard_id")
        if not oc_sid:
            return

        fingerprint = self._split_failure_fingerprint(split)
        entry = self._get_split_failure_entry(state, obj_type, oc_sid)
        if entry.get("fingerprint") != fingerprint:
            entry["count"] = 0
            entry["fingerprint"] = fingerprint
            entry["skipped"] = False

        entry["count"] = int(entry.get("count") or 0) + 1
        entry["fingerprint"] = fingerprint
        count = entry["count"]

        if count >= _SPLIT_FAILURE_SKIP_THRESHOLD and not entry.get("skipped"):
            entry["skipped"] = True
            self.helper.connector_logger.info(
                f"[{obj_type}] split: skipped "
                f"{oc_sid} (name={oc.get('name')}) — abandoned after "
                f"{count} consecutive failures ({reason})"
            )
        else:
            self.helper.connector_logger.info(
                f"[{obj_type}] split: skip {oc_sid} (name={oc.get('name')}) — "
                f"{reason} (failure {count}/{_SPLIT_FAILURE_SKIP_THRESHOLD})"
            )
        self._persist_state(state)

    def _apply_merge_split(
        self,
        client: ThreatLibraryClient,
        state: Dict[str, Any],
        timestamp: int,
    ) -> bool:
        """Run alias merge/split for each configured threat-object type."""
        success = True
        for obj_type in self.object_types:
            if obj_type not in _MERGE_SPLIT_TYPES:
                continue
            if not self._apply_merge_split_for_type(client, state, timestamp, obj_type):
                success = False
        return success

    def _apply_merge_split_for_type(
        self,
        client: ThreatLibraryClient,
        state: Dict[str, Any],
        timestamp: int,
        obj_type: str,
    ) -> bool:
        """Compare one catalogue with OpenCTI and apply split/merge."""
        api_items: List[Dict[str, Any]] = []
        try:
            for item in client.iter_all_items(obj_type):
                api_items.append(item)
                n = len(api_items)
                if n == _MERGE_SPLIT_CATALOGUE_WARN or (
                    n > _MERGE_SPLIT_CATALOGUE_WARN
                    and n % _MERGE_SPLIT_CATALOGUE_WARN == 0
                ):
                    self.helper.connector_logger.warning(
                        f"[{obj_type}] merge/split catalogue size is {n}; "
                        "holding the full catalogue in memory"
                    )
        except Exception as ex:
            self.helper.connector_logger.error(
                f"[{obj_type}] merge/split catalogue fetch failed: {ex}\n"
                f"{traceback.format_exc()}"
            )
            return False

        opencti_entities = self._opencti_entities_for_merge_split(
            obj_type, state, api_items=api_items
        )
        plan = analyze_merge_split(api_items, opencti_entities)

        if not plan.splits and not plan.merges:
            self.helper.connector_logger.info(
                f"[{obj_type}] merge/split: no candidates "
                f"(api={len(api_items)}, opencti_scoped={len(opencti_entities)})"
            )
            return True

        self.helper.connector_logger.info(
            f"[{obj_type}] merge/split: {len(plan.splits)} split(s), "
            f"{len(plan.merges)} merge(s)"
        )

        success = True
        for split in plan.splits:
            if not self._execute_split(split, timestamp, obj_type, state):
                success = False

        for merge in plan.merges:
            if not self._execute_merge(merge, timestamp, obj_type, state):
                success = False
        return success

    def _execute_split(
        self,
        split: SplitCandidate,
        timestamp: int,
        obj_type: str,
        state: Dict[str, Any],
    ) -> bool:
        oc = split.opencti_entity
        oid = oc.get("id")
        oc_sid = oc.get("standard_id")
        if not oid or not oc_sid:
            return False

        if self._should_skip_split_after_failures(split, obj_type, state):
            self.helper.connector_logger.debug(
                f"[{obj_type}] split: skipped {oc_sid} "
                f"(name={oc.get('name')}) — previously abandoned"
            )
            return False

        if self._analyst_locks_entity(
            oc,
            obj_type_path=obj_type,
            state=state,
            api_item=split.keep_api_item,
        ):
            self._record_split_failure(
                split,
                obj_type,
                state,
                reason=("OpenCTI confidence exceeds Threat Library (analyst lock)"),
            )
            return False

        stix_objects: List[Any] = []
        seen_identities: Dict[str, bool] = {}
        pushed: List[str] = []

        refresh_items: List[Dict[str, Any]] = []
        if split.keep_api_item:
            refresh_items.append(split.keep_api_item)
        refresh_items.extend(split.split_off_api_items)

        # Aliases must not be removed until every required split-off object was
        # successfully upserted; skipped upserts (analyst lock / read errors)
        # would otherwise drop aliases without transferring them.
        required_split_off_sids = {
            str(item.get("standard_id"))
            for item in (split.split_off_api_items or [])
            if item.get("standard_id")
        }

        pushed_items: List[Dict[str, Any]] = []
        for item in refresh_items:
            prep = self._prepare_upsert_item(obj_type, item, state)
            if prep.skip:
                if prep.skip_reason:
                    sid = item.get("standard_id")
                    self.helper.connector_logger.info(
                        f"[{obj_type}] split: skip upsert for {sid} "
                        f"(name={item.get('name')}) — {prep.skip_reason}"
                    )
                continue
            sdo = self._upsert_sdo_from_prep(obj_type, prep)
            if sdo is None:
                sid = item.get("standard_id")
                self.helper.connector_logger.error(
                    f"[{obj_type}] split: failed to build SDO for {sid} "
                    f"(name={item.get('name')})"
                )
                self._record_split_failure(
                    split,
                    obj_type,
                    state,
                    reason=f"failed to build SDO for {sid}",
                )
                return False
            stix_objects.append(sdo)
            sid = item.get("standard_id")
            if sid:
                pushed.append(sid)
                pushed_items.append(prep.api_item)
            cb = item.get("createdBy") or {}
            cb_id = cb.get("standard_id")
            if cb_id and cb_id not in seen_identities:
                identity = self.converter.build_identity(cb)
                if identity is not None:
                    stix_objects.append(identity)
                    seen_identities[cb_id] = True

        missing_split_off = sorted(
            sid for sid in required_split_off_sids if sid not in pushed
        )
        if missing_split_off and split.aliases_to_remove:
            self._record_split_failure(
                split,
                obj_type,
                state,
                reason=(
                    "split-off upsert incomplete before alias removal: "
                    + ",".join(missing_split_off)
                ),
            )
            return False

        if stix_objects:
            if not self._batch_send(stix_objects, timestamp, obj_type):
                self._record_split_failure(
                    split,
                    obj_type,
                    state,
                    reason="OpenCTI push failed",
                )
                return False
            self._record_sync_state(state, obj_type, pushed_items)
            managed = state.setdefault("managed_ids", {})
            cur = set(managed.get(obj_type, []))
            cur.update(pushed)
            managed[obj_type] = sorted(cur)
        elif required_split_off_sids or not split.aliases_to_remove:
            self._record_split_failure(
                split,
                obj_type,
                state,
                reason="no upsertable split-off items",
            )
            return False

        # Alias mutation only after dependent objects are sent (or for alias-only
        # splits), so a failed push leaves the conflicting aliases intact for retry.
        if split.aliases_to_remove:
            remaining = [
                a for a in (oc.get("aliases") or []) if a not in split.aliases_to_remove
            ]
            try:
                self.helper.api.stix_domain_object.update_field(
                    id=oid,
                    input={"key": "aliases", "value": remaining},
                )
                self.helper.connector_logger.info(
                    f"[{obj_type}] split: removed aliases {split.aliases_to_remove} "
                    f"from {oc_sid} (name={oc.get('name')})"
                )
            except Exception as ex:
                self.helper.connector_logger.error(
                    f"[{obj_type}] split alias update failed for {oc_sid}: {ex}"
                )
                self._record_split_failure(
                    split,
                    obj_type,
                    state,
                    reason=f"alias update failed: {ex}",
                )
                return False

        self._clear_split_failure(state, obj_type, oc_sid)
        self._persist_state(state)
        return True

    def _opencti_fusion_merge(
        self,
        target_entity: Dict[str, Any],
        source_entities: List[Dict[str, Any]],
        obj_type: str,
        state: Dict[str, Any],
    ) -> List[str]:
        """Fuse duplicate objects into the target via OpenCTI merge."""
        target_internal_id = target_entity.get("id")
        target_sid = target_entity.get("standard_id")
        if not target_internal_id or not target_sid:
            return []

        source_pairs: List[Tuple[str, str]] = []
        for src in source_entities:
            src_sid = src.get("standard_id")
            src_internal_id = src.get("id")
            if not src_sid or not src_internal_id or src_sid == target_sid:
                continue
            if not self._should_allow_reconcile_delete(src):
                self.helper.connector_logger.info(
                    f"[{obj_type}] merge: skip source {src_sid} "
                    f"(name={src.get('name')}) — protected by exclude-labels "
                    "or createdBy allowlist"
                )
                continue
            if self._is_entity_user_edited(obj_type, src, state):
                self.helper.connector_logger.info(
                    f"[{obj_type}] merge: skip source {src_sid} "
                    f"(name={src.get('name')}) — OpenCTI confidence exceeds "
                    "Threat Library (analyst lock)"
                )
                continue
            source_pairs.append((src_internal_id, src_sid))

        if not source_pairs:
            return []

        merged: List[str] = []
        for offset in range(0, len(source_pairs), _OPENCTI_MERGE_SOURCE_BATCH):
            batch = source_pairs[offset : offset + _OPENCTI_MERGE_SOURCE_BATCH]
            chunk_internal = [pair[0] for pair in batch]
            chunk_sids = [pair[1] for pair in batch]
            try:
                self.helper.api.stix.merge(
                    id=target_internal_id,
                    object_ids=chunk_internal,
                )
                merged.extend(chunk_sids)
                self.helper.connector_logger.info(
                    f"[{obj_type}] OpenCTI merge: fused {chunk_sids} into "
                    f"{target_sid} (name={target_entity.get('name')})"
                )
            except Exception as ex:
                self.helper.connector_logger.error(
                    f"[{obj_type}] OpenCTI merge failed for sources {chunk_sids} "
                    f"into {target_sid}: {ex}"
                )
        return merged

    def _execute_merge(
        self,
        merge: MergeCandidate,
        timestamp: int,
        obj_type: str,
        state: Dict[str, Any],
    ) -> bool:
        stix_objects: List[Any] = []
        seen_identities: Dict[str, bool] = {}
        pushed: List[str] = []

        item = merge.target_api_item
        target_sid = item.get("standard_id")

        score_candidates: List[Dict[str, Any]] = [
            entity
            for entity in merge.opencti_entities_to_merge
            if self._should_allow_reconcile_delete(entity)
        ]
        if target_sid:
            try:
                existing_api_entity = self._read_opencti_entity(obj_type, target_sid)
            except OpenCTIReadError as ex:
                self.helper.connector_logger.error(
                    f"[{obj_type}] merge: OpenCTI read failed for target "
                    f"{target_sid}: {ex}"
                )
                return False
            if existing_api_entity and self._should_allow_reconcile_delete(
                existing_api_entity
            ):
                score_candidates.append(existing_api_entity)
            elif existing_api_entity:
                self.helper.connector_logger.info(
                    f"[{obj_type}] merge: skip protected OpenCTI target "
                    f"{target_sid} (name={existing_api_entity.get('name')}) as "
                    "fusion survivor candidate — exclude-labels or createdBy "
                    "allowlist"
                )

        preferred_survivor = pick_opencti_merge_survivor(
            target_sid or "", score_candidates
        )
        preferred_survivor_sid = (
            preferred_survivor.get("standard_id") if preferred_survivor else None
        )
        if (
            preferred_survivor
            and preferred_survivor_sid
            and preferred_survivor_sid != target_sid
        ):
            self.helper.connector_logger.info(
                f"[{obj_type}] merge: choosing OpenCTI survivor "
                f"{preferred_survivor_sid} (name={preferred_survivor.get('name')}, "
                f"aliases={len(preferred_survivor.get('aliases') or [])}) over "
                f"upstream {target_sid} (name={item.get('name')}) — more aliases"
            )

        survivor_prep = self._prepare_upsert_item(obj_type, item, state)
        survivor_pushed: List[Dict[str, Any]] = []
        if survivor_prep.skip and survivor_prep.retryable:
            self.helper.connector_logger.error(
                f"[{obj_type}] merge: aborting — survivor upsert skipped "
                f"for {target_sid} ({survivor_prep.skip_reason})"
            )
            return False
        if not survivor_prep.skip:
            sdo = self._upsert_sdo_from_prep(obj_type, survivor_prep)
            if sdo is not None:
                stix_objects.append(sdo)
                if target_sid:
                    pushed.append(target_sid)
                    survivor_pushed.append(item)
                cb = item.get("createdBy") or {}
                cb_id = cb.get("standard_id")
                if cb_id and cb_id not in seen_identities:
                    identity = self.converter.build_identity(cb)
                    if identity is not None:
                        stix_objects.append(identity)
                        seen_identities[cb_id] = True
        elif survivor_prep.skip_reason:
            self.helper.connector_logger.info(
                f"[{obj_type}] merge: skip survivor upsert for {target_sid} "
                f"(name={item.get('name')}) — {survivor_prep.skip_reason}"
            )

        if stix_objects and not self._batch_send(stix_objects, timestamp, obj_type):
            self.helper.connector_logger.warning(
                f"[{obj_type}] merge: survivor upsert failed for {target_sid}; "
                "skipping OpenCTI fusion"
            )
            return False

        if survivor_pushed:
            self._record_sync_state(state, obj_type, survivor_pushed)

        if not target_sid:
            return True

        try:
            api_target = self._wait_for_opencti_entity(
                obj_type,
                target_sid,
                context="merge",
            )
        except OpenCTIReadError as ex:
            self.helper.connector_logger.error(
                f"[{obj_type}] merge: OpenCTI read failed while waiting for "
                f"survivor {target_sid}: {ex}"
            )
            return False
        if not api_target and survivor_prep.opencti_entity:
            api_target = survivor_prep.opencti_entity
            self.helper.connector_logger.warning(
                f"[{obj_type}] merge: using cached OpenCTI entity for "
                f"{target_sid} after post-upsert read miss"
            )

        fusion_target: Optional[Dict[str, Any]] = None
        if preferred_survivor_sid and preferred_survivor_sid != target_sid:
            try:
                preferred_live = self._wait_for_opencti_entity(
                    obj_type,
                    preferred_survivor_sid,
                    context="merge preferred survivor",
                )
            except OpenCTIReadError as ex:
                self.helper.connector_logger.error(
                    f"[{obj_type}] merge: OpenCTI read failed while waiting for "
                    f"preferred survivor {preferred_survivor_sid}: {ex}"
                )
                return False
            if preferred_live:
                fusion_target = preferred_live
            elif preferred_survivor and preferred_survivor.get("id"):
                fusion_target = preferred_survivor
                self.helper.connector_logger.warning(
                    f"[{obj_type}] merge: using cached preferred survivor "
                    f"{preferred_survivor_sid} after read miss"
                )
            elif api_target:
                self.helper.connector_logger.warning(
                    f"[{obj_type}] merge: preferred survivor "
                    f"{preferred_survivor_sid} no longer readable; "
                    f"fusing into upstream {target_sid}"
                )
                fusion_target = api_target
        elif api_target:
            fusion_target = api_target
        elif preferred_survivor and preferred_survivor.get("id"):
            fusion_target = preferred_survivor
            self.helper.connector_logger.warning(
                f"[{obj_type}] merge: upstream survivor {target_sid} not "
                f"readable after upsert; fusing into OpenCTI candidate "
                f"{fusion_target.get('standard_id')} "
                f"(name={fusion_target.get('name')})"
            )

        if not fusion_target or not fusion_target.get("id"):
            self.helper.connector_logger.error(
                f"[{obj_type}] merge: survivor {target_sid} not found in OpenCTI "
                "after upsert (and no usable OpenCTI fusion candidate)"
            )
            return False

        fusion_target_sid = fusion_target.get("standard_id")
        if not self._should_allow_reconcile_delete(fusion_target):
            self.helper.connector_logger.info(
                f"[{obj_type}] merge: skip OpenCTI fusion into {fusion_target_sid} "
                f"(name={fusion_target.get('name')}) — protected by exclude-labels "
                "or createdBy allowlist"
            )
            return True
        if self._analyst_locks_entity(
            fusion_target,
            obj_type_path=obj_type,
            state=state,
            api_item=merge.target_api_item,
        ):
            self.helper.connector_logger.info(
                f"[{obj_type}] merge: skip OpenCTI fusion into {fusion_target_sid} "
                f"(name={fusion_target.get('name')}) — OpenCTI confidence exceeds "
                "Threat Library (analyst lock)"
            )
            return True

        source_by_sid: Dict[str, Dict[str, Any]] = {}
        for src in merge.opencti_entities_to_merge:
            src_sid = src.get("standard_id")
            if src_sid and src_sid != fusion_target_sid:
                source_by_sid[src_sid] = src
        if target_sid != fusion_target_sid and api_target:
            source_by_sid[target_sid] = api_target

        merged_sids = self._opencti_fusion_merge(
            fusion_target,
            list(source_by_sid.values()),
            obj_type,
            state,
        )

        managed = state.setdefault("managed_ids", {})
        cur = set(managed.get(obj_type, []))
        if pushed:
            cur.update(pushed)
        for sid in merged_sids:
            cur.discard(sid)
        if fusion_target_sid:
            cur.add(fusion_target_sid)
        managed[obj_type] = sorted(cur)
        self._persist_state(state)
        return True

    def _cycle_type(
        self,
        client: ThreatLibraryClient,
        obj_type: str,
        state: Dict[str, Any],
        timestamp: int,
        seed: str,
    ) -> bool:
        """Import one object type. Return False on fetch/push/conversion failure."""
        cursor_key = f"cursor_{obj_type}"
        cursor_ids_key = f"cursor_ids_{obj_type}"
        cursor = state.get(cursor_key) or seed
        seen_at_cursor = {str(sid) for sid in (state.get(cursor_ids_key) or []) if sid}
        self.helper.connector_logger.info(
            f"[{obj_type}] cycle start (cursor={cursor or '(none)'})"
        )

        stix_objects: List[Any] = []
        seen_identities: Dict[str, bool] = {}
        identity_by_id: Dict[str, Any] = {}
        pushed_standard_ids: List[str] = []
        pushed_api_items: List[Dict[str, Any]] = []
        latest = cursor
        latest_ids: Set[str] = set(seen_at_cursor) if cursor else set()
        count = 0
        skipped_user_edit = 0
        conversion_failures = 0
        retryable_skips = 0
        batch_item_count = 0
        any_pushed = False
        batch_size = self._opencti_batch_size

        def advance_checkpoint(mod: str, sid: str) -> None:
            nonlocal latest, latest_ids
            if not mod:
                return
            if not latest or mod > latest:
                latest = mod
                latest_ids = {sid} if sid else set()
            elif mod == latest and sid:
                latest_ids.add(sid)

        def flush_batch() -> bool:
            nonlocal stix_objects, pushed_standard_ids, pushed_api_items
            nonlocal batch_item_count, any_pushed, seen_identities
            if not stix_objects:
                return True
            ok = self._batch_send(stix_objects, timestamp, obj_type)
            if not ok:
                return False
            any_pushed = True
            self._record_sync_state(state, obj_type, pushed_api_items)
            managed = state.setdefault("managed_ids", {})
            cur = set(managed.get(obj_type, []))
            cur.update(pushed_standard_ids)
            managed[obj_type] = sorted(cur)
            self._persist_state(state)
            stix_objects = []
            pushed_standard_ids = []
            pushed_api_items = []
            batch_item_count = 0
            # Re-include referenced identities in every subsequent batch.
            seen_identities = {}
            return True

        try:
            for item in client.iter_new_items(
                obj_type, cursor, cursor_ids=seen_at_cursor
            ):
                prep = self._prepare_upsert_item(obj_type, item, state)
                mod = item.get("modified") or ""
                sid = str(item.get("standard_id") or "")
                count += 1
                if prep.skip:
                    if prep.skip_reason:
                        self.helper.connector_logger.info(
                            f"[{obj_type}] skip upsert for {sid or item.get('standard_id')} "
                            f"(name={item.get('name')}) — {prep.skip_reason}"
                        )
                    if prep.retryable:
                        # Read/API failures must remain retryable — do not advance.
                        retryable_skips += 1
                        continue
                    # Intentional skips (e.g. analyst lock) are checkpointed.
                    advance_checkpoint(mod, sid)
                    skipped_user_edit += 1
                    continue
                sdo = self._upsert_sdo_from_prep(obj_type, prep)
                if sdo is None:
                    conversion_failures += 1
                    self.helper.connector_logger.warning(
                        f"[{obj_type}] failed to build SDO for {sid or item.get('standard_id')} "
                        f"(name={item.get('name')}); cursor will not advance past "
                        "failed conversions"
                    )
                    continue
                advance_checkpoint(mod, sid)
                stix_objects.append(sdo)
                batch_item_count += 1
                if sid:
                    pushed_standard_ids.append(sid)
                    pushed_api_items.append(prep.api_item)

                cb = item.get("createdBy") or {}
                cb_id = cb.get("standard_id")
                if cb_id:
                    if cb_id not in identity_by_id:
                        identity_by_id[cb_id] = self.converter.build_identity(cb)
                    identity = identity_by_id[cb_id]
                    if identity is not None and cb_id not in seen_identities:
                        stix_objects.append(identity)
                        seen_identities[cb_id] = True
                        batch_item_count += 1

                if count % 100 == 0:
                    self.helper.connector_logger.info(
                        f"[{obj_type}] converted {count} object(s) so far"
                    )

                if batch_item_count >= batch_size and not flush_batch():
                    self.helper.connector_logger.warning(
                        f"[{obj_type}] OpenCTI push failed; "
                        f"cursor not advanced (will retry on next cycle)"
                    )
                    return False
        except Exception as ex:
            self.helper.connector_logger.error(
                f"[{obj_type}] fetch failed: {ex}\n{traceback.format_exc()}"
            )
            return False

        if skipped_user_edit:
            self.helper.connector_logger.info(
                f"[{obj_type}] skipped {skipped_user_edit} object(s) "
                "(analyst confidence lock)"
            )

        if not flush_batch():
            self.helper.connector_logger.warning(
                f"[{obj_type}] OpenCTI push failed; "
                f"cursor not advanced (will retry on next cycle)"
            )
            return False

        if conversion_failures or retryable_skips:
            self.helper.connector_logger.warning(
                f"[{obj_type}] "
                f"{conversion_failures} conversion failure(s), "
                f"{retryable_skips} retryable skip(s); "
                "cursor not advanced so failed items remain retryable"
            )
            return False

        if any_pushed:
            state[cursor_key] = latest or cursor
            state[cursor_ids_key] = sorted(latest_ids)
            self._persist_state(state)
            self.helper.connector_logger.info(
                f"[{obj_type}] ingested {count} object(s), cursor now "
                f"{state[cursor_key] or '(none)'}"
            )
        elif count:
            state[cursor_key] = latest or cursor
            state[cursor_ids_key] = sorted(latest_ids)
            self._persist_state(state)
            self.helper.connector_logger.info(
                f"[{obj_type}] no new objects this cycle "
                f"(cursor advanced after {count} skipped)"
            )
        else:
            self.helper.connector_logger.info(f"[{obj_type}] no new objects this cycle")
        return True

    def _item_to_sdo(self, item: Dict[str, Any], obj_type_path: str):
        return self.converter.item_to_sdo(item, obj_type_path, self._sync_labels)

    def _batch_send(
        self, stix_objects: List[Any], timestamp: int, obj_type: str
    ) -> bool:
        if not stix_objects:
            return True
        batch_size = self._opencti_batch_size
        if len(stix_objects) <= batch_size:
            return self._batch_send_stix_bundle(stix_objects, timestamp, obj_type)

        identities, rest = self._partition_identities(stix_objects)
        if not rest:
            total_chunks = (len(identities) + batch_size - 1) // batch_size
            for chunk_idx, offset in enumerate(range(0, len(identities), batch_size)):
                chunk = identities[offset : offset + batch_size]
                self.helper.connector_logger.info(
                    f"[{obj_type}] OpenCTI push chunk "
                    f"{chunk_idx + 1}/{total_chunks} "
                    f"({len(chunk)} object(s))"
                )
                if not self._batch_send_stix_bundle(chunk, timestamp, obj_type):
                    return False
            return True

        # Keep each SDO chunk self-contained for cleanup_inconsistent_bundle:
        # re-attach all referenced identities to every emitted chunk.
        sdo_chunk_size = (
            max(1, batch_size - len(identities)) if identities else batch_size
        )
        total_chunks = (len(rest) + sdo_chunk_size - 1) // sdo_chunk_size
        for chunk_idx, offset in enumerate(range(0, len(rest), sdo_chunk_size)):
            chunk = identities + rest[offset : offset + sdo_chunk_size]
            self.helper.connector_logger.info(
                f"[{obj_type}] OpenCTI push chunk "
                f"{chunk_idx + 1}/{total_chunks} "
                f"({len(chunk)} object(s))"
            )
            if not self._batch_send_stix_bundle(chunk, timestamp, obj_type):
                return False
        return True

    def _sleep_before_retry(self, delay_s: int) -> int:
        """Sleep at least 1s between OpenCTI push retries, then return next delay."""
        sleep_s = max(_OPENCTI_RETRY_MIN_DELAY_S, int(delay_s))
        self.helper.connector_logger.info(f"Retrying in {sleep_s} seconds...")
        time.sleep(sleep_s)
        next_delay = int(sleep_s * self._retry_backoff_multiplier) or sleep_s
        return max(_OPENCTI_RETRY_MIN_DELAY_S, next_delay)

    @staticmethod
    def _is_retryable_upload_error(exc: BaseException) -> bool:
        return isinstance(
            exc,
            (
                ConnectionError,
                OSError,
                TimeoutError,
                requests.exceptions.RequestException,
            ),
        )

    def _mark_work_failed(
        self, work_id: Optional[str], obj_type: str, exc: BaseException
    ) -> None:
        if not work_id:
            return
        try:
            self.helper.api.work.to_processed(
                work_id,
                f"[{obj_type}] upload failed: {exc}",
                in_error=True,
            )
        except Exception as close_ex:
            self.helper.connector_logger.warning(
                f"[{obj_type}] failed to mark work {work_id} in_error: {close_ex}"
            )

    def _batch_send_stix_bundle(
        self, stix_objects: List[Any], timestamp: int, obj_type: str
    ) -> bool:
        stix_objects = self._with_tlp_marking(stix_objects)
        self.helper.connector_logger.debug(
            f"[{obj_type}] start uploading {len(stix_objects)} object(s) "
            f"(mode=bundle)"
        )

        # SDK processors inject WorkManager-backed send (preferred path).
        if self._send_bundle is not None:
            return self._send_bundle_with_retries(stix_objects, obj_type)

        now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        friendly_name = (
            f"RST Threat Library [{obj_type}] @ " f"{now.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        max_retries = max(1, int(self._max_retries))
        retry_delay = self._retry_delay

        for attempt in range(max_retries):
            work_id: Optional[str] = None
            try:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.helper.send_stix2_bundle(
                    self.helper.stix2_create_bundle(stix_objects),
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                self.helper.connector_logger.info(
                    f"[{obj_type}] sent bundle of {len(stix_objects)} object(s)"
                )
                self.helper.api.work.to_processed(
                    work_id,
                    f"Sent bundle of {len(stix_objects)} object(s) for {obj_type}",
                )
                return True

            except Exception as ex:
                self._mark_work_failed(work_id, obj_type, ex)
                if self._is_retryable_upload_error(ex):
                    self.helper.connector_logger.error(
                        f"[{obj_type}] push attempt {attempt + 1}/{max_retries} "
                        f"failed: {ex}"
                    )
                    if attempt < max_retries - 1:
                        retry_delay = self._sleep_before_retry(retry_delay)
                        continue
                    self.helper.connector_logger.error(
                        f"[{obj_type}] failed to upload bundle after "
                        f"{max_retries} attempts."
                    )
                    return False

                error_message = f"[{obj_type}] unexpected error during upload: {ex}"
                self.helper.connector_logger.error(error_message)
                raise

        return False

    def _send_bundle_with_retries(self, stix_objects: List[Any], obj_type: str) -> bool:
        """Push via injected WorkManager send with the connector retry policy."""
        if self._send_bundle is None:
            raise RuntimeError(
                "SDK WorkManager send hook is not configured (_send_bundle)"
            )
        send_bundle = self._send_bundle
        max_retries = max(1, int(self._max_retries))
        retry_delay = self._retry_delay

        for attempt in range(max_retries):
            try:
                return bool(send_bundle(stix_objects, obj_type))
            except Exception as ex:
                if self._is_retryable_upload_error(ex):
                    self.helper.connector_logger.error(
                        f"[{obj_type}] push attempt {attempt + 1}/{max_retries} "
                        f"failed: {ex}"
                    )
                    if attempt < max_retries - 1:
                        retry_delay = self._sleep_before_retry(retry_delay)
                        continue
                    self.helper.connector_logger.error(
                        f"[{obj_type}] failed to upload bundle after "
                        f"{max_retries} attempts."
                    )
                    return False
                error_message = f"[{obj_type}] unexpected error during upload: {ex}"
                self.helper.connector_logger.error(error_message)
                raise
        return False

    def _with_tlp_marking(self, stix_objects: List[Any]) -> List[Any]:
        """Include the configured TLP marking definition in the bundle."""
        marking = self.converter.tlp_marking
        marking_id = getattr(marking, "id", None)
        if any(self._stix_type_and_id(obj)[1] == marking_id for obj in stix_objects):
            return stix_objects
        return [marking, *stix_objects]

    @staticmethod
    def _stix_type_and_id(obj: Any) -> Tuple[Optional[str], Optional[str]]:
        obj_type = getattr(obj, "type", None)
        obj_id = getattr(obj, "id", None)
        if isinstance(obj_type, str) and obj_type:
            return obj_type, str(obj_id) if obj_id else None
        try:
            payload = json.loads(obj.serialize())
        except Exception:
            return None, None
        if not isinstance(payload, dict):
            return None, None
        oid = payload.get("id")
        return payload.get("type"), str(oid) if oid else None

    @staticmethod
    def _partition_identities(
        stix_objects: List[Any],
    ) -> Tuple[List[Any], List[Any]]:
        identities: List[Any] = []
        rest: List[Any] = []
        seen_identity: Dict[str, bool] = {}
        for obj in stix_objects:
            obj_type, oid = RSTThreatLibrary._stix_type_and_id(obj)
            if obj_type == "identity":
                if oid and oid not in seen_identity:
                    seen_identity[oid] = True
                    identities.append(obj)
            else:
                rest.append(obj)
        return identities, rest
