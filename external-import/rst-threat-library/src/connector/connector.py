import json
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from pycti import OpenCTIConnectorHelper, get_config_variable

from connector.confidence import (
    confidence_value,
    make_sync_record,
    upstream_confidence_from_record,
)
from connector.converter_to_stix import ConverterToStix
from connector.merge_split import (
    MergeCandidate,
    SplitCandidate,
    analyze_intrusion_set_merge_split,
    identifiers_from_api_item,
    identifiers_from_opencti,
    pick_opencti_merge_survivor,
)
from connector.settings import ConnectorSettings
from connector.utils import ThreatObjectType
from rst_threat_library_client import ThreatLibraryClient

_OPENCTI_MERGE_SOURCE_BATCH = 3
_SPLIT_FAILURE_SKIP_THRESHOLD = 3
_SPLIT_FAILURES_STATE_KEY = "split_failures"
_MERGE_SURVIVOR_READ_ATTEMPTS = 8
_MERGE_SURVIVOR_READ_DELAY_S = 2.0


@dataclass
class UpsertPrep:
    skip: bool
    api_item: Dict[str, Any]
    opencti_entity: Optional[Dict[str, Any]] = None
    skip_reason: str = ""


class RSTThreatLibrary:
    def __init__(
        self, *, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper
        self.converter = ConverterToStix(helper=self.helper)

        tl = self.config.rst_threat_library

        self.object_types = [str(t).strip() for t in tl.object_types if str(t).strip()]
        self.import_from_date = tl.import_from_date or ""

        self._client_config = {
            "baseurl": str(tl.baseurl),
            "apikey": tl.apikey,
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

        _push = (tl.opencti_push_mode or "bundle").strip().lower()
        self.opencti_push_mode = _push if _push in ("bundle", "api") else "bundle"

        self._sync_labels = [str(x).strip() for x in tl.sync_labels if str(x).strip()]
        self._reconcile_exclude_labels = [
            str(x).strip() for x in tl.reconcile_exclude_labels if str(x).strip()
        ]
        self._reconcile_allow_created_by = [
            str(x).strip() for x in tl.reconcile_allow_created_by if str(x).strip()
        ]

        self.update_existing_data = bool(
            get_config_variable(
                "CONNECTOR_UPDATE_EXISTING_DATA",
                ["connector", "update_existing_data"],
                self.config.to_helper_config(),
                default=True,
            )
        )

        self.merge_split_enabled = bool(tl.merge_split)
        self.respect_user_edits = bool(tl.respect_user_edits)
        self._intrusion_set_default_confidence = tl.intrusion_set_default_confidence

    def _seed_cursor(self) -> str:
        s = (self.import_from_date or "").strip()
        if not s:
            return ""
        try:
            datetime.strptime(s, "%Y-%m-%d")
        except ValueError:
            return ""
        return f"{s}T00:00:00.000Z"

    def _publish_connector_info(self, *, mark_last_run: bool) -> None:
        """Populate OpenCTI connector status fields and push them to the UI.

        """
        helper = self.helper
        try:
            duration_period_s = self.config.connector.duration_period.total_seconds()

            try:
                helper.check_connector_buffering()
            except Exception:
                helper.connector_info.queue_threshold = float(
                    helper.connect_queue_threshold
                )

            if mark_last_run:
                helper.last_run_datetime()
            helper.next_run_datetime(duration_period_s)
            helper.force_ping()
        except Exception as ex:
            helper.connector_logger.warning(
                f"Failed to publish connector status to OpenCTI UI: {ex}"
            )

    def process_message(self) -> None:
        timestamp = int(time.time())

        self._publish_connector_info(mark_last_run=True)

        current_state = self.helper.get_state() or {}
        self._cycle(current_state, timestamp)

        self._publish_connector_info(mark_last_run=True)

        if self.helper.connect_run_and_terminate:
            self.helper.connector_logger.info("Connector stopped")
            self.helper.force_ping()
            sys.exit(0)

    def run(self) -> None:
        self.helper.connector_logger.info("Starting RST Threat Library connector")
        self.helper.connector_logger.info(
            f"OpenCTI push mode: {self.opencti_push_mode} "
            f"(CONNECTOR_UPDATE_EXISTING_DATA={self.update_existing_data})"
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
            f"Intrusion-set merge/split at import: enabled={self.merge_split_enabled}"
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
                "Intrusion-set duplicates use OpenCTI stix.merge (relationships, "
                "sightings, notes preserved); merge/split runs after delta import."
            )

        duration_period_s = self.config.connector.duration_period.total_seconds()
        self.helper.connector_logger.info(
            f"Scheduled execution period: {duration_period_s}s"
        )
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=duration_period_s,
        )

    def _cycle(self, state: Dict[str, Any], timestamp: int) -> None:
        seed = self._seed_cursor()
        client = ThreatLibraryClient(
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

        for obj_type in self.object_types:
            self._cycle_type(client, obj_type, state, timestamp, seed)

        if self.merge_split_enabled:
            self._apply_intrusion_set_merge_split(client, state, timestamp)

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

        opencti_entity = self._read_opencti_entity(obj_type_path, sid)
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
        api = self.helper.api
        try:
            if obj_type_path == ThreatObjectType.INTRUSION_SETS:
                return api.intrusion_set.read(id=standard_id)
            if obj_type_path == ThreatObjectType.MALWARE:
                return api.malware.read(id=standard_id)
            if obj_type_path == ThreatObjectType.TOOLS:
                return api.tool.read(id=standard_id)
            if obj_type_path == ThreatObjectType.CAMPAIGNS:
                return api.campaign.read(id=standard_id)
        except Exception as ex:
            self.helper.connector_logger.debug(
                f"[{obj_type_path}] read {standard_id} for confidence check: {ex}"
            )
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
        """Read an entity, retrying while bundle-mode workers run."""
        if not standard_id:
            return None

        entity = self._read_opencti_entity(obj_type_path, standard_id)
        if entity:
            return entity

        for attempt in range(1, max(attempts, 1)):
            self.helper.connector_logger.info(
                f"[{obj_type_path}] {context}: waiting for {standard_id} "
                f"in OpenCTI (attempt {attempt}/{attempts - 1}, "
                f"delay={delay_s:.1f}s)"
            )
            time.sleep(delay_s)
            entity = self._read_opencti_entity(obj_type_path, standard_id)
            if entity:
                self.helper.connector_logger.info(
                    f"[{obj_type_path}] {context}: {standard_id} readable after "
                    f"wait (attempt {attempt}/{attempts - 1})"
                )
                return entity
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
        """Intrusion sets to compare with the API catalogue for merge/split.

        """
        managed = set((state.get("managed_ids") or {}).get(obj_type_path, []))
        api_idents: Set[str] = set()
        if api_items:
            for item in api_items:
                api_idents |= set(identifiers_from_api_item(item))

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
            elif api_idents and (set(identifiers_from_opencti(entity)) & api_idents):
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
            self.helper.set_state(state)

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
            self.helper.set_state(state)
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
                f"[{obj_type}] split: intrusion set skipped "
                f"{oc_sid} (name={oc.get('name')}) — abandoned after "
                f"{count} consecutive failures ({reason})"
            )
        else:
            self.helper.connector_logger.info(
                f"[{obj_type}] split: skip {oc_sid} (name={oc.get('name')}) — "
                f"{reason} (failure {count}/{_SPLIT_FAILURE_SKIP_THRESHOLD})"
            )
        self.helper.set_state(state)

    def _apply_intrusion_set_merge_split(
        self,
        client: ThreatLibraryClient,
        state: Dict[str, Any],
        timestamp: int,
    ) -> None:
        """Run merge/split after import against OpenCTI entities."""
        obj_type = ThreatObjectType.INTRUSION_SETS
        try:
            api_items = list(client.iter_all_items(obj_type))
        except Exception as ex:
            self.helper.connector_logger.error(
                f"[{obj_type}] merge/split catalogue fetch failed: {ex}\n"
                f"{traceback.format_exc()}"
            )
            return

        opencti_entities = self._opencti_entities_for_merge_split(
            obj_type, state, api_items=api_items
        )
        plan = analyze_intrusion_set_merge_split(api_items, opencti_entities)

        if not plan.splits and not plan.merges:
            self.helper.connector_logger.info(
                f"[{obj_type}] merge/split: no candidates "
                f"(api={len(api_items)}, opencti_scoped={len(opencti_entities)})"
            )
            return

        self.helper.connector_logger.info(
            f"[{obj_type}] merge/split: {len(plan.splits)} split(s), "
            f"{len(plan.merges)} merge(s)"
        )

        for split in plan.splits:
            self._execute_intrusion_set_split(split, timestamp, obj_type, state)

        for merge in plan.merges:
            self._execute_intrusion_set_merge(merge, timestamp, obj_type, state)

    def _execute_intrusion_set_split(
        self,
        split: SplitCandidate,
        timestamp: int,
        obj_type: str,
        state: Dict[str, Any],
    ) -> None:
        oc = split.opencti_entity
        oid = oc.get("id")
        oc_sid = oc.get("standard_id")
        if not oid or not oc_sid:
            return

        if self._should_skip_split_after_failures(split, obj_type, state):
            self.helper.connector_logger.debug(
                f"[{obj_type}] split: intrusion set skipped {oc_sid} "
                f"(name={oc.get('name')}) — previously abandoned"
            )
            return

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
                reason=(
                    "OpenCTI confidence exceeds Threat Library (analyst lock)"
                ),
            )
            return

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
                return

        stix_objects: List[Any] = []
        seen_identities: Dict[str, bool] = {}
        pushed: List[str] = []

        refresh_items: List[Dict[str, Any]] = []
        if split.keep_api_item:
            refresh_items.append(split.keep_api_item)
        refresh_items.extend(split.split_off_api_items)

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
                continue
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

        if stix_objects and self._batch_send(stix_objects, timestamp, obj_type):
            self._record_sync_state(state, obj_type, pushed_items)
            managed = state.setdefault("managed_ids", {})
            cur = set(managed.get(obj_type, []))
            cur.update(pushed)
            managed[obj_type] = sorted(cur)
            self._clear_split_failure(state, obj_type, oc_sid)
            self.helper.set_state(state)
        elif not stix_objects and not split.aliases_to_remove:
            self._record_split_failure(
                split,
                obj_type,
                state,
                reason="no upsertable split-off items",
            )
        else:
            self._clear_split_failure(state, obj_type, oc_sid)

    def _opencti_fusion_merge_intrusion_sets(
        self,
        target_entity: Dict[str, Any],
        source_entities: List[Dict[str, Any]],
        obj_type: str,
        state: Dict[str, Any],
    ) -> List[str]:
        """Fuse duplicate intrusion sets into target via OpenCTI UI merge."""
        target_internal_id = target_entity.get("id")
        target_sid = target_entity.get("standard_id")
        if not target_internal_id or not target_sid:
            return []

        source_sids: List[str] = []
        for src in source_entities:
            src_sid = src.get("standard_id")
            if not src_sid or src_sid == target_sid:
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
            source_sids.append(src_sid)

        if not source_sids:
            return []

        merged: List[str] = []
        for offset in range(0, len(source_sids), _OPENCTI_MERGE_SOURCE_BATCH):
            chunk = source_sids[offset : offset + _OPENCTI_MERGE_SOURCE_BATCH]
            try:
                self.helper.api.stix.merge(
                    id=target_internal_id,
                    object_ids=chunk,
                )
                merged.extend(chunk)
                self.helper.connector_logger.info(
                    f"[{obj_type}] OpenCTI merge: fused {chunk} into "
                    f"{target_sid} (name={target_entity.get('name')})"
                )
            except Exception as ex:
                self.helper.connector_logger.error(
                    f"[{obj_type}] OpenCTI merge failed for sources {chunk} "
                    f"into {target_sid}: {ex}"
                )
        return merged

    def _execute_intrusion_set_merge(
        self,
        merge: MergeCandidate,
        timestamp: int,
        obj_type: str,
        state: Dict[str, Any],
    ) -> None:
        stix_objects: List[Any] = []
        seen_identities: Dict[str, bool] = {}
        pushed: List[str] = []

        item = merge.target_api_item
        target_sid = item.get("standard_id")

        score_candidates: List[Dict[str, Any]] = list(
            merge.opencti_entities_to_merge
        )
        if target_sid:
            existing_api_entity = self._read_opencti_entity(obj_type, target_sid)
            if existing_api_entity:
                score_candidates.append(existing_api_entity)

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
            return

        if survivor_pushed:
            self._record_sync_state(state, obj_type, survivor_pushed)

        if not target_sid:
            return

        api_target = self._wait_for_opencti_entity(
            obj_type,
            target_sid,
            context="merge",
        )
        if not api_target and survivor_prep.opencti_entity:
            api_target = survivor_prep.opencti_entity
            self.helper.connector_logger.warning(
                f"[{obj_type}] merge: using cached OpenCTI entity for "
                f"{target_sid} after post-upsert read miss"
            )

        fusion_target: Optional[Dict[str, Any]] = None
        if preferred_survivor_sid and preferred_survivor_sid != target_sid:
            preferred_live = self._wait_for_opencti_entity(
                obj_type,
                preferred_survivor_sid,
                context="merge preferred survivor",
            )
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
            return

        fusion_target_sid = fusion_target.get("standard_id")
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
            return

        source_by_sid: Dict[str, Dict[str, Any]] = {}
        for src in merge.opencti_entities_to_merge:
            src_sid = src.get("standard_id")
            if src_sid and src_sid != fusion_target_sid:
                source_by_sid[src_sid] = src
        if target_sid != fusion_target_sid and api_target:
            source_by_sid[target_sid] = api_target

        merged_sids = self._opencti_fusion_merge_intrusion_sets(
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
        self.helper.set_state(state)

    def _cycle_type(
        self,
        client: ThreatLibraryClient,
        obj_type: str,
        state: Dict[str, Any],
        timestamp: int,
        seed: str,
    ) -> None:
        cursor_key = f"cursor_{obj_type}"
        cursor = state.get(cursor_key) or seed
        self.helper.connector_logger.info(
            f"[{obj_type}] cycle start (cursor={cursor or '(none)'})"
        )

        stix_objects: List[Any] = []
        seen_identities: Dict[str, bool] = {}
        pushed_standard_ids: List[str] = []
        pushed_api_items: List[Dict[str, Any]] = []
        latest = cursor
        count = 0
        skipped_user_edit = 0

        try:
            for item in client.iter_new_items(obj_type, cursor):
                prep = self._prepare_upsert_item(obj_type, item, state)
                mod = item.get("modified") or ""
                if mod and (not latest or mod > latest):
                    latest = mod
                count += 1
                if prep.skip:
                    skipped_user_edit += 1
                    if prep.skip_reason:
                        sid = item.get("standard_id")
                        self.helper.connector_logger.info(
                            f"[{obj_type}] skip upsert for {sid} "
                            f"(name={item.get('name')}) — {prep.skip_reason}"
                        )
                    continue
                sdo = self._upsert_sdo_from_prep(obj_type, prep)
                if sdo is None:
                    continue
                stix_objects.append(sdo)
                sid = item.get("standard_id")
                if sid:
                    pushed_standard_ids.append(sid)
                    pushed_api_items.append(prep.api_item)

                cb = item.get("createdBy") or {}
                cb_id = cb.get("standard_id")
                if cb_id and cb_id not in seen_identities:
                    identity = self.converter.build_identity(cb)
                    if identity is not None:
                        stix_objects.append(identity)
                        seen_identities[cb_id] = True

                if count % 100 == 0:
                    self.helper.connector_logger.info(
                        f"[{obj_type}] converted {count} object(s) so far"
                    )
        except Exception as ex:
            self.helper.connector_logger.error(
                f"[{obj_type}] fetch failed: {ex}\n{traceback.format_exc()}"
            )
            return

        if skipped_user_edit:
            self.helper.connector_logger.info(
                f"[{obj_type}] skipped {skipped_user_edit} object(s) "
                "(analyst confidence lock)"
            )

        if not stix_objects:
            if count:
                state[cursor_key] = latest or cursor
                self.helper.set_state(state)
            self.helper.connector_logger.info(f"[{obj_type}] no new objects this cycle")
        else:
            ok = self._batch_send(stix_objects, timestamp, obj_type)
            if ok:
                self._record_sync_state(state, obj_type, pushed_api_items)
                state[cursor_key] = latest or cursor
                managed = state.setdefault("managed_ids", {})
                cur = set(managed.get(obj_type, []))
                cur.update(pushed_standard_ids)
                managed[obj_type] = sorted(cur)
                self.helper.set_state(state)
                self.helper.connector_logger.info(
                    f"[{obj_type}] ingested {count} object(s), cursor now "
                    f"{state[cursor_key] or '(none)'}"
                )
            else:
                self.helper.connector_logger.warning(
                    f"[{obj_type}] OpenCTI push failed ({self.opencti_push_mode}); "
                    f"cursor not advanced (will retry on next cycle)"
                )
                return

    def _item_to_sdo(self, item: Dict[str, Any], obj_type_path: str):
        return self.converter.item_to_sdo(item, obj_type_path, self._sync_labels)

    def _batch_send(
        self, stix_objects: List[Any], timestamp: int, obj_type: str
    ) -> bool:
        if self.opencti_push_mode == "api":
            return self._batch_send_via_api(stix_objects, timestamp, obj_type)
        return self._batch_send_stix_bundle(stix_objects, timestamp, obj_type)

    def _batch_send_stix_bundle(
        self, stix_objects: List[Any], timestamp: int, obj_type: str
    ) -> bool:
        now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        friendly_name = (
            f"RST Threat Library [{obj_type}] @ " f"{now.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.helper.connector_logger.debug(
            f"[{obj_type}] start uploading {len(stix_objects)} object(s) "
            f"(mode=bundle)"
        )

        max_retries = self._max_retries
        retry_delay = self._retry_delay

        for attempt in range(max_retries):
            try:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.helper.send_stix2_bundle(
                    self.helper.stix2_create_bundle(stix_objects),
                    update=self.update_existing_data,
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

            except (ConnectionError, OSError, TimeoutError) as ex:
                self.helper.connector_logger.error(
                    f"[{obj_type}] push attempt {attempt + 1}/{max_retries} "
                    f"failed: {ex}"
                )
                if attempt < max_retries - 1:
                    self.helper.connector_logger.info(
                        f"Retrying in {retry_delay} seconds..."
                    )
                    time.sleep(retry_delay)
                    retry_delay = (
                        int(retry_delay * self._retry_backoff_multiplier) or retry_delay
                    )
                else:
                    self.helper.connector_logger.error(
                        f"[{obj_type}] failed to upload bundle after "
                        f"{max_retries} attempts."
                    )
                    return False

            except Exception as ex:
                error_message = f"[{obj_type}] unexpected error during upload: {ex}"
                self.helper.connector_logger.error(error_message)
                raise ConnectionError(error_message) from ex

        return False

    @staticmethod
    def _stix_objects_to_api_order(stix_objects: List[Any]) -> List[Any]:
        """Import identities before SDOs that reference created_by_ref."""
        identities: List[Any] = []
        rest: List[Any] = []
        seen_identity: Dict[str, bool] = {}
        for obj in stix_objects:
            d = json.loads(obj.serialize())
            if d.get("type") == "identity":
                oid = d.get("id")
                if oid and oid not in seen_identity:
                    seen_identity[oid] = True
                    identities.append(obj)
            else:
                rest.append(obj)
        return identities + rest

    def _batch_send_via_api(
        self, stix_objects: List[Any], timestamp: int, obj_type: str
    ) -> bool:
        now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        friendly_name = (
            f"RST Threat Library [{obj_type}] API @ "
            f"{now.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        ordered = self._stix_objects_to_api_order(stix_objects)
        self.helper.connector_logger.debug(
            f"[{obj_type}] start API import of {len(ordered)} object(s) "
            f"(update_existing={self.update_existing_data})"
        )

        max_retries = self._max_retries
        retry_delay = self._retry_delay

        for attempt in range(max_retries):
            try:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                for obj in ordered:
                    data = json.loads(obj.serialize())
                    self.helper.api.stix2.import_object(
                        data, update=self.update_existing_data
                    )
                self.helper.connector_logger.info(
                    f"[{obj_type}] API-imported {len(ordered)} object(s)"
                )
                self.helper.api.work.to_processed(
                    work_id,
                    f"API-imported {len(ordered)} object(s) for {obj_type}",
                )
                return True

            except (ConnectionError, OSError, TimeoutError) as ex:
                self.helper.connector_logger.error(
                    f"[{obj_type}] API push attempt {attempt + 1}/{max_retries} "
                    f"failed: {ex}"
                )
                if attempt < max_retries - 1:
                    self.helper.connector_logger.info(
                        f"Retrying in {retry_delay} seconds..."
                    )
                    time.sleep(retry_delay)
                    retry_delay = (
                        int(retry_delay * self._retry_backoff_multiplier) or retry_delay
                    )
                else:
                    self.helper.connector_logger.error(
                        f"[{obj_type}] failed API import after {max_retries} attempts."
                    )
                    return False

            except Exception as ex:
                error_message = f"[{obj_type}] unexpected error during API import: {ex}"
                self.helper.connector_logger.error(error_message)
                raise ConnectionError(error_message) from ex

        return False
