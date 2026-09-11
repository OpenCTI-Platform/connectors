"""
ThreatFox connector (STIX-bundle ingestion + API post-pass for observable external references)

- Ingests via STIX bundle.
    - Same behaviour as before: process as bundles
- STRICT REQUIREMENT: external reference is ONLY the 12th CSV column ('reference') exactly as provided by the API.
    - We don't want to mistake malicious domains as a clickable reference!!
- Adds external references to Indicator & Malware in STIX.
- After bundle ingestion, attaches the same external reference to the Observable via OpenCTI API.
    - A limitation of the bundle approach. It does not allow you to append references on creation. Has to be done using the API.
- Maps ThreatFox confidence_level (0-100) to x_opencti_score on Observables & Indicators.
    - Fixes the "fixed score" issue. Now it reflects what Abuse.ch is saying.
- Creates Observable --related-to--> Malware family (is_family=True) for graph linkage even without indicators.
"""

from __future__ import annotations

import csv
import io
import os
import ssl
import sys
import time
import traceback
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Dict, Iterable, List, Optional, Tuple, Union

import stix2
from pycti import (
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from stix2.base import _Observable as Observable

from src.models.configs.config_loader import ConfigLoader


ALL_TYPES = "all_types"
BASE_PATH = os.path.dirname(os.path.abspath(__file__))


# pylint:disable=too-many-instance-attributes
class ThreatFox:
    """ThreatFox connector (STIX bundle ingestion with post-attach of refs to SCOs)"""

    def __init__(self):
        """Initializer"""

        # Instantiate the connector helper from config
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(config=self.config.model_dump_pycti())

        # ThreatFox config
        self.threatfox_csv_url = self.config.threatfox.csv_url
        self.threatfox_import_offline = self.config.threatfox.import_offline
        self.threatfox_interval = self.config.threatfox.interval
        self.create_indicators = self.config.threatfox.create_indicators
        self.default_x_opencti_score = self.config.threatfox.default_x_opencti_score
        self.x_opencti_score_ip = self.config.threatfox.x_opencti_score_ip
        self.x_opencti_score_domain = self.config.threatfox.x_opencti_score_domain
        self.x_opencti_score_url = self.config.threatfox.x_opencti_score_url
        self.x_opencti_score_hash = self.config.threatfox.x_opencti_score_hash

        self.ioc_to_import = [
            ioc.strip() for ioc in self.config.threatfox.ioc_to_import.split(",") if ioc.strip()
        ]
        if len(self.ioc_to_import) == 0:
            self.ioc_to_import = [ALL_TYPES]

        # Producer identity
        self.identity: Dict = self.helper.api.identity.create(
            type="Organization",
            name="Threat Fox | Abuse.ch",
            description=(
                "abuse.ch is operated by a random swiss guy fighting malware for non-profit, "
                "running a couple of projects helping internet service providers and network operators "
                "protecting their infrastructure from malware."
            ),
        )
        # Prefer a STIX id for created_by_ref; fallback if needed
        self.identity_id = self.identity.get("standard_id") or self.identity["id"]

        # Pending observables to process post-ingestion (external refs + relationships)
        # Each item: {
        #   "entity_type": str, "value": str, "hash_field": Optional[str],
        #   "urls": List[str], "indicator_id": Optional[str], "stix_id": str,
        #   "malware_stix_id": Optional[str], "confidence": Optional[int]
        # }
        self._pending_observables: List[Dict] = []

        # Cache to reduce ext-ref recreation during the post-pass
        self._cache_ext_ref_ids: Dict[str, str] = {}

        # Optional extra delay (seconds) before post-pass to allow indexing to settle
        try:
            self.postpass_delay = float(os.getenv("THREATFOX_POSTPASS_DELAY_SEC", "5"))
        except Exception:
            self.postpass_delay = 5.0

    # ------------------------ Utility & config ------------------------ #
    def get_interval(self) -> float:
        """Convert the threatfox_interval (days) to seconds"""
        return float(self.threatfox_interval) * 60 * 60 * 24

    # ----------------------------- Run/Loop --------------------------- #
    def run(self):
        """Run the connector loop."""
        while True:
            try:
                self.loop()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception:  # pylint:disable=broad-exception-caught
                self.helper.log_error(traceback.format_exc())

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)

    def loop(self) -> None:
        """Main connector loop."""
        now_dt = datetime.now(UTC)
        now_ts = now_dt.timestamp()
        state = self.helper.get_state()
        if state is None:
            state = {}

        last_run_ts = state.get("last_run")
        if last_run_ts is None:
            self.helper.log_info("Connector has never run")
            last_run_ts = 0
        else:
            last_run_dt = datetime.fromtimestamp(last_run_ts, UTC)
            self.helper.log_info(f"Connector last run: {last_run_dt}")

        next_dt = datetime.fromtimestamp(now_ts + self.get_interval(), UTC)
        if (now_ts - last_run_ts) >= self.get_interval():
            self.helper.log_info("Connector will run!")
            self.import_data(state, now_dt, now_ts)
            self.helper.log_info(f"Last_run stored, next run in: {next_dt - now_dt}")
        else:
            self.helper.log_info(
                f"Connector will not run, next run in: {next_dt - now_dt}"
            )

    # -------------------------- Import pipeline ----------------------- #
    def import_data(self, state: Dict, now_dt: datetime, now_ts: int) -> None:
        """Pull and import ThreatFox data via STIX; then post-attach external refs to SCOs."""

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            "Threat Fox run @ " + now_dt.strftime("%Y-%m-%d %H:%M:%S"),
        )

        csv.register_dialect("custom", delimiter=",", quotechar='"', skipinitialspace=True)

        last_processed_entry_running_max = 0

        try:
            lines = self.download_csv()
            csv_reader = csv.reader(lines, dialect="custom")

            bundle_objects: List[stix2._STIXBase] = []

            last_processed_entry = state.get("last_processed_entry")  # epoch
            if last_processed_entry is None:
                self.helper.log_info(
                    "'last_processed_entry' state not found, setting it to epoch start."
                )
                last_processed_entry = 0

            last_processed_entry_running_max = last_processed_entry

            # reset per run
            self._pending_observables = []
            self._cache_ext_ref_ids = {}

            for i, row in enumerate(csv_reader):
                if len(row) > 15:
                    self.helper.log_info(
                        f"The csv line is badly formatted and will be ignored.(line: {i}, data: {row})"
                    )
                    continue
                ioc = FeedRow(row)

                # skip unwanted IOC types
                if ALL_TYPES not in self.ioc_to_import:
                    if ioc.type not in self.ioc_to_import:
                        self.helper.log_info(f"Unwanted ioc_type skipped: {ioc.type}")
                        continue

                # occasional logging
                if i % 5000 == 0:
                    self.helper.log_info(
                        f"Processing entry {i} with dateadded='{ioc.first_seen}'"
                    )

                # skip entry if newer events already processed in the past
                if last_processed_entry > ioc.first_seen.timestamp():
                    continue

                # update the running max
                last_processed_entry_running_max = max(
                    ioc.first_seen.timestamp(),
                    last_processed_entry_running_max,
                )

                if not self.threatfox_import_offline:
                    if not ioc.last_seen or ioc.last_seen < now_dt:
                        self.helper.log_info(f"Skipping offline IOC: {ioc.value}")
                        continue

                # ---- STIX creation path ----
                for obj in self.process_row(ioc):
                    bundle_objects.append(obj)

            # Build and send bundle
            bundle = stix2.Bundle(
                objects=bundle_objects,
                allow_custom=True,
            ).serialize()

            self.helper.log_debug(bundle)
            if "objects" in bundle:
                self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                )

            # ---- delay before post-pass (tunable) ----
            if self.postpass_delay > 0:
                self.helper.log_info(f"[ThreatFox] sleeping {self.postpass_delay:.1f}s before post-pass attach")
                time.sleep(self.postpass_delay)

            # ---- 2nd pass: attach external references to Observables via API ----
            self._attach_external_refs_to_observables()

        except Exception:  # pylint:disable=broad-exception-caught
            self.helper.log_error(traceback.format_exc())

        # Store the current timestamp as a last run
        message = f"Connector successfully run, storing last_run as {now_ts}"
        self.helper.log_info(message)
        self.helper.set_state(
            {
                "last_run": now_ts,
                "last_processed_entry": last_processed_entry_running_max,
            }
        )
        self.helper.api.work.to_processed(work_id, message)

    def download_csv(self) -> Iterable[str]:
        """
        Download the csv_url, and if zipped, extract `full.csv` otherwise
        treat the response as the csv itself. Return the non-commented lines
        as a generator.
        """

        self.helper.log_info("Fetching Threat Fox dataset")
        with urllib.request.urlopen(
            self.threatfox_csv_url,
            context=ssl.create_default_context(),
        ) as response:
            data: bytes = response.read()

        try:
            zipped_file = io.BytesIO(data)
            with zipfile.ZipFile(zipped_file, "r") as zip_ref:
                with zip_ref.open("full.csv") as full_file:
                    csv_data = full_file.read()
        except zipfile.BadZipFile:
            # Treat as an unzipped CSV from /recent/
            csv_data = data

        for line in csv_data.decode("utf-8").splitlines():
            if line.startswith("#"):
                continue
            yield line

    # ------------------- STIX creation (primary path) -------------------
    def process_row(self, ioc: "FeedRow") -> Iterable[stix2._STIXBase]:
        """Process the IOC record and generate SCO/SDO/SRO objects."""

        result = self.process_row_observable(ioc)
        if result is None:
            return
        
        stix_observable, stix_indicator, obs_metadata = result
        if stix_observable:
            yield stix_observable
        if stix_indicator:
            yield stix_indicator

        # Don't create malware if the source doesn't exist
        if stix_observable is None:
            return

        # Create malware SDO (as FAMILY) and add refs; then relationships
        stix_malware = self.process_row_malware(ioc)
        if stix_malware:
            yield stix_malware

        # Relationships with confidence
        if stix_indicator and stix_observable:
            yield self.create_relationship(
                stix_indicator, "based-on", stix_observable, ioc.confidence_level
            )

        if stix_indicator and stix_malware:
            yield self.create_relationship(
                stix_indicator, "indicates", stix_malware, ioc.confidence_level
            )

        # Always relate observable to malware (even if no indicator)
        if stix_observable and stix_malware:
            yield self.create_relationship(
                stix_observable, "related-to", stix_malware, ioc.confidence_level
            )

        # --- Queue for post-pass API processing (external refs + relationships) ---
        self._pending_observables.append(
            {
                "entity_type": obs_metadata["observable_type"],
                "value": obs_metadata["value_for_lookup"],
                "hash_field": obs_metadata["hash_field"],
                "urls": self._reference_urls(ioc),
                "indicator_id": stix_indicator.id if stix_indicator else None,
                "stix_id": stix_observable.id,
                "malware_stix_id": stix_malware.id if stix_malware else None,
                "confidence": ioc.confidence_level,
            }
        )

    def process_row_observable(
        self, ioc: "FeedRow"
    ) -> Optional[Tuple[Observable, Optional[stix2.Indicator], Dict[str, Union[str, None]]]]:
        """Process the IOC record and return an observable, indicator, and metadata for post-pass."""

        description = None
        score_from_conf = int(ioc.confidence_level)

        # --- Map the IOC to a STIX SCO (+ pattern metadata) ---
        # NOTE: external_references is NOT valid on STIX SCOs, only SDOs
        # External references are attached via API in the post-pass

        if ioc.type == "ip:port":
            ioc.value, port = ioc.value.split(":", maxsplit=1)
            description = f"Traffic seen on port {port}"
            pattern_value = f"[ipv4-addr:value = '{ioc.value}']"
            indicator_type = "ipv4"
            observable_type = "IPv4-Addr"
            stix_observable = stix2.IPv4Address(
                value=ioc.value,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity_id,
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                    "x_opencti_score": score_from_conf,
                },
            )
            value_for_lookup = ioc.value
            hash_field = None

        elif ioc.type == "domain":
            pattern_value = f"[domain-name:value = '{ioc.value}']"
            indicator_type = "domain"
            observable_type = "Domain-Name"
            stix_observable = stix2.DomainName(
                value=ioc.value,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity_id,
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                    "x_opencti_score": score_from_conf,
                },
            )
            value_for_lookup = ioc.value
            hash_field = None

        elif ioc.type == "url":
            pattern_value = f"[url:value = '{ioc.value}']"
            indicator_type = "url"
            observable_type = "Url"
            stix_observable = stix2.URL(
                value=ioc.value,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity_id,
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                    "x_opencti_score": score_from_conf,
                },
            )
            value_for_lookup = ioc.value
            hash_field = None

        elif ioc.type == "md5_hash":
            pattern_value = f"[file:hashes.MD5 = '{ioc.value}']"
            indicator_type = "md5"
            observable_type = "StixFile"
            stix_observable = stix2.File(
                name=ioc.value,
                hashes={"MD5": ioc.value},
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity_id,
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                    "x_opencti_score": score_from_conf,
                },
            )
            value_for_lookup = ioc.value
            hash_field = "hashes.MD5"

        elif ioc.type == "sha1_hash":
            pattern_value = f"[file:hashes.SHA1 = '{ioc.value}']"
            indicator_type = "sha1"
            observable_type = "StixFile"
            stix_observable = stix2.File(
                name=ioc.value,
                hashes={"SHA-1": ioc.value},
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity_id,
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                    "x_opencti_score": score_from_conf,
                },
            )
            value_for_lookup = ioc.value
            hash_field = "hashes.SHA-1"  # IMPORTANT: exact key

        elif ioc.type == "sha256_hash":
            pattern_value = f"[file:hashes.'SHA-256' = '{ioc.value}']"
            indicator_type = "sha256"
            observable_type = "StixFile"
            stix_observable = stix2.File(
                name=ioc.value,
                hashes={"SHA-256": ioc.value},
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity_id,
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                    "x_opencti_score": score_from_conf,
                },
            )
            value_for_lookup = ioc.value
            hash_field = "hashes.SHA-256"

        else:
            self.helper.log_warning(f"Unrecognized ioc_type: {ioc.type}")
            return None

        # Capture the STIX id of the observable we just created (deterministic)
        observable_stix_id = stix_observable.id

        # --- Indicator (optional) ---
        indicator_id: Optional[str] = None
        stix_indicator: Optional[stix2.Indicator] = None

        if self.create_indicators:
            indicator_id = Indicator.generate_id(pattern_value)
            stix_indicator = stix2.Indicator(
                name=ioc.value,
                description=description,
                id=indicator_id,
                indicator_types=[indicator_type],
                pattern_type="stix",
                pattern=pattern_value,
                labels=ioc.tags,
                object_marking_refs=[stix2.TLP_WHITE],
                created_by_ref=self.identity_id,
                confidence=ioc.confidence_level,
                external_references=[
                    stix2.ExternalReference(source_name="ThreatFox", url=u)
                    for u in self._reference_urls(ioc)
                ],
                custom_properties={
                    "x_opencti_main_observable_type": observable_type,
                    "x_opencti_score": score_from_conf,
                },
            )
            self.helper.log_debug(f"Indicator created: {stix_indicator}")

        # Return metadata for post-pass queueing (done in process_row)
        obs_metadata = {
            "observable_type": observable_type,
            "value_for_lookup": value_for_lookup,
            "hash_field": hash_field,
        }

        return stix_observable, stix_indicator, obs_metadata

    def process_row_malware(self, ioc: "FeedRow") -> Optional[stix2.Malware]:
        """Process the IOC record and generate a malware SDO (family)"""

        # Determine family (prefer printable)
        family_name = self._normalize_family_name(ioc)
        if not family_name:
            return None

        # Normalize malware_types (STIX open-vocab requires lowercase)
        if ioc.threat_type == "botnet_cc":
            malware_types = ["bot"]
        elif ioc.threat_type == "payload_delivery":
            malware_types = ["dropper"]
        else:
            malware_types = None

        # Build aliases (preserve ThreatFox aliases and fk_malware)
        aliases = list(ioc.malware_aliases) if ioc.malware_aliases else []
        if ioc.fk_malware and ioc.fk_malware not in aliases:
            aliases.append(ioc.fk_malware)

        # External references for Malware SDO (OK in STIX)
        ext_refs = [stix2.ExternalReference(source_name="ThreatFox", url=u) for u in self._reference_urls(ioc)]

        # Create the malware object (as FAMILY)
        stix_malware = stix2.Malware(
            id=Malware.generate_id(family_name),
            name=family_name,
            aliases=aliases or None,
            created_by_ref=self.identity_id,
            object_marking_refs=[stix2.TLP_WHITE],
            confidence=ioc.confidence_level,
            description=f"Threat: {family_name}\nReporter: {ioc.reporter}",
            is_family=True,
            labels=ioc.tags,
            malware_types=malware_types,
            external_references=ext_refs or None,
        )
        self.helper.log_debug(f"Malware object created: {stix_malware}")

        return stix_malware

    def create_relationship(
        self,
        source: stix2._STIXBase,
        rel_type: str,
        target: stix2._STIXBase,
        confidence: Optional[int] = None,
    ) -> stix2.Relationship:
        """Create a relationship between two objects"""

        stix_rel = stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source.id, target.id),
            source_ref=source.id,
            target_ref=target.id,
            relationship_type=rel_type,
            created_by_ref=self.identity_id,
            object_marking_refs=[stix2.TLP_WHITE],
            confidence=int(confidence) if confidence is not None else None,
        )
        self.helper.log_debug(f"Relationship created: {source.id} -> {target.id}")

        return stix_rel

    # ---------------------- 2nd pass (post-ingestion) ----------------------
    def _reference_urls(self, ioc: "FeedRow") -> List[str]:
        """
        STRICT requirement:
        Use ONLY the value from the 12th CSV column ('reference') exactly as provided by the API.
        No regex, no inference, no validation.
        """
        ref = (ioc.reference or "").strip()
        if not ref or ref.lower() == "none":
            return []
        return [ref]

    def _resolve_via_indicator(self, indicator_id: str) -> Optional[str]:
        """
        Resolve the observable by following the Indicator --based-on--> Observable relationship.
        Uses 6.8.x-style kwargs (no filters payload).
        """
        try:
            # Primary: indicator is the 'from' side in "based-on"
            rels = self.helper.api.stix_core_relationship.list(
                fromId=indicator_id,
                relationship_type="based-on",
                first=1,
            ) or []
            if rels:
                rel = rels[0]
                to_obj = rel.get("to") or {}
                to_id = to_obj.get("id") or rel.get("toId") or rel.get("to_id")
                if to_id:
                    return to_id

            # Fallback: direction-agnostic variant
            rels = self.helper.api.stix_core_relationship.list(
                fromOrToId=indicator_id,
                relationship_type="based-on",
                first=1,
            ) or []
            if rels:
                rel = rels[0]
                to_obj = rel.get("to") or {}
                to_id = to_obj.get("id") or rel.get("toId") or rel.get("to_id")
                if to_id:
                    return to_id
        except Exception:
            # swallow and fallback to value-based lookup
            pass
        return None

    def _read_observable_by_stix_id(self, stix_id: str) -> Optional[str]:
        """Return the OpenCTI internal id for a SCO given its STIX (standard) id."""
        try:
            obj = self.helper.api.stix_cyber_observable.read(id=stix_id)
            if obj:
                return obj["id"]  # OpenCTI internal id
        except Exception:
            pass
        return None

    def _find_observable_id(
        self,
        entity_type: str,
        value: str,
        hash_field: Optional[str],
        max_attempts: int = 12,
        initial_sleep: float = 0.8,
    ) -> Optional[str]:
        """
        Value-based fallback with normalization & retries.
        entity_type: "Url" | "Domain-Name" | "IPv4-Addr" | "StixFile"
        value:       original value we emitted in STIX (or the hash string for files)
        hash_field:  "hashes.MD5" | "hashes.SHA-1" | "hashes.SHA-256" | None
        """
        def _read(filters_dict) -> Optional[str]:
            try:
                oid_obj = self.helper.api.stix_cyber_observable.read(filters=filters_dict)
                if oid_obj:
                    return oid_obj["id"]
            except Exception:
                pass
            try:
                oid_obj = self.helper.api.stix_cyber_observable.read(
                    filters=filters_dict.get("filters", filters_dict)
                )
                if oid_obj:
                    return oid_obj["id"]
            except Exception:
                pass
            try:
                items = self.helper.api.stix_cyber_observable.list(
                    filters=filters_dict, first=1
                ) or []
                if items:
                    return items[0]["id"]
            except Exception:
                pass
            try:
                items = self.helper.api.stix_cyber_observable.list(
                    filters=filters_dict.get("filters", filters_dict), first=1
                ) or []
                if items:
                    return items[0]["id"]
            except Exception:
                pass
            return None

        # Candidates to try (ordered)
        candidates: List[Dict] = []
        if entity_type == "StixFile":
            if hash_field:
                candidates.append(
                    {"mode": "and", "filters": [
                        {"key": "entity_type", "values": [entity_type]},
                        {"key": hash_field,    "values": [value]},
                    ]}
                )
            candidates.append(
                {"mode": "and", "filters": [
                    {"key": "entity_type", "values": [entity_type]},
                    {"key": "value",       "values": [value]},
                ]}
            )
        elif entity_type == "Url":
            v = value.strip()
            candidates.append(
                {"mode": "and", "filters": [
                    {"key": "entity_type", "values": [entity_type]},
                    {"key": "value",       "values": [v]},
                ]}
            )
            if v.endswith("/"):
                candidates.append(
                    {"mode": "and", "filters": [
                        {"key": "entity_type", "values": [entity_type]},
                        {"key": "value",       "values": [v[:-1]]},
                    ]}
                )
        elif entity_type == "Domain-Name":
            v = value.strip()
            candidates.append(
                {"mode": "and", "filters": [
                    {"key": "entity_type", "values": [entity_type]},
                    {"key": "value",       "values": [v]},
                ]}
            )
            if v.lower() != v:
                candidates.append(
                    {"mode": "and", "filters": [
                        {"key": "entity_type", "values": [entity_type]},
                        {"key": "value",       "values": [v.lower()]},
                    ]}
                )
        elif entity_type == "IPv4-Addr":
            candidates.append(
                {"mode": "and", "filters": [
                    {"key": "entity_type", "values": [entity_type]},
                    {"key": "value",       "values": [value.strip()]},
                ]}
            )

        # Retry loop (trimmed to reduce noise)
        sleep = initial_sleep
        for _attempt in range(1, max_attempts + 1):
            for f in candidates:
                oid = _read(f)
                if oid:
                    return oid
            time.sleep(sleep)
            sleep *= 1.4
        return None

    def _attach_external_refs_to_observables(self) -> None:
        """Attach ThreatFox external refs and relationships to SCOs via API (post-ingestion)."""
        total = len(self._pending_observables or [])
        if total == 0:
            self.helper.log_info("[ThreatFox] post-pass: no pending observables to update")
            return

        self.helper.log_info(f"[ThreatFox] post-pass starting with {total} pending observable(s)")

        refs_attached = 0
        rels_created = 0
        not_found = 0
        errors = 0

        for entry in self._pending_observables:
            entity_type: str = entry["entity_type"]            # "Url" | "Domain-Name" | "IPv4-Addr" | "StixFile"
            value: str = entry["value"]
            hash_field: Optional[str] = entry["hash_field"]    # "hashes.MD5" | "hashes.SHA-1" | "hashes.SHA-256" | None
            urls: List[str] = entry.get("urls") or []
            indicator_id: Optional[str] = entry.get("indicator_id")  # type: ignore[assignment]
            stix_id: Optional[str] = entry.get("stix_id")            # type: ignore[assignment]
            malware_stix_id: Optional[str] = entry.get("malware_stix_id")  # type: ignore[assignment]
            confidence: Optional[int] = entry.get("confidence")  # type: ignore[assignment]

            # 0) Best-effort: resolve directly by the STIX id we emitted in the bundle
            obs_id = None
            if stix_id:
                obs_id = self._read_observable_by_stix_id(stix_id)

            # 1) If not found, try via Indicator --based-on--> Observable
            if not obs_id and indicator_id:
                obs_id = self._resolve_via_indicator(indicator_id)

            # 2) Fallback: value/hash lookup with retries
            if not obs_id:
                obs_id = self._find_observable_id(entity_type, value, hash_field)

            if not obs_id:
                not_found += 1
                self.helper.log_warning(
                    f"[ThreatFox] Observable not found for post-pass after all strategies: "
                    f"{entity_type} / {value} (hash_field={hash_field}, indicator_id={indicator_id}, stix_id={stix_id})"
                )
                continue

            # --- Create/attach external references ---
            for url in urls:
                try:
                    ext_ref_id = self._cache_ext_ref_ids.get(url)
                    if not ext_ref_id:
                        ext_ref = self.helper.api.external_reference.create(
                            source_name="ThreatFox",
                            url=url,
                        )
                        ext_ref_id = ext_ref["id"]
                        self._cache_ext_ref_ids[url] = ext_ref_id

                    # Primary: singular attach method
                    try:
                        self.helper.api.stix_cyber_observable.add_external_reference(
                            id=obs_id, external_reference_id=ext_ref_id
                        )
                    except Exception:
                        # Fallback: plural attach (for pycti variants)
                        self.helper.api.stix_cyber_observable.add_external_references(
                            id=obs_id, external_references_ids=[ext_ref_id]
                        )

                    refs_attached += 1
                    self.helper.log_debug(
                        f"[ThreatFox] attached ext-ref {url} to {entity_type}:{value} ({obs_id})"
                    )

                except Exception:  # pylint:disable=broad-exception-caught
                    errors += 1
                    self.helper.log_error(
                        f"[ThreatFox] Failed attaching external ref '{url}' to observable {obs_id}:\n{traceback.format_exc()}"
                    )

            # --- Create observable --related-to--> malware relationship via API ---
            if malware_stix_id:
                try:
                    # Resolve malware internal ID from STIX ID
                    malware_obj = self.helper.api.malware.read(id=malware_stix_id)
                    if malware_obj:
                        malware_internal_id = malware_obj["id"]
                        
                        # Create relationship via API
                        self.helper.api.stix_core_relationship.create(
                            fromId=obs_id,
                            toId=malware_internal_id,
                            relationship_type="related-to",
                            createdBy=self.identity["id"],
                            confidence=int(confidence) if confidence is not None else None,
                        )
                        rels_created += 1
                        self.helper.log_debug(
                            f"[ThreatFox] created relationship {entity_type}:{value} --related-to--> malware ({malware_stix_id})"
                        )
                    else:
                        self.helper.log_warning(
                            f"[ThreatFox] Malware not found for relationship: {malware_stix_id}"
                        )
                except Exception:  # pylint:disable=broad-exception-caught
                    errors += 1
                    self.helper.log_error(
                        f"[ThreatFox] Failed creating relationship for observable {obs_id} to malware {malware_stix_id}:\n{traceback.format_exc()}"
                    )

        self.helper.log_info(
            f"[ThreatFox] post-pass finished: refs_attached={refs_attached} rels_created={rels_created} not_found={not_found} errors={errors}"
        )

    # ----------------------------- Utilities -----------------------------
    def _normalize_family_name(self, ioc: "FeedRow") -> Optional[str]:
        """Prefer printable/family; else derive from fk_malware like 'win.mirai' -> 'Mirai'."""
        if ioc.malware_printable:
            return ioc.malware_printable.strip()
        if ioc.fk_malware:
            base = ioc.fk_malware.split(".")[-1].strip()
            return base[:1].upper() + base[1:] if base else None
        return None


# ----------------------------- FeedRow ------------------------------- #
# pylint:disable=too-many-instance-attributes
@dataclass(init=False)
class FeedRow:
    """ThreatFox csv row"""

    first_seen: datetime
    id: str
    value: str
    type: str
    threat_type: str
    fk_malware: str
    malware_aliases: List[str]
    malware_printable: str
    last_seen: Union[datetime, None]
    confidence_level: int
    reference: str
    tags: List[str]
    anonymous: bool
    reporter: str

    def __init__(self, row: Tuple):
        """Initializer"""

        first_seen = row[0]
        self.first_seen = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
        self.first_seen = self.first_seen.replace(tzinfo=UTC)

        self.id = row[1]
        self.value = row[2]
        self.type = row[3]
        self.threat_type = row[4]
        self.fk_malware = row[5]
        self.malware_aliases = list(filter(None, row[6].split(",")))
        self.malware_printable = row[7]

        if self.malware_aliases == ["None"]:
            self.malware_aliases = []

        if self.fk_malware == "unknown":
            self.fk_malware = ""

        if self.malware_printable == "Unknown malware":
            self.malware_printable = ""
        else:
            if self.malware_printable and self.malware_printable not in self.malware_aliases:
                self.malware_aliases.insert(0, self.malware_printable)

        last_seen = row[8]
        if last_seen:
            self.last_seen = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
            self.last_seen = self.last_seen.replace(tzinfo=UTC)
        else:
            self.last_seen = None

        self.confidence_level = int(row[9])
        self.is_compromised = str(row[10]).lower() == "true"
        self.reference = row[11] if row[11] != "None" else ""
        self.tags = [
            t for t in row[12].split(",")
            if t and t.lower() != "none"
        ]

        if self.threat_type:
            self.tags.insert(0, self.threat_type)

        self.anonymous = bool(int(row[13]))
        self.reporter = row[14]


def main() -> None:
    """Run the ThreatFox connector."""
    try:
        ThreatFoxConnector = ThreatFox()
        ThreatFoxConnector.run()
    except Exception:  # pylint:disable=broad-exception-caught
        print(traceback.format_exc())


# ----------------------------- Entrypoint ---------------------------- #
if __name__ == "__main__":
    main()