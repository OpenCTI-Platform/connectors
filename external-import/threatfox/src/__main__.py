"""
ThreatFox connector (STIX-bundle ingestion)

- Ingests via STIX bundle only; no direct writes to the OpenCTI API.
- STRICT REQUIREMENT: external reference is ONLY the 12th CSV column ('reference') exactly as provided by the API.
    - We don't want to mistake malicious domains as a clickable reference!!
- Adds external references to Indicator & Malware (external_references) and to
  Observables (x_opencti_external_references, as STIX SCOs have no
  external_references property).
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
from src.models.configs.config_loader import ConfigLoader
from stix2.base import _Observable as Observable

ALL_TYPES = "all_types"
BASE_PATH = os.path.dirname(os.path.abspath(__file__))


# pylint:disable=too-many-instance-attributes
class ThreatFox:
    """ThreatFox connector (STIX bundle ingestion)"""

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
        # Per-IOC-type override, used in preference to the confidence-derived
        # score when set; see _resolve_score().
        self._score_override_by_type = {
            "ip:port": self.x_opencti_score_ip,
            "domain": self.x_opencti_score_domain,
            "url": self.x_opencti_score_url,
            "md5_hash": self.x_opencti_score_hash,
            "sha1_hash": self.x_opencti_score_hash,
            "sha256_hash": self.x_opencti_score_hash,
        }

        self.ioc_to_import = [
            ioc.strip()
            for ioc in self.config.threatfox.ioc_to_import.split(",")
            if ioc.strip()
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

    # ------------------------ Utility & config ------------------------ #
    def get_interval(self) -> float:
        """Convert the threatfox_interval (days) to seconds"""
        return float(self.threatfox_interval) * 60 * 60 * 24

    def _resolve_score(self, ioc: "FeedRow") -> int:
        """Resolve the x_opencti_score for an IOC.

        A per-type override (THREATFOX_X_OPENCTI_SCORE_IP/DOMAIN/URL/HASH) takes
        precedence when set; otherwise the score is derived from ThreatFox's own
        confidence_level, falling back to THREATFOX_DEFAULT_X_OPENCTI_SCORE only
        if confidence_level itself is unusable.
        """
        override = self._score_override_by_type.get(ioc.type)
        if override is not None:
            return override
        try:
            return int(ioc.confidence_level)
        except (TypeError, ValueError):
            return self.default_x_opencti_score

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
            if self.import_data(state, now_dt, now_ts):
                self.helper.log_info(
                    f"Last_run stored, next run in: {next_dt - now_dt}"
                )
        else:
            self.helper.log_info(
                f"Connector will not run, next run in: {next_dt - now_dt}"
            )

    # -------------------------- Import pipeline ----------------------- #
    def import_data(self, state: Dict, now_dt: datetime, now_ts: int) -> bool:
        """Pull and import ThreatFox data via STIX.

        Returns True when the run succeeded and state was advanced. On failure
        (download or bundle send) the work is marked in error and state is left
        untouched so the next run retries the same window.
        """

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            "Threat Fox run @ " + now_dt.strftime("%Y-%m-%d %H:%M:%S"),
        )

        csv.register_dialect(
            "custom", delimiter=",", quotechar='"', skipinitialspace=True
        )

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

        except Exception:  # pylint:disable=broad-exception-caught
            self.helper.log_error(traceback.format_exc())
            message = "Connector run failed, state not updated"
            self.helper.api.work.to_processed(work_id, message, in_error=True)
            return False

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
        return True

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

        stix_observable, stix_indicator = result
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

    def process_row_observable(
        self, ioc: "FeedRow"
    ) -> Optional[Tuple[Observable, Optional[stix2.Indicator]]]:
        """Process the IOC record and return an observable and optional indicator."""

        description = None
        score = self._resolve_score(ioc)
        ext_refs = [
            stix2.ExternalReference(source_name="ThreatFox", url=u)
            for u in self._reference_urls(ioc)
        ]

        # --- Map the IOC to a STIX SCO (+ pattern metadata) ---
        # STIX SCOs have no external_references property; OpenCTI reads them
        # from x_opencti_external_references on bundle ingestion.

        if ioc.type == "ip:port":
            ioc.value, port = ioc.value.split(":", maxsplit=1)
            description = f"Traffic seen on port {port}"
            pattern_value = f"[ipv4-addr:value = '{ioc.value}']"
            indicator_type = "ipv4"
            observable_type = "IPv4-Addr"
            stix_observable = stix2.IPv4Address(
                value=ioc.value,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties=self._observable_custom_properties(
                    ioc, description, score, ext_refs
                ),
            )

        elif ioc.type == "domain":
            pattern_value = f"[domain-name:value = '{ioc.value}']"
            indicator_type = "domain"
            observable_type = "Domain-Name"
            stix_observable = stix2.DomainName(
                value=ioc.value,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties=self._observable_custom_properties(
                    ioc, description, score, ext_refs
                ),
            )

        elif ioc.type == "url":
            pattern_value = f"[url:value = '{ioc.value}']"
            indicator_type = "url"
            observable_type = "Url"
            stix_observable = stix2.URL(
                value=ioc.value,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties=self._observable_custom_properties(
                    ioc, description, score, ext_refs
                ),
            )

        elif ioc.type == "md5_hash":
            pattern_value = f"[file:hashes.MD5 = '{ioc.value}']"
            indicator_type = "md5"
            observable_type = "StixFile"
            stix_observable = stix2.File(
                name=ioc.value,
                hashes={"MD5": ioc.value},
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties=self._observable_custom_properties(
                    ioc, description, score, ext_refs
                ),
            )

        elif ioc.type == "sha1_hash":
            pattern_value = f"[file:hashes.SHA1 = '{ioc.value}']"
            indicator_type = "sha1"
            observable_type = "StixFile"
            stix_observable = stix2.File(
                name=ioc.value,
                hashes={"SHA-1": ioc.value},
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties=self._observable_custom_properties(
                    ioc, description, score, ext_refs
                ),
            )

        elif ioc.type == "sha256_hash":
            pattern_value = f"[file:hashes.'SHA-256' = '{ioc.value}']"
            indicator_type = "sha256"
            observable_type = "StixFile"
            stix_observable = stix2.File(
                name=ioc.value,
                hashes={"SHA-256": ioc.value},
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties=self._observable_custom_properties(
                    ioc, description, score, ext_refs
                ),
            )

        else:
            self.helper.log_warning(f"Unrecognized ioc_type: {ioc.type}")
            return None

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
                external_references=ext_refs,
                custom_properties={
                    "x_opencti_main_observable_type": observable_type,
                    "x_opencti_score": score,
                },
            )
            self.helper.log_debug(f"Indicator created: {stix_indicator}")

        return stix_observable, stix_indicator

    def _observable_custom_properties(
        self,
        ioc: "FeedRow",
        description: Optional[str],
        score: int,
        ext_refs: List[stix2.ExternalReference],
    ) -> Dict:
        """Return the OpenCTI custom properties shared by every ThreatFox SCO."""
        return {
            "created_by_ref": self.identity_id,
            "x_opencti_description": description,
            "x_opencti_labels": ioc.tags,
            "x_opencti_score": score,
            "x_opencti_external_references": ext_refs or None,
        }

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
        ext_refs = [
            stix2.ExternalReference(source_name="ThreatFox", url=u)
            for u in self._reference_urls(ioc)
        ]

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

    # ---------------------- External references ----------------------
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
            if (
                self.malware_printable
                and self.malware_printable not in self.malware_aliases
            ):
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
        self.tags = [t for t in row[12].split(",") if t and t.lower() != "none"]

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
