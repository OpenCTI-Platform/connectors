"""ThreatFox connector"""

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
import validators
import yaml
from pycti import (
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)
from stix2.base import _Observable as Observable

ALL_TYPES = "all_types"
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = f"{BASE_PATH}/data.csv"


# pylint:disable=too-many-instance-attributes
class ThreatFox:
    """ThreatFox connector"""

    def __init__(self):
        """Initializer"""

        # Instantiate the connector helper from config
        config_file_path = f"{BASE_PATH}/config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Extra config
        self.threatfox_csv_url: str = get_config_variable(
            "THREATFOX_CSV_URL",
            ["threatfox", "csv_url"],
            config,
            default="https://threatfox.abuse.ch/export/csv/recent/",
        )
        self.threatfox_import_offline: bool = get_config_variable(
            "THREATFOX_IMPORT_OFFLINE",
            ["threatfox", "import_offline"],
            config,
            default=True,
        )
        self.threatfox_interval: int = get_config_variable(
            "THREATFOX_INTERVAL",
            ["threatfox", "interval"],
            config,
            isNumber=True,
            default=3,
        )
        self.create_indicators: bool = get_config_variable(
            "THREATFOX_CREATE_INDICATORS",
            ["threatfox", "create_indicators"],
            config,
            default=True,
        )
        self.ioc_to_import: list[str] = get_config_variable(
            "THREATFOX_IOC_TO_IMPORT",
            ["threatfox", "ioc_to_import"],
            config,
            default=ALL_TYPES,
        ).split(",")
        self.ioc_to_import = [ioc.strip() for ioc in self.ioc_to_import]
        if len(self.ioc_to_import) == 0:
            self.ioc_to_import = [ALL_TYPES]

        self.update_existing_data: bool = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            default=False,
        )

        self.identity: str = self.helper.api.identity.create(
            type="Organization",
            name="Threat Fox | Abuse.ch",
            description="abuse.ch is operated by a random swiss guy fighting malware for "
            "non-profit, running a couple of projects helping internet service providers "
            "and network operators protecting their infrastructure from malware.",
        )

    def get_interval(self) -> float:
        """Convert the threatfox_interval from days to millis"""

        return float(self.threatfox_interval) * 60 * 60 * 24

    def run(self):
        """Run the connector"""

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
        """Main connector loop"""

        # Get the current timestamp and check
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

    def import_data(self, state: Dict, now_dt: datetime, now_ts: int) -> None:
        """Pull and import ThreatFox data"""

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            "Threat Fox run @ " + now_dt.strftime("%Y-%m-%d %H:%M:%S"),
        )

        csv.register_dialect(
            "custom",
            delimiter=",",
            quotechar='"',
            skipinitialspace=True,
        )

        last_processed_entry_running_max = 0

        try:
            lines = self.download_csv()
            csv_reader = csv.reader(lines, dialect="custom")

            bundle_objects = []

            last_processed_entry = state.get("last_processed_entry")  # epoch
            if last_processed_entry is None:
                self.helper.log_info(
                    "'last_processed_entry' state not found, setting it to epoch start."
                )
                last_processed_entry = 0

            last_processed_entry_running_max = last_processed_entry

            for i, row in enumerate(csv_reader):
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

                bundle_objects.extend(self.process_row(ioc))

            bundle = stix2.Bundle(
                objects=bundle_objects,
                allow_custom=True,
            ).serialize()

            self.helper.log_debug(bundle)
            if "objects" in bundle:
                self.helper.send_stix2_bundle(
                    bundle,
                    update=self.update_existing_data,
                    work_id=work_id,
                )

            if os.path.exists(CSV_PATH):
                os.remove(CSV_PATH)

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

        with open(CSV_PATH, "wb") as fd:
            fd.write(csv_data)

        with open(CSV_PATH, "r", encoding="utf-8") as fd:
            yield from (line for line in fd if not line.startswith("#"))

    def process_row(self, ioc: FeedRow) -> Iterable[Dict]:
        """Process the IOC record and generate SCO/SDO/SRO objects."""

        stix_observable, stix_indicator = self.process_row_observable(ioc)
        if stix_observable:
            yield stix_observable
        if stix_indicator:
            yield stix_indicator

        # Don't create malware if the source doesn't exist
        if stix_observable is None:
            return

        stix_malware = self.process_row_malware(ioc)
        if stix_malware:
            yield stix_malware

        if stix_indicator and stix_observable:
            yield self.create_relationship(stix_indicator, "based-on", stix_observable)

        if stix_indicator and stix_malware:
            yield self.create_relationship(stix_indicator, "indicates", stix_malware)

    def process_row_observable(
        self, ioc: FeedRow
    ) -> Tuple[Optional[Observable], Optional[stix2.Indicator]]:
        """Process the IOC record and return an observable and indicator"""

        description = None
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
                    "created_by_ref": self.identity["standard_id"],
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                },
            )
        elif ioc.type == "domain":
            pattern_value = f"[domain-name:value = '{ioc.value}']"
            indicator_type = "domain"
            observable_type = "Domain-Name"
            stix_observable = stix2.DomainName(
                value=ioc.value,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                },
            )
        elif ioc.type == "url":
            pattern_value = f"[url:value = '{ioc.value}']"
            indicator_type = "url"
            observable_type = "Url"
            stix_observable = stix2.URL(
                value=ioc.value,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                },
            )
        elif ioc.type == "md5_hash":
            pattern_value = f"[file:hashes.MD5 = '{ioc.value}']"
            indicator_type = "md5"
            observable_type = "StixFile"
            stix_observable = stix2.File(
                name=ioc.value,
                hashes={"MD5": ioc.value},
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                },
            )
        elif ioc.type == "sha1_hash":
            pattern_value = f"[file:hashes.SHA1 = '{ioc.value}']"
            indicator_type = "sha1"
            observable_type = "StixFile"
            stix_observable = stix2.File(
                name=ioc.value,
                hashes={"SHA-1": ioc.value},
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                },
            )
        elif ioc.type == "sha256_hash":
            pattern_value = f"[file:hashes.'SHA-256' = '{ioc.value}']"
            indicator_type = "sha256"
            observable_type = "StixFile"
            stix_observable = stix2.File(
                name=ioc.value,
                hashes={"SHA-256": ioc.value},
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                    "x_opencti_description": description,
                    "x_opencti_labels": ioc.tags,
                },
            )
        else:
            self.helper.log_warning(f"Unrecognized ioc_type: {ioc.type}")
            return None

        # Check if we have an external reference
        if validators.url(ioc.reference):
            ext_refs = [
                stix2.ExternalReference(
                    source_name="ThreatFox source reference",
                    url=ioc.reference,
                )
            ]
        else:
            ext_refs = []

        if self.create_indicators:
            stix_indicator = stix2.Indicator(
                name=ioc.value,
                description=description,
                id=Indicator.generate_id(pattern_value),
                indicator_types=[indicator_type],
                pattern_type="stix",
                pattern=pattern_value,
                valid_from=datetime.now(UTC),
                labels=ioc.tags,
                object_marking_refs=[stix2.TLP_WHITE],
                created_by_ref=self.identity["standard_id"],
                confidence=ioc.confidence_level,
                external_references=ext_refs,
                custom_properties={
                    "x_opencti_main_observable_type": observable_type,
                },
            )
            self.helper.log_debug(f"Indicator created: {stix_indicator}")
        else:
            stix_indicator = None

        return stix_observable, stix_indicator

    def process_row_malware(self, ioc: FeedRow) -> stix2.Malware:
        """Process the IOC record and generate a malware SDO"""

        if not ioc.malware_printable:
            return None

        if ioc.threat_type == "botnet_cc":
            malware_types = ["Bot"]
        elif ioc.threat_type == "payload_delivery":
            malware_types = ["dropper"]
        else:
            malware_types = None

        # Create the malware object
        stix_malware = stix2.Malware(
            id=Malware.generate_id(ioc.fk_malware),
            name=ioc.fk_malware,
            aliases=ioc.malware_aliases,
            created_by_ref=self.identity["standard_id"],
            object_marking_refs=[stix2.TLP_WHITE],
            confidence=ioc.confidence_level,
            description=f"Threat: {ioc.fk_malware}\nReporter: {ioc.reporter}",
            is_family=False,
            labels=ioc.tags,
            malware_types=malware_types,
        )
        self.helper.log_debug(f"Malware object created: {stix_malware}")

        return stix_malware

    def create_relationship(
        self,
        source: Observable,
        rel_type: str,
        target: Observable,
    ) -> stix2.Relationship:
        """Create a relationship between two objects"""

        stix_rel = stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source.id, target.id),
            source_ref=source.id,
            target_ref=target.id,
            relationship_type=rel_type,
            created_by_ref=self.identity["standard_id"],
            object_marking_refs=[stix2.TLP_WHITE],
        )
        self.helper.log_debug(f"Relationship created: {source.id} -> {target.id}")

        return stix_rel


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

    def __init__(self, row: Tuple) -> None:
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
            self.malware_aliases.insert(0, self.malware_printable)

        last_seen = row[8]
        if last_seen:
            self.last_seen = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
            self.last_seen = self.last_seen.replace(tzinfo=UTC)
        else:
            self.last_seen = None

        self.confidence_level = int(row[9])
        self.reference = row[10]

        if self.reference == "None":
            self.reference = ""

        self.tags = list(filter(None, row[11].split(",")))

        if self.threat_type:
            self.tags.insert(0, self.threat_type)

        self.anonymous = bool(int(row[12]))
        self.reporter = row[13]


if __name__ == "__main__":
    try:
        ThreatFoxConnector = ThreatFox()
        ThreatFoxConnector.run()
    except Exception:  # pylint:disable=broad-exception-caught
        print(traceback.format_exc())
        time.sleep(10)
        sys.exit(0)
