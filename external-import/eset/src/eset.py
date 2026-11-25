import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import cabby
import eti_api
import stix2
from dateutil.parser import parse
from pycti import Indicator, Malware, OpenCTIConnectorHelper, Report
from settings import ConnectorSettings

TMP_DIR = "TMP"

OBSERVABLE_TYPES_MAP = {
    "url:value": "Url",
    "domain-name:value": "Domain-Name",
    "ipv4-addr:value": "IPv4-Addr",
    "file:hashes.MD5": "MD5",
    "file:hashes.'SHA-1'": "SHA-1",
    "file:hashes.'SHA-256'": "SHA-256",
}


class Eset:
    def __init__(self):
        # Instantiate the connector helper from config
        self.config = ConnectorSettings()
        self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())
        # Extra config
        self.eset_api_url = self.config.eset.api_url
        self.eset_username = self.config.eset.username
        self.eset_password = self.config.eset.password.get_secret_value()
        self.eset_collections = self.config.eset.collections
        self.eset_import_apt_reports = self.config.eset.import_apt_reports
        self.eset_import_start_date = self.config.eset.import_start_date
        self.eset_create_observables = self.config.eset.create_observables
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="ESET",
            description="ESET, s.r.o., is a software company specializing in cybersecurity.",
        )
        self.added_after = int(self.eset_import_start_date.timestamp())
        # Init variables
        self.cache = {}

        # Create temporary dir and initialize logging.
        if sys.version_info.major == 2:  # Compatibility with Python 2.7.
            if not os.path.isdir(TMP_DIR):
                os.makedirs(TMP_DIR)
        else:
            os.makedirs(TMP_DIR, exist_ok=True)

    def get_interval(self):
        return int(self.config.connector.duration_period.total_seconds())

    def _download_all_report_stuff(self, connection, report, base_path):
        """Download xml, pdf and adds (if available) from given *report* into paths starting with *base_path*."""
        for fmt in ["pdf", "xml", "adds"]:
            ext = fmt if fmt != "adds" else "zip"
            connection.get_report(report, fmt, file_path="{}.{}".format(base_path, ext))

    def _import_reports(self, work_id, start_epoch):
        connection = eti_api.Connection(
            username=self.eset_username,
            password=self.eset_password,
            host="eti.eset.com",
        )
        from_date = datetime.fromtimestamp(start_epoch, timezone.utc)
        i = 0
        for report in connection.list_reports(
            type="all", datetimefrom=from_date.isoformat()
        ):
            bundle_objects = []
            if report["status"] != "finished":
                self.helper.log_info("Finished")
                continue  # Skip not generated reports.
            i += 1
            file_path = os.path.join(TMP_DIR, "{}_{:02d}".format("all", i))
            self._download_all_report_stuff(connection, report, file_path)
            if os.path.isfile(file_path + ".pdf"):
                name = report["filename"].replace(".pdf", "")
                date = parse(report["date"])
                with open(file_path + ".pdf", "rb") as f:
                    file_data_encoded = base64.b64encode(f.read())
                file = {
                    "name": report["filename"],
                    "data": file_data_encoded.decode("utf-8"),
                    "mime_type": "application/pdf",
                    "no_trigger_import": True,
                }
                stix_report = stix2.Report(
                    id=Report.generate_id(name, date),
                    name=name,
                    report_types=["APT Report"],
                    description=name,
                    published=date,
                    labels=["apt", "eset"],
                    created_by_ref=self.identity["standard_id"],
                    object_refs=[self.identity["standard_id"]],
                    allow_custom=True,
                    x_opencti_files=[file],
                    object_marking_refs=[stix2.TLP_AMBER.get("id")],
                )
                bundle_objects.append(stix_report)
                try:
                    self.helper.log_debug("Objects to be sent " + str(bundle_objects))
                    self.helper.send_stix2_bundle(
                        self.helper.stix2_create_bundle(bundle_objects),
                        bypass_split=True,
                        work_id=work_id,
                    )
                except Exception as e:
                    self.helper.log_info("Failed to process report " + name)
                    self.helper.log_info("ERROR: " + str(e))
                os.remove(file_path + ".pdf")
                if os.path.isfile(file_path + ".xml"):
                    os.remove(file_path + ".xml")
                if os.path.isfile(file_path + ".zip"):
                    os.remove(file_path + ".zip")

    def _import_collection(self, collection, work_id, start_epoch):
        client = cabby.create_client(
            self.eset_api_url, discovery_path="/taxiiservice/discovery", use_https=True
        )
        client.set_auth(username=self.eset_username, password=self.eset_password)
        no_more_result = False
        end_epoch = start_epoch + 3600
        atomic_ind_pattern = re.compile(r"\[(\S+) = '[^']+'\]")
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with collection="
                + str(collection)
                + ", start_epoch="
                + str(start_epoch)
                + ", end_epoch="
                + str(end_epoch)
            )
            begin_date = datetime.fromtimestamp(start_epoch, timezone.utc)
            end_date = datetime.fromtimestamp(end_epoch, timezone.utc)
            try:
                for item in client.poll(
                    collection + " (stix2)", begin_date=begin_date, end_date=end_date
                ):
                    if not item.content:  # Skip empty packages.
                        continue
                    parsed_content = json.loads(item.content)
                    objects = []
                    id_remaps = {}
                    removed_ids = set()
                    for object in parsed_content["objects"]:
                        # If no author provided in the entity, then default to set
                        # author to ESET
                        if not "created_by_ref" in object:
                            object["created_by_ref"] = self.identity["standard_id"]
                        # Don't consume identity entities w/ "customer" as the name.
                        # ESET uses this to indicate country targeting, and consuming
                        # these causes problems due to dedupe.
                        # TODO: Convert these & relevant relationship refs to country
                        # locations.
                        if (
                            object["type"] == "identity"
                            and "name" in object
                            and object["name"] == "customer"
                        ) or object["type"] == "observed-data":
                            removed_ids.add(object["id"])
                            continue

                        # Malware STIX IDs need to be manually recomputed so they're
                        # deterministic by malware name
                        if object["type"] == "malware" and "name" in object:
                            new_id = Malware.generate_id(object["name"])
                            if object["id"] in id_remaps:
                                new_id = id_remaps[object["id"]]
                            else:
                                id_remaps[object["id"]] = new_id
                            object["id"] = new_id

                        # If we remapped a STIX id earlier to a pycti one, we need  to
                        # reflect that properly in any relevant relationship too
                        if object["type"] == "relationship":
                            if "source_ref" in object:
                                if object["source_ref"] in removed_ids:
                                    continue  # skip relationship if either ref is in removed_ids
                                if object["source_ref"] in id_remaps:
                                    object["source_ref"] = id_remaps[
                                        object["source_ref"]
                                    ]
                            if "target_ref" in object:
                                if object["target_ref"] in removed_ids:
                                    continue  # skip relationship if either ref is in removed_ids
                                if object["target_ref"] in id_remaps:
                                    object["target_ref"] = id_remaps[
                                        object["target_ref"]
                                    ]

                        if object["type"] == "indicator":
                            object["name"] = object["pattern"]
                            object["pattern_type"] = "stix"
                            object["pattern"] = (
                                object["pattern"]
                                .replace("SHA1", "'SHA-1'")
                                .replace("SHA256", "'SHA-256'")
                            )
                            new_id = Indicator.generate_id(object["pattern"])
                            if object["id"] in id_remaps:
                                new_id = id_remaps[object["id"]]
                            else:
                                id_remaps[object["id"]] = new_id
                            object["id"] = new_id

                            # Attempt to fill in x_opencti_main_observable_type
                            atomic_match = atomic_ind_pattern.fullmatch(
                                object["pattern"]
                            )
                            if atomic_match:
                                pattern_field_name = atomic_match.group(1)
                                if pattern_field_name in OBSERVABLE_TYPES_MAP:
                                    object["x_opencti_main_observable_type"] = (
                                        OBSERVABLE_TYPES_MAP[pattern_field_name]
                                    )
                            if self.eset_create_observables:
                                object["x_opencti_create_observables"] = (
                                    self.eset_create_observables
                                )
                            # Clear where_sighted_refs for indicators only
                            # (this property is not valid for other STIX object types)
                            object["where_sighted_refs"] = []
                        objects.append(object)
                    parsed_content["objects"] = objects
                    self.helper.send_stix2_bundle(
                        json.dumps(parsed_content),
                        work_id=work_id,
                    )
            except Exception as e:
                self.helper.log_error(str(e))
            if end_epoch > int(time.time()):
                no_more_result = True
            else:
                start_epoch = end_epoch
                end_epoch = start_epoch + 3600

    def run(self):
        while True:
            try:
                self.helper.log_info("Synchronizing with ESET API...")
                timestamp = int(time.time())
                now = datetime.fromtimestamp(timestamp, timezone.utc)
                friendly_name = "ESET run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                current_state = self.helper.get_state()
                if current_state is None:
                    self.helper.set_state({"last_run": self.added_after})
                # Get collections
                current_state = self.helper.get_state()

                if self.eset_collections is not None:
                    for collection in self.eset_collections:
                        self._import_collection(
                            collection, work_id, current_state["last_run"]
                        )
                if self.eset_import_apt_reports:
                    self._import_reports(work_id, current_state["last_run"])
                self.helper.set_state({"last_run": timestamp})
                message = "End of synchronization"
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    self.helper.force_ping()
                    sys.exit(0)

                time.sleep(self.get_interval())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)

            except Exception as e:
                self.helper.log_error(str(e))

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    sys.exit(1)

                time.sleep(60)


if __name__ == "__main__":
    try:
        eset_connector = Eset()
        eset_connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(1)
