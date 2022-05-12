################################
# OpenCTI Restore Files         #
################################
import datetime
import json
import os
import sys
from pathlib import Path

import yaml
from pycti import OpenCTIConnectorHelper, OpenCTIStix2Splitter, get_config_variable


def ref_extractors(objects):
    ids = []
    for data in objects:
        for key in data.keys():
            if key.startswith("x_") is False:
                if key.endswith("_ref"):
                    ids.append(data[key])
                if key.endswith("_refs"):
                    ids.extend(data[key])
    return set(ids)


def fetch_stix_data(file):
    # Open a file: file
    file = open(file, mode="r")
    file_content = file.read()
    file.close()
    file_json = json.loads(file_content)
    return file_json["objects"]


def date_convert(name):
    return datetime.datetime.strptime(name, "%Y%m%dT%H%M%SZ")


class RestoreFilesConnector:
    def __init__(self, conf_data):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else conf_data
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.direct_creation = get_config_variable(
            "DIRECT_CREATION",
            ["backup", "direct_creation"],
            config,
            default=False,
        )
        self.backup_protocol = get_config_variable(
            "BACKUP_PROTOCOL", ["backup", "protocol"], config
        )
        self.backup_path = get_config_variable(
            "BACKUP_PATH", ["backup", "path"], config
        )

    def find_element(self, dir_date, id):
        name = id + ".json"
        path = self.backup_path + "/opencti_data"
        for root, dirs, files in os.walk(path):
            if name in files:
                # If find dir is before, no need to process the element as missing
                path = os.path.basename(root)
                if date_convert(path) > dir_date:
                    return fetch_stix_data(os.path.join(root, name))[0]
        return None

    def resolve_missing(self, dir_date, element_ids, data, acc=[]):
        refs = ref_extractors([data])
        for ref in refs:
            if ref not in element_ids:
                not_in = next((x for x in acc if x["id"] == ref), None)
                if not_in is None:
                    missing_element = self.find_element(dir_date, ref)
                    acc.insert(0, missing_element)
                    self.resolve_missing(dir_date, element_ids, missing_element, acc)

    def restore_files(self):
        stix2_splitter = OpenCTIStix2Splitter()
        state = self.helper.get_state()
        start_directory = state["current"] if state is not None else None
        start_date = (
            date_convert(start_directory) if start_directory is not None else None
        )
        path = self.backup_path + "/opencti_data"
        dirs = sorted(Path(path).iterdir(), key=lambda d: date_convert(d.name))
        for entry in dirs:
            friendly_name = "Restore run directory @ " + entry.name
            self.helper.log_info(friendly_name)
            dir_date = date_convert(entry.name)
            if start_date is not None and dir_date <= start_date:
                continue
            # 00 - Create a bundle for the directory
            files_data = []
            element_ids = []
            # 01 - build all _ref / _refs contained in the bundle
            element_refs = []
            for file in os.scandir(entry):
                if file.is_file():
                    objects = fetch_stix_data(file)
                    object_ids = set(map(lambda x: x["id"], objects))
                    element_refs.extend(ref_extractors(objects))
                    files_data.extend(objects)
                    element_ids.extend(object_ids)
            # Ensure the bundle is consistent (include meta elements)
            # 02 - Scan bundle to detect missing elements
            acc = []
            ids = set(element_ids)
            refs = set(element_refs)
            for ref in refs:
                if ref not in ids:
                    # 03 - If missing, scan the other dir/files to find the elements
                    missing_element = self.find_element(dir_date, ref)
                    if missing_element is not None:
                        acc.insert(0, missing_element)
                        # 04 - Restart the process to handle recursive resolution
                        self.resolve_missing(dir_date, ids, missing_element, acc)
            # 05 - Add elements to the bundle
            objects_with_missing = acc + files_data
            if len(objects_with_missing) > 0:
                # Create the work
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                # 06 - Send the bundle to the worker queue
                stix_bundle = {
                    "type": "bundle",
                    "objects": objects_with_missing,
                }
                if self.direct_creation:
                    # Bundle must be split for reordering
                    bundles = stix2_splitter.split_bundle(stix_bundle, False)
                    self.helper.log_info(
                        "restore dir "
                        + entry.name
                        + " with "
                        + str(len(bundles))
                        + " bundles (direct creation)"
                    )
                    for bundle in bundles:
                        self.helper.api.stix2.import_bundle_from_json(
                            json.dumps(bundle), True
                        )
                    # 06 - Save the state
                    self.helper.set_state({"current": entry.name})
                else:
                    self.helper.log_info("restore dir (worker bundles):" + entry.name)
                    self.helper.send_stix2_bundle(
                        json.dumps(stix_bundle), work_id=work_id
                    )
                    message = "Restore dir run, storing last_run as {0}".format(
                        entry.name
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    # 06 - Save the state
                    self.helper.set_state({"current": entry.name})
        self.helper.log_info("restore run completed")

    def start(self):
        # Check if the directory exists
        if not os.path.exists(self.backup_path + "/opencti_data"):
            raise ValueError("Backup path does not exist")
        self.restore_files()


if __name__ == "__main__":
    json_conf = sys.argv[1] if len(sys.argv) > 1 else None
    conf = json.loads(json_conf) if json_conf is not None else {}
    RestoreFilesInstance = RestoreFilesConnector(conf)
    RestoreFilesInstance.start()
