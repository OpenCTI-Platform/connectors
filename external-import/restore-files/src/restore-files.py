################################
# OpenCTI Restore Files         #
################################
import os
import yaml
import json
import datetime

from pycti import OpenCTIConnectorHelper, get_config_variable


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
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
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
        state = self.helper.get_state()
        start_directory = state["current"] if state is not None else None
        start_date = (
            date_convert(start_directory) if start_directory is not None else None
        )
        path = self.backup_path + "/opencti_data"
        obj = os.scandir(path)
        print("Files and Directories in '% s':" % path)
        # cache_ids = {}
        for entry in obj:
            if entry.is_dir():
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
                # 06 - Send the bundle to the worker queue
                stix_bundle = {
                    "type": "bundle",
                    "objects": objects_with_missing,
                }
                self.helper.send_stix2_bundle(json.dumps(stix_bundle))
                # 06 - Save the state
                self.helper.set_state({"current": entry.name})

    def start(self):
        # Check if the directory exists
        if not os.path.exists(self.backup_path + "/opencti_data"):
            raise ValueError("Backup path does not exist")
        self.restore_files()


if __name__ == "__main__":
    RestoreFilesInstance = RestoreFilesConnector()
    RestoreFilesInstance.start()
