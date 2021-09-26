################################
# OpenCTI Backup Files         #
################################

import os
import yaml
import json

from pycti import OpenCTIConnectorHelper, get_config_variable, StixMetaTypes


class BackupFilesConnector:
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

    def _enrich_with_files(self, current):
        entity = current
        files = []
        if entity["type"] != "relationship" and not StixMetaTypes.has_value(
            entity["type"]
        ):
            files = self.helper.api.stix_core_object.list_files(id=entity["id"])
        elif entity["type"] == "external-reference":
            files = self.helper.api.external_reference.list_files(id=entity["id"])
        if len(files) > 0:
            entity["x_opencti_files"] = []
            for file in files:
                url = (
                    self.helper.api.api_url.replace("graphql", "storage/get/")
                    + file["id"]
                )
                data = self.helper.api.fetch_opencti_file(
                    url, binary=True, serialize=True
                )
                entity["x_opencti_files"].append(
                    {
                        "name": file["name"],
                        "data": data,
                        "mime_type": file["metaData"]["mimetype"],
                    }
                )
        return entity

    def write_files(self, entity_type, entity_id, bundle):
        path = self.backup_path + "/opencti_data"
        if not os.path.exists(path + "/" + entity_type):
            os.mkdir(path + "/" + entity_type)
        path = path + "/" + entity_type
        if not os.path.exists(path + "/" + entity_id.split("--")[1][0]):
            os.mkdir(path + "/" + entity_id.split("--")[1][0])
        path = path + "/" + entity_id.split("--")[1][0]
        with open(path + "/" + entity_id + ".json", "w") as file:
            json.dump(bundle, file, indent=4)

    def delete_file(self, entity_type, entity_id):
        path = (
            self.backup_path
            + "/opencti_data/"
            + entity_type
            + "/"
            + entity_id.split("--")[1][0]
        )
        if not os.path.exists(path):
            return
        if os.path.isfile(path + "/" + entity_id + ".json"):
            os.unlink(path + "/" + entity_id + ".json")

    def _process_message(self, msg):
        if msg.event == "create" or msg.event == "update" or msg.event == "delete":
            self.helper.log_info("Processing event " + msg.id)
            data = json.loads(msg.data)
            if msg.event == "create":
                bundle = {
                    "type": "bundle",
                    "x_opencti_event_version": data["version"],
                    "objects": [data["data"]],
                }
                data["data"] = self._enrich_with_files(data["data"])
                self.write_files(data["data"]["type"], data["data"]["id"], bundle)
            elif msg.event == "update":
                bundle = {
                    "type": "bundle",
                    "x_opencti_event_version": data["version"],
                    "objects": [data["data"]],
                }
                data["data"] = self._enrich_with_files(data["data"])
                self.write_files(data["data"]["type"], data["data"]["id"], bundle)
            elif msg.event == "delete":
                self.delete_file(data["data"]["type"], data["data"]["id"])

    def start(self):
        # Check if the directory exists
        if not os.path.exists(self.backup_path):
            raise ValueError("Backup path does not exist")
        if not os.path.exists(self.backup_path + "/opencti_data"):
            os.mkdir(self.backup_path + "/opencti_data")
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    BackupFilesInstance = BackupFilesConnector()
    BackupFilesInstance.start()
