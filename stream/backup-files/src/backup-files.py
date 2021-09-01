################################
# OpenCTI Backup Files         #
################################

import os
import yaml
import json

from pycti import OpenCTIConnectorHelper, get_config_variable


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

    def write_file(self, entity_type, entity_id, bundle):
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
        path = self.backup_path + "/opencti_data/" + entity_type + "/" + entity_id.split("--")[1][0]
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
                self.write_file(data["data"]["type"], data["data"]["id"], bundle)
            elif msg.event == "update":
                bundle = {
                    "type": "bundle",
                    "x_opencti_event_version": data["version"],
                    "objects": [data["data"]],
                }
                self.write_file(data["data"]["type"], data["data"]["id"], bundle)
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
