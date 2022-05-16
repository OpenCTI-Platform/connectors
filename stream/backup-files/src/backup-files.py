################################
# OpenCTI Backup Files         #
################################
import datetime
import json
import os
import sys

import yaml
from dateutil import parser
from pycti import OpenCTIConnectorHelper, get_config_variable


def round_time(dt, round_to=60):
    seconds = (dt.replace(tzinfo=None) - dt.min).seconds
    rounding = (seconds + round_to / 2) // round_to * round_to
    return dt + datetime.timedelta(0, rounding - seconds, -dt.microsecond)


class BackupFilesConnector:
    def __init__(self, conf_data):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else conf_data
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
        files = self.helper.api.get_attribute_in_extension("files", current)
        if files is not None and len(files) > 0:
            for file in files:
                file_data = self.helper.api.fetch_opencti_file(
                    file["uri"], binary=True, serialize=True
                )
                file["data"] = file_data
        return entity

    def write_files(self, date_range, entity_id, bundle):
        path = self.backup_path + "/opencti_data"
        if not os.path.exists(path + "/" + date_range):
            os.mkdir(path + "/" + date_range)
        path = path + "/" + date_range
        with open(path + "/" + entity_id + ".json", "w") as file:
            json.dump(bundle, file, indent=4)

    def delete_file(self, date_range, entity_id):
        path = self.backup_path + "/opencti_data/" + date_range
        if not os.path.exists(path):
            return
        if os.path.isfile(path + "/" + entity_id + ".json"):
            os.unlink(path + "/" + entity_id + ".json")

    def _process_message(self, msg):
        if msg.event == "create" or msg.event == "update" or msg.event == "delete":
            data = json.loads(msg.data)
            # created_at will be removed in next version
            created_at_extension = self.helper.api.get_attribute_in_extension(
                "created_at", data["data"]
            )
            creation_date = (
                created_at_extension
                if created_at_extension is not None
                else data["data"]["created_at"]
            )
            created_at = parser.parse(creation_date)
            date_range = round_time(created_at).strftime("%Y%m%dT%H%M%SZ")
            if msg.event == "create":
                bundle = {
                    "type": "bundle",
                    "objects": [data["data"]],
                }
                data["data"] = self._enrich_with_files(data["data"])
                self.write_files(date_range, data["data"]["id"], bundle)
            elif msg.event == "update":
                bundle = {
                    "type": "bundle",
                    "objects": [data["data"]],
                }
                data["data"] = self._enrich_with_files(data["data"])
                self.write_files(date_range, data["data"]["id"], bundle)
            elif msg.event == "delete":
                self.delete_file(date_range, data["data"]["id"])
            self.helper.log_info(
                "Backup processed event "
                + msg.id
                + " in "
                + date_range
                + " / "
                + data["data"]["id"]
            )

    def start(self):
        # Check if the directory exists
        if not os.path.exists(self.backup_path):
            raise ValueError("Backup path does not exist - " + self.backup_path)
        if not os.path.exists(self.backup_path + "/opencti_data"):
            os.mkdir(self.backup_path + "/opencti_data")
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    json_conf = sys.argv[1] if len(sys.argv) > 1 else None
    conf = json.loads(json_conf) if json_conf is not None else {}
    BackupFilesInstance = BackupFilesConnector(conf)
    BackupFilesInstance.start()
