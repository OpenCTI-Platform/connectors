import os
import yaml
import json

from elasticsearch import Elasticsearch
from pycti import OpenCTIConnectorHelper


class HistoryConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.logger_config = self.helper.api.get_logs_worker_config()
        self.elasticsearch = Elasticsearch([self.logger_config["elasticsearch_url"]])
        self.elasticsearch_index = self.logger_config["elasticsearch_index"]

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)
            history_data = {
                "internal_id": msg.id,
                "event_type": msg.event,
                "timestamp": data["timestamp"],
                "user_id": data["user"],
                "context_data": {
                    "id": data["data"]["x_opencti_internal_id"]
                    if "x_opencti_internal_id" in data["data"]
                    else data["data"]["x_opencti_id"],
                    "entity_type": data["data"]["type"],
                    "from_id": data["data"]["x_opencti_source_ref"]
                    if "x_opencti_source_ref" in data["data"]
                    else None,
                    "to_id": data["data"]["x_opencti_target_ref"]
                    if "x_opencti_target_ref" in data["data"]
                    else None,
                    "message": data["message"],
                },
            }
            self.elasticsearch.index(
                index=self.elasticsearch_index, id=msg.id, body=history_data
            )
        except:
            pass

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    HistoryInstance = HistoryConnector()
    HistoryInstance.start()
