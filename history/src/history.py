import datetime
import os

import elasticsearch
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
        if (
            self.logger_config["elasticsearch_username"] is not None
            and self.logger_config["elasticsearch_password"] is not None
        ):
            self.elasticsearch = Elasticsearch(
                [self.logger_config["elasticsearch_url"]],
                verify_certs=self.logger_config[
                    "elasticsearch_ssl_reject_unauthorized"
                ],
                http_auth=(
                    self.logger_config["elasticsearch_username"],
                    self.logger_config["elasticsearch_password"],
                ),
            )
        elif self.logger_config["elasticsearch_api_key"] is not None:
            self.elasticsearch = Elasticsearch(
                [self.logger_config["elasticsearch_url"]],
                verify_certs=self.logger_config[
                    "elasticsearch_ssl_reject_unauthorized"
                ],
                api_key=self.logger_config["elasticsearch_api_key"],
            )
        else:
            self.elasticsearch = Elasticsearch(
                [self.logger_config["elasticsearch_url"]],
                verify_certs=self.logger_config[
                    "elasticsearch_ssl_reject_unauthorized"
                ],
            )
        self.elasticsearch_index = self.logger_config["elasticsearch_index"]

    def _process_message(self, msg):
        try:
            event_json = json.loads(msg.data)
            unix_time = round(int(msg.id.split("-")[0]) / 1000)
            event_date = datetime.datetime.fromtimestamp(
                unix_time, datetime.timezone.utc
            )
            timestamp = event_date.isoformat().replace("+00:00", "Z")
            origin = event_json["origin"]
            history_data = {
                "internal_id": msg.id,
                "event_type": msg.event,
                "timestamp": timestamp,
                "entity_type": "history",
                "user_id": origin["user_id"],
                "applicant_id": origin["applicant_id"]
                if "applicant_id" in origin
                else None,
                "context_data": {
                    "id": event_json["data"]["x_opencti_internal_id"]
                    if "x_opencti_internal_id" in event_json["data"]
                    else event_json["data"]["x_opencti_id"],
                    "entity_type": event_json["data"]["type"],
                    "from_id": event_json["data"]["x_opencti_source_ref"]
                    if "x_opencti_source_ref" in event_json["data"]
                    else None,
                    "to_id": event_json["data"]["x_opencti_target_ref"]
                    if "x_opencti_target_ref" in event_json["data"]
                    else None,
                    "message": event_json["message"],
                },
            }
            self.elasticsearch.index(
                index=self.elasticsearch_index, id=msg.id, body=history_data
            )

        except elasticsearch.RequestError as err:
            print("Unexpected error:", err, msg)
            pass

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    HistoryInstance = HistoryConnector()
    HistoryInstance.start()
