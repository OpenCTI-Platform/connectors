import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from logging import getLogger

from elasticsearch import Elasticsearch
from pycti import OpenCTIConnectorHelper, StixCyberObservableTypes, get_config_variable
from requests.exceptions import ConnectionError

from .sightings_manager import SignalsManager
from .import_manager import IntelManager

logger = getLogger("elastic-threatintel-connector")


class ElasticThreatIntelConnector:
    def __init__(self, config: dict = {}, datadir: str = None):
        self.shutdown_event: threading.Event = threading.Event()

        self.helper = OpenCTIConnectorHelper(config)

        logger.info("Connected to OpenCTI")
        # TODO: Add option for starting queue X time period ago
        self.helper.set_state(
            {"connectorLastEventId": int(round(time.time() * 1000)) - 1000}
        )
        self.msg_count = 0

        self.opencti_ext_url = get_config_variable(
            "OPENCTI_EXTERNAL_URL", ["opencti", "external_url"], config
        )

        self.es_config = {
            "elastic": {
                "elasticsearch_url": get_config_variable(
                    "ELASTIC_URL", ["elastic", "url"], config
                ),
                "ssl_verify": get_config_variable(
                    "ELASTIC_SSL_VERIFY", ["elastic", "ssl_verify"], config, False, True
                ),
                "cloud_id": get_config_variable(
                    "ELASTIC_CLOUD_ID", ["elastic", "cloud.id"], config
                ),
                "api_key": get_config_variable(
                    "ELASTIC_API_KEY", ["elastic", "api_key"], config
                ),
                "username": get_config_variable(
                    "ELASTIC_USERNAME", ["elastic", "username"], config
                ),
                "password": get_config_variable(
                    "ELASTIC_PASSWORD", ["elastic", "password"], config
                ),
            },
            "connector": {
                "entity_name": get_config_variable(
                    "CONNECTOR_ENTITY_NAME", ["connector", "entity_name"], config
                ),
                "entity_description": get_config_variable(
                    "CONNECTOR_ENTITY_NAME", ["connector", "entity_name"], config
                ),
            },
        }

        # Get setup configuration
        _value = get_config_variable("ELASTIC_SETUP_JSON", ["elastic", "setup"], config)
        if _value is not None and not isinstance(_value, dict):
            try:
                _value = json.loads(_value)
            except json.JSONDecodeError:
                logger.error("ELASTIC_SETUP_JSON env var is not a valid JSON string")
                sys.exit(-1)

        if isinstance(_value, dict):
            self.es_config["elastic"]["setup"] = _value

        # Get signals configuration
        _value = get_config_variable(
            "ELASTIC_SIGNALS_JSON", ["elastic", "signals"], config
        )
        if _value is not None and not isinstance(_value, dict):
            try:
                _value = json.loads(_value)
            except json.JSONDecodeError:
                logger.error("ELASTIC_SIGNALS_JSON env var is not a valid JSON string")
                sys.exit(-1)

        if isinstance(_value, dict):
            self.es_config["elastic"]["signals"] = _value

        # Get import start date
        _value = get_config_variable(
            "ELASTIC_IMPORT_FROM_DATE", ["elastic", "import_from_date"], config
        )
        try:
            self.elastic_import_from_date = datetime.fromisoformat(_value)
        except ValueError:
            self.helper.log_error("Invalid ELASTIC_IMPORT_FROM_DATE format. Skipping")

        # Get indicator types
        _value = get_config_variable(
            "ELASTIC_INDICATOR_TYPES", ["elastic", "indicator_types"], config
        )
        # Try to split a CSV value
        if isinstance(_value, str):
            _value = _value.split(",")
        if isinstance(_value, list):
            self.es_config["elastic"]["indicator_types"] = _value
        else:
            raise ValueError("Invalid setting for ELASTIC_INDICATOR_TYPES")

        # Optionally allow labels
        self.elastic_import_label = get_config_variable(
            "ELASTIC_IMPORT_LABEL", ["elastic", "import_label"], config, False, ""
        )

        # Get the external URL as configured in OpenCTI Settings page
        query = """
        query SettingsQuery {
            settings {
                id
                platform_url
            }
        }
        """
        _settings = self.helper.api.query(query)["data"]["settings"]
        self.es_config["elastic"]["platform_url"] = _settings.get("platform_url", None)

        api_key: tuple(str) = None
        http_auth: tuple(str) = None

        if self.es_config["elastic"].get("username", None) and self.es_config.get(
            "password", None
        ):
            http_auth = (
                self.es_config["elastic"].get("username"),
                self.es_config["elastic"].get("password"),
            )

        api_key = None
        if self.es_config["elastic"].get("api_key", None):
            api_key = tuple(self.es_config["elastic"].get("api_key").split(":"))

        assert (http_auth is None or api_key is None) and (
            http_auth is not None or api_key is not None
        )

        logger.trace(f"http_auth: {http_auth}")
        logger.trace(f"api_key: {api_key}")

        if self.es_config["elastic"].get("cloud_id"):
            self.elasticsearch = Elasticsearch(
                cloud_id=self.es_config["elastic"].get("cloud_id"),
                verify_certs=self.es_config["elastic"].get("ssl_verify"),
                http_auth=http_auth,
                api_key=api_key,
            )
        elif self.es_config["elastic"].get("elasticsearch_url"):
            self.elasticsearch = Elasticsearch(
                [self.es_config["elastic"].get("elasticsearch_url")],
                verify_certs=self.es_config["elastic"].get("ssl_verify"),
                http_auth=http_auth,
                api_key=api_key,
            )

        logger.info("Connected to Elasticsearch")

        self.import_manager = IntelManager(
            self.helper, self.elasticsearch, self.es_config, datadir
        )

        self.sightings_manager = SignalsManager(
            config=self.es_config,
            shutdown_event=self.shutdown_event,
            opencti_client=self.helper,
            elasticsearch_client=self.elasticsearch,
        )

    def handle_create_indicator(self, timestamp: datetime, data: dict) -> None:
        logger.debug("[CREATE] Processing indicator {" + data["id"] + "}")

        if self.elastic_import_label == "*":
            self.import_manager.import_threatintel_from_indicator(timestamp, data)
            return

        # If no label in this creation and import if filtered
        if ("labels" not in data) or (self.elastic_import_label not in data["labels"]):
            self.helper.log_info(
                "[CREATE] No label corresponding to import filter, doing nothing"
            )
            return

        if self.elastic_import_label in data["labels"]:
            self.import_manager.import_threatintel_from_indicator(timestamp, data)
            return

    def handle_update_indicator(self, timestamp, data):
        logger.debug("[UPDATE] Processing indicator {" + data["id"] + "}")

        if self.elastic_import_label == "*":
            self.import_manager.import_threatintel_from_indicator(
                timestamp, data, is_update=True
            )
            return

        # If no label in this creation and import if filtered
        if ("labels" not in data) or (self.elastic_import_label not in data["labels"]):
            self.helper.log_info(
                "[UPDATE] No label corresponding to import filter, doing nothing"
            )
            return

        if self.elastic_import_label in data["labels"]:
            self.import_manager.import_threatintel_from_indicator(
                timestamp, data, is_update=True
            )
            return

    def handle_delete_indicator(self, timestamp, data):
        logger.debug("[DELETE] Processing indicator {" + data["id"] + "}")

        if self.elastic_import_label == "*":
            self.import_manager.delete_threatintel_from_indicator(data)
        # If no label in this creation and import if filtered
        if ("labels" not in data) or (self.elastic_import_label not in data["labels"]):
            self.helper.log_info(
                "[DELETE] No label corresponding to import filter, doing nothing"
            )
            return

        if self.elastic_import_label in data["labels"]:
            self.import_manager.delete_threatintel_from_indicator(data)
            return

    def _process_message(self, msg) -> None:
        try:
            event_id = msg.id
            timestamp = datetime.fromtimestamp(
                round(int(event_id.split("-")[0]) / 1000), tz=timezone.utc
            )
            data = json.loads(msg.data)["data"]
        except ValueError:
            logger.error(f"Unable to process the message: {msg}")
            raise ValueError("Cannot process the message: " + msg)

        logger.debug(f"[PROCESS] Message (id: {event_id}, date: {timestamp})")

        if msg.event == "create":
            if (
                data["type"] == "indicator"
                and data["pattern_type"] in self.es_config["elastic"]["indicator_types"]
            ):
                logger.trace(data)
                return self.handle_create_indicator(timestamp, data)

            return None

        if msg.event == "update":
            if (
                data["type"] == "indicator"
                and data["pattern_type"] in self.es_config["elastic"]["indicator_types"]
            ):
                return self.handle_update_indicator(timestamp, data)

            return None

        if msg.event == "delete":
            if data["type"] == "indicator":
                logger.trace(data)
                return self.handle_delete_indicator(timestamp, data)

            # No label
            if "labels" not in data["data"] and self.elastic_import_label != "*":
                logger.info("No label marked as import, doing nothing")
                return
            # Import or exceptionlist labels are not in the given labels
            elif (
                "labels" in data and self.elastic_import_label not in data["labels"]
            ) and self.elastic_import_label != "*":
                logger.info(
                    "No label marked as import or no global label, doing nothing"
                )
                return

            if (
                "labels" in data and self.elastic_import_label in ["labels"]
            ) or self.elastic_import_label == "*":

                if self.msg_count % 13 == 0:
                    print(
                        f"Message count: {self.msg_count}      \tEntity: {data['type']}"
                    )
                    print(json.dumps(msg.__dict__, sort_keys=True, indent=4))
                    print("=========================================================")

    def start(self) -> None:
        retries_left = 10

        self.shutdown_event.clear()
        self.sightings_manager.start()

        while retries_left > 0:
            try:
                logger.info("Streaming events from OpenCTI")
                self.helper.listen_stream(self._process_message)
            except ConnectionError:
                retries_left -= 1
                logger.warn("Disconnected from OpenCTI")
            except KeyboardInterrupt:
                retries_left = 0
                break
            except Exception as e:
                logger.error("Something went wrong")
                retries_left = 0
                raise e

        logger.info("Shutting down")
        self.shutdown_event.set()
        self.elasticsearch.close()

        self.sightings_manager.join(timeout=3)
        if self.sightings_manager.is_alive():
            logger.warn("Killing sightings manager")

        logger.info(
            "Main thread complete. Waiting on background threads to complete. Press CTRL+C to quit."
        )
