import json
import sys
import threading
import time
from datetime import datetime, timezone
from logging import getLogger

from elasticsearch import Elasticsearch
from pycti import OpenCTIConnectorHelper
from requests.exceptions import ConnectionError
from scalpl import Cut

from .import_manager import IntelManager
from .sightings_manager import SignalsManager

logger = getLogger("elastic-threatintel-connector")


class ElasticThreatIntelConnector:
    def __init__(self, config: dict = {}, datadir: str = None):
        self.shutdown_event: threading.Event = threading.Event()

        self.helper = OpenCTIConnectorHelper(config)
        logger.info("Connected to OpenCTI")

        self.config = Cut(config)
        # Set first event start time
        if self.config.get("elastic.import_from_date", None):
            try:
                # Convert configured value to UTC epoch
                _value = self.config.get("elastic.import_from_date")
                _t = int(round(datetime.fromisoformat(_value).timestamp() * 1000))
                self.config["elastic.import_from_date"] = _t
            except ValueError:
                logger.error(
                    "Invalid 'elastic.import_from_date' format. It must be in ISO format matching the pattern: YYYY-MM-DD[*HH[:MM[:SS[.fff[fff]]]][+HH:MM[:SS[.ffffff]]]]"
                )
                sys.exit(1)
        else:
            # Start from the beginning of the current second
            self.config["elastic.import_from_date"] = (
                int(round(time.time() * 1000)) - 1000
            )

        self.helper.set_state(
            {"connectorLastEventId": self.config["elastic.import_from_date"]}
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
        self.config["elastic.platform_url"] = _settings.get("platform_url", None)

        self._connect_elasticsearch()

        self.import_manager = IntelManager(
            self.helper, self.elasticsearch, self.config, datadir
        )

        self.sightings_manager = SignalsManager(
            config=self.config,
            shutdown_event=self.shutdown_event,
            opencti_client=self.helper,
            elasticsearch_client=self.elasticsearch,
        )

    def _connect_elasticsearch(self) -> None:
        _apikey: tuple(str) = None
        _httpauth: tuple(str) = None

        if self.config.get("cloud.auth", None):
            _httpauth = tuple(self.config.get("cloud.auth").split(":"))
        elif self.config.get("output.elasticsearch.username", None) and self.config.get(
            "output.elasticsearch.password", None
        ):
            _httpauth = (
                self.config.get("output.elasticsearch.username"),
                self.config.get("output.elasticsearch.password"),
            )

        if self.config.get("output.elasticsearch.api_key", None):
            _apikey = tuple(self.config.get("output.elasticsearch.api_key").split(":"))

        if _httpauth is not None and _apikey is not None:
            logger.critical(
                "Either username/password auth or api_key auth should be used for Elasticsearch, not both."
            )
            sys.exit(1)

        if self.config.get("cloud.id", None):
            logger.debug(
                f"Connecting to Elasticsearch using cloud.id {self.config.get('cloud.id')}"
            )
            self.elasticsearch = Elasticsearch(
                cloud_id=self.config.get("cloud.id"),
                verify_certs=self.config.get("output.elasticsearch.ssl_verify", True),
                http_auth=_httpauth,
                api_key=_apikey,
            )
        else:
            logger.debug(
                f"Connecting to Elasticsearch using hosts: {self.config.get('output.elasticsearch.hosts', ['localhost:9200'])}"
            )
            self.elasticsearch = Elasticsearch(
                hosts=self.config.get("output.elasticsearch.hosts", ["localhost:9200"]),
                verify_certs=self.config.get("output.elasticsearch.ssl_verify", True),
                http_auth=_httpauth,
                api_key=_apikey,
            )

        logger.info("Connected to Elasticsearch")

        return

    def handle_create_indicator(self, timestamp: datetime, data: dict) -> None:
        logger.debug("[CREATE] Processing indicator {" + data["id"] + "}")

        if self.config["elastic.import_label"] == "*":
            self.import_manager.import_threatintel_from_indicator(timestamp, data)
            return

        if ("labels" not in data) or (
            self.config["elastic.import_label"] not in data["labels"]
        ):
            logger.info(
                "[CREATE] No label corresponding to import filter, doing nothing"
            )
            return

        if self.config["elastic.import_label"] in data["labels"]:
            self.import_manager.import_threatintel_from_indicator(timestamp, data)
            return

    def handle_update_indicator(self, timestamp, data):
        logger.debug("[UPDATE] Processing indicator {" + data["id"] + "}")
        """
        {"id": "indicator--4d649d3a-d6ca-5dbc-8ed1-767f4a5fa23b", "x_opencti_id": "ab717e44-ccae-40b6-ad37-9183527d3392", "type": "indicator", "x_data_update": {"replace": {"valid_until": "2021-06-10T18:07:00.000Z", "revoked": false}}}
        """

        if self.config["elastic.import_label"] == "*":
            self.import_manager.import_threatintel_from_indicator(
                timestamp, data, is_update=True
            )
            return

        if ("labels" not in data) or (
            self.config["elastic.import_label"] not in data["labels"]
        ):
            logger.info(
                "[UPDATE] No label corresponding to import filter, doing nothing"
            )
            return

        if self.config["elastic.import_label"] in data["labels"]:
            self.import_manager.import_threatintel_from_indicator(
                timestamp, data, is_update=True
            )
            return

    def handle_delete_indicator(self, timestamp, data):
        logger.debug("[DELETE] Processing indicator {" + data["id"] + "}")

        if self.config["elastic.import_label"] == "*":
            self.import_manager.delete_threatintel_from_indicator(data)

        if ("labels" not in data) or (
            self.config["elastic.import_label"] not in data["labels"]
        ):
            logger.info(
                "[DELETE] No label corresponding to import filter, doing nothing"
            )
            return

        if self.config["elastic.import_label"] in data["labels"]:
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
                and data["pattern_type"] in self.config["elastic.indicator_types"]
            ):
                logger.trace(data)
                return self.handle_create_indicator(timestamp, data)

            return None

        if msg.event == "update":
            logger.trace(f"[UPDATE]: {json.dumps(data)}")
            if data["type"] == "indicator":
                return self.handle_update_indicator(timestamp, data)

            return None

        if msg.event == "delete":
            if data["type"] == "indicator":
                logger.trace(data)
                return self.handle_delete_indicator(timestamp, data)

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
            logger.warn("Sightings manager didn't shutdown by request")

        logger.info(
            "Main thread complete. Waiting on background threads to complete. Press CTRL+C to quit."
        )
