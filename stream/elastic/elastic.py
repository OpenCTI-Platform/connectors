import json
import sys
import threading
import time
from datetime import datetime, timezone
from logging import getLogger

from elasticsearch import Elasticsearch
from pycti import OpenCTIConnectorHelper
from scalpl import Cut

from . import LOGGER_NAME
from .import_manager import IntelManager, StixManager
from .sightings_manager import SignalsManager

logger = getLogger(LOGGER_NAME)


class ElasticConnector:
    def __init__(self, config: dict = {}, datadir: str = None):
        self.shutdown_event: threading.Event = threading.Event()

        self.helper = OpenCTIConnectorHelper(config)
        logger.info("Connected to OpenCTI")

        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing Live Stream ID")

        self.config = Cut(config)

        # Start streaming from 1 second ago
        self.helper.set_state(
            {"connectorLastEventId": str(int(round(time.time() * 1000)) - 1000)}
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
        self.config["opencti.platform_url"] = _settings.get("platform_url", None)

        self._connect_elasticsearch()

        if self.config["connector.mode"] == "ecs":
            self.import_manager = IntelManager(
                self.helper, self.elasticsearch, self.config, datadir
            )

            self.sightings_manager = SignalsManager(
                config=self.config,
                shutdown_event=self.shutdown_event,
                opencti_client=self.helper,
                elasticsearch_client=self.elasticsearch,
            )
        elif self.config["connector.mode"] == "stix":
            self.import_manager = StixManager(
                self.helper, self.elasticsearch, self.config, datadir
            )

            self.sightings_manager = None
        else:
            logger.error(
                f"connector.mode: {self.config['connector.mode']} is unsupported. Should be 'ecs' or 'stix'"
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
            ssl_ver = (
                "True"
                == str(
                    self.config.get("output.elasticsearch.ssl_verify", True)
                ).capitalize()
            )
            self.elasticsearch = Elasticsearch(
                hosts=self.config.get("output.elasticsearch.hosts", ["localhost:9200"]),
                http_auth=_httpauth,
                api_key=_apikey,
                verify_certs=ssl_ver,
            )

        logger.info("Connected to Elasticsearch")

        return

    def handle_create(self, timestamp: datetime, data: dict) -> None:
        logger.debug("[CREATE] Processing indicator {" + data["id"] + "}")

        self.import_manager.import_cti_event(timestamp, data)
        return

    def handle_update(self, timestamp, data):
        logger.debug("[UPDATE] Processing indicator {" + data["id"] + "}")

        self.import_manager.import_cti_event(timestamp, data, is_update=True)
        return

    def handle_delete(self, timestamp, data):
        logger.debug("[DELETE] Processing indicator {" + data["id"] + "}")

        self.import_manager.delete_cti_event(data)
        return

    def _process_message(self, msg) -> None:
        logger.debug("_process_message")

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
            return self.handle_create(timestamp, data)

        if msg.event == "update":
            return self.handle_update(timestamp, data)

        if msg.event == "delete":
            return self.handle_delete(timestamp, data)

    def start(self) -> None:
        self.shutdown_event.clear()

        if self.config["connector.mode"] == "ecs":
            self.sightings_manager.start()

        # Look out, this doesn't block
        self.helper.listen_stream(self._process_message)

        try:
            # Just wait here until someone presses ctrl+c
            self.shutdown_event.wait()
        except KeyboardInterrupt:
            self.shutdown_event.set()

        logger.info("Shutting down")

        if self.config["connector.mode"] == "ecs":
            self.sightings_manager.join(timeout=3)
            if self.sightings_manager.is_alive():
                logger.warn("Sightings manager didn't shutdown by request")

        self.elasticsearch.close()
        logger.info(
            "Main thread complete. Waiting on background threads to complete. Press CTRL+C to quit."
        )
