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
            }
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

    def _process_intel(
        self, entity_type, timestamp, data, original_intel_document=None
    ):
        entity = None
        intel_document = None
        creation_time = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")

        threatintel_data = {
            "@timestamp": timestamp,
            "event": {
                "created": creation_time,
                "kind": "enrichment",
                "category": "threat",
                "type": "indicator",
                "dataset": "threatintel.opencti",
            },
            "threatintel": {},
        }

        if entity_type == "indicator":
            logger.trace(f"Querying indicator: { data['data']['x_opencti_id'] }")
            entity = self.helper.api.indicator.read(id=data["data"]["x_opencti_id"])

            #             query = """
            # query IndicatorQuery($id: String!) {
            #   indicator(id: $id) {
            #     id
            #     revoked
            #     externalReferences {
            #       ... on ExternalReferenceConnection {
            #         edges {
            #           node {
            #             url
            #           }
            #         }
            #       }
            #     }
            #     valid_from
            #     valid_until
            #     x_opencti_detection
            #     x_opencti_score
            #     confidence
            #     pattern
            #     pattern_type
            #     x_mitre_platforms

            #     name
            #     description
            #     createdBy {
            #       ... on Organization {
            #         name
            #       }
            #       ... on Individual {
            #         name
            #       }
            #     }

            #     indicator_types

            #     objectMarking {
            #       edges {
            #         node {
            #           definition
            #           definition_type
            #         }
            #       }
            #     }
            #   }
            # }
            # """
            # entity = self.helper.api.query(
            #     query, variables={"id": data["data"]["x_opencti_id"]})

            logger.trace(entity)

            if (
                entity is None
                or entity["revoked"]
                or entity["pattern_type"] not in self.es_config["indicator_types"]
            ):
                return None

            if "externalReferences" in entity:
                threatintel_data["event"]["reference"] = [
                    item.get("url", None) for item in entity["externalReferences"]
                ]

            if self.platform_url is not None:
                threatintel_data["event"][
                    "url"
                ] = f"{self.platform_url}/dashboard/observations/indicators/{entity['id']}"

            threatintel_data["threatintel"]["opencti"] = {
                "internal_id": entity.get("id", None),
                "valid_from": entity.get("valid_from", None),
                "valid_until": entity.get("valid_until", None),
                "enable_detection": entity.get("x_opencti_detection", None),
                "risk_score": entity.get("x_opencti_score", None),
                "confidence": entity.get("confidence", None),
                "original_pattern": entity.get("pattern", None),
                "pattern_type": entity.get("pattern_type", None),
            }

            if entity.get("x_mitre_platforms", None):
                threatintel_data["threatintel"]["opencti"]["mitre"] = {
                    "platforms": entity.get("x_mitre_platforms", None)
                }

            if entity["pattern_type"] == "stix":
                logger.trace("STIX entity type===================")
                intel_document = self._create_ecs_indicator_stix(
                    entity, threatintel_data, original_intel_document
                )

            logger.trace("intel_document")
            logger.trace(intel_document)

        elif (
            StixCyberObservableTypes.has_value(entity_type)
            and entity_type.lower() in self.elastic_observable_types
        ):
            entity = self.helper.api.stix_cyber_observable.read(
                id=data["data"]["x_opencti_id"]
            )
            if entity is None or entity["revoked"]:
                return {"entity": entity, "intel_document": intel_document}

        intel_document = {k: v for k, v in intel_document.items() if v is not None}

        # intel_document = self._create_observable(entity, original_intel_document)
        return {"entity": entity, "intel_document": intel_document}

    def handle_create_indicator(self, timestamp: datetime, data: dict):
        logger.debug("[CREATE] Processing indicator {" + data["id"] + "}")

        if self.elastic_import_label == "*":
            return self.import_manager.import_threatintel_from_indicator(
                timestamp, data
            )

    def handle_update_indicator(self, timestamp, data):
        pass

    def handle_delete_indicator(self, timestamp, data):
        pass

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

    def start(self):
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
            else:
                retries_left = 0

        logger.info("Shutting down")
        self.shutdown_event.set()
        self.sightings_manager.join()
