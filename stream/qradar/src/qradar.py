################################
# Qradar Connector for OpenCTI #
################################

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue

import requests
import yaml
from prometheus_client import Counter, Gauge, start_http_server
from pycti import OpenCTIConnectorHelper, get_config_variable


class QradarReference:
    def __init__(
        self,
        qradar_url: str,
        qradar_token: str,
        qradar_reference_name: str,
        qradar_ssl_verify: bool,
    ) -> None:
        self.qradar_url = qradar_url
        self.qradar_token = qradar_token
        self.qradar_reference_name = qradar_reference_name
        self.qradar_ssl_verify = qradar_ssl_verify

    @property
    def collection_url(self) -> str:
        return f"{self.qradar_url}/api/reference_data/sets/{self.qradar_reference_name}"

    @property
    def headers(self) -> dict:
        return {
            "SEC": f"{self.qradar_token}",
        }

    def init(self) -> bool:
        return True

    def get_type(self, payload):
        return re.search(
            "main_observable_type': '(.*?)'", str(payload["extensions"])
        ).group(1)

    def create_refernce(self, name: str):
        r = requests.post(
            f"{self.qradar_url}/api/reference_data/sets?element_type=ALN&name={self.qradar_reference_name}_{name}",
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        return r.status_code < 300

    def create(self, id: str, payload: dict):
        payload["_key"] = id
        r = requests.post(
            f"{self.collection_url}_{self.get_type(payload)}",
            {"value": payload.get("name")},
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        if r.status_code == 404:
            self.create_refernce(self.get_type(payload))
            self.create(id, payload)
        else:
            r.raise_for_status()

    def update(self, id: str, payload: dict):
        payload["_key"] = id

        r = requests.post(
            f"{self.collection_url}/{self.qradar_reference_name}_{self.get_type(payload)}",
            {"value": payload.get("name")},
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        if r.status_code == 404:
            self.create(id, payload)
        else:
            r.raise_for_status()

    def delete(self, id: str, payload):
        r = requests.delete(
            f"{self.collection_url}/{self.qradar_reference_name}_{self.get_type(payload)}/{payload.get('name')}",
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        if r.status_code != 404:
            r.raise_for_status()


class Metrics:
    def __init__(self, name: str, addr: str, port: int) -> None:
        self.name = name
        self.addr = addr
        self.port = port

        self._processed_messages_counter = Counter(
            "processed_messages", "Number of processed messages", ["name", "action"]
        )
        self._current_state_gauge = Gauge(
            "current_state", "Current connector state", ["name"]
        )

    def msg(self, action: str):
        self._processed_messages_counter.labels(self.name, action).inc()

    def state(self, event_id: str):
        """Set current state metric from an event id.

        An event id looks like 1679004823824-0, it contains time information
        about when the event was generated."""

        ts = int(event_id.split("-")[0])
        self._current_state_gauge.labels(self.name).set(ts)

    def start_server(self):
        start_http_server(self.port, addr=self.addr)


class QradarConnector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        qradar_reference: QradarReference,
        queue: Queue,
        ignore_types: list[str],
        consumer_count: int,
        metrics: Metrics | None = None,
    ) -> None:
        self.qradar_reference = qradar_reference
        self.queue = queue
        self.helper = helper
        self.ignore_types = ignore_types
        self.metrics = metrics
        self.consumer_count = consumer_count

        self._org_name_cache = {}

    def is_filtered(self, data: dict):
        return "type" in data and data["type"] in self.ignore_types

    def get_org_name(self, entity_id: str) -> str | None:
        if entity_id in self._org_name_cache:
            return self._org_name_cache.get(entity_id)

        entity = self.helper.api.stix_domain_object.read(id=entity_id)
        org_name = entity.get("name")
        self._org_name_cache[entity_id] = org_name

        return org_name

    def register_producer(self):
        self.helper.listen_stream(self.produce)

    def produce(self, msg):
        self.queue.put(msg)

    def start_consumers(self):
        self.helper.log_info(f"starting {self.consumer_count} consumer threads")
        with ThreadPoolExecutor() as executor:
            for _ in range(self.consumer_count):
                executor.submit(self.consume)

    def consume(self):
        # ensure the process stop when there is an issue while
        # processing message
        try:
            self._consume()
        except Exception as e:
            self.helper.log_error("an error occurred while consuming messages")
            self.helper.log_error(e)
            os._exit(1)  # exit the current process, killing all threads

    def _consume(self):
        while True:
            msg = self.queue.get()

            payload = json.loads(msg.data)["data"]
            id = OpenCTIConnectorHelper.get_attribute_in_extension("id", payload)

            self.helper.log_debug(f"processing message with id {id}")

            if self.is_filtered(payload):
                self.helper.log_debug(f"item with id {id} is filtered")
                continue

            match msg.event:
                case "create":
                    self.qradar_reference.create(id, payload)
                    self.helper.log_debug(f"reference_set item with id {id} created")

                case "update":
                    self.qradar_reference.update(id, payload)
                    self.helper.log_debug(f"reference_set item with id {id} updated")

                case "delete":
                    self.helper.log_debug(f"reference_set item with id {id} deleted")
                    self.qradar_reference.delete(id, payload)

            if self.metrics is not None:
                self.metrics.msg(msg.event)
                self.metrics.state(msg.id)

    def start(self):
        if self.qradar_reference.init():
            self.helper.log_info("reference_set created")
        else:
            self.helper.log_warning("unable to create reference_set")

        self.register_producer()
        self.start_consumers()


def fix_loggers() -> None:
    logging.getLogger(
        "stix_shifter_modules.qradar.stix_translation.query_translator"
    ).setLevel(logging.CRITICAL)
    logging.getLogger("stix_shifter.stix_translation.stix_translation").setLevel(
        logging.CRITICAL
    )
    logging.getLogger(
        "stix_shifter_utils.stix_translation.stix_translation_error_mapper"
    ).setLevel(logging.CRITICAL)


def load_config_file() -> dict:
    config_file = Path(__file__).parent / "config.yml"

    if not config_file.is_file():
        return {}

    config_content = config_file.read_text()
    config = yaml.safe_load(config_content)
    return config


def check_helper(helper: OpenCTIConnectorHelper) -> None:
    if (
        helper.connect_live_stream_id is None
        or helper.connect_live_stream_id == "ChangeMe"
    ):
        helper.log_error("missing Live Stream ID")
        exit(1)


if __name__ == "__main__":
    # fix loggers
    fix_loggers()

    # load and check config
    config = load_config_file()
    # create opencti helper
    helper = OpenCTIConnectorHelper(config)
    helper.log_info("connector helper initialized")
    check_helper(helper)

    # read config
    ignore_types = get_config_variable(
        "QRADAR_IGNORE_TYPES", ["qradar", "ignore_types"], config
    ).split(",")
    qradar_url = get_config_variable("QRADAR_URL", ["qradar", "url"], config)
    qradar_token = get_config_variable("QRADAR_TOKEN", ["qradar", "token"], config)
    qradar_ssl_verify = get_config_variable(
        "QRADAR_SSL_VERIFY", ["qradar", "ssl_verify"], config, False, True
    )
    qradar_reference_name = get_config_variable(
        "QRADAR_REFERENCE_NAME", ["qradar", "reference_name"], config
    )

    # additional connector conf
    consumer_count: int = get_config_variable(
        "CONNECTOR_CONSUMER_COUNT",
        ["connector", "consumer_count"],
        config,
        isNumber=True,
        default=10,
    )

    # metrics conf
    enable_prom_metrics: bool = get_config_variable(
        "METRICS_ENABLE", ["metrics", "enable"], config, default=False
    )
    metrics_port: int = get_config_variable(
        "METRICS_PORT", ["metrics", "port"], config, isNumber=True, default=9113
    )
    metrics_addr: str = get_config_variable(
        "METRICS_ADDR", ["metrics", "addr"], config, default="0.0.0.0"
    )

    # create reference_set instance
    reference_set = QradarReference(
        qradar_url,
        qradar_token,
        qradar_reference_name,
        qradar_ssl_verify,
    )

    # create queue
    queue = Queue(maxsize=2 * consumer_count)

    # create prom metrics
    if enable_prom_metrics:
        metrics = Metrics(helper.connect_name, metrics_addr, metrics_port)
        helper.log_info(f"starting metrics server on {metrics_addr}:{metrics_port}")
        metrics.start_server()
    else:
        metrics = None

    # create connector and start
    QradarConnector(
        helper,
        reference_set,
        queue,
        ignore_types,
        consumer_count,
        metrics=metrics,
    ).start()
