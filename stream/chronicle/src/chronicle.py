################################
# Chronicle Connector for OpenCTI #
################################

import json
import logging
import os
import re
import urllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue


import yaml
from prometheus_client import Counter, Gauge, start_http_server
from pycti import OpenCTIConnectorHelper, get_config_variable
from google.oauth2 import service_account
from googleapiclient import _auth
from common import chronicle_auth
from common import regions
from google.auth.transport import requests

class ChronicleReference:
    def __init__(
            self,
            region: str,
            list_name: str,
            credential_file: str,
            url="https://backstory.googleapis.com",
    ) -> None:
        self.url = url
        self.region = region,
        self.credential_file = credential_file
        self.list_name = list_name

    @property
    def chronicle_url(self) -> str:
        return str(regions.url(self.url, self.region))

    @property
    def session(self) -> requests.AuthorizedSession:
        return chronicle_auth.initialize_http_session(self.credential_file)

    def init(self) -> bool:
        return True

    def create_list(self, payload):
        url = f"{self.url}/v2/lists"
        body = {
            "name": self.list_name,
            "description": "description",
            "lines": [payload],
            "content_type": "CONTENT_TYPE_DEFAULT_STRING",
        }
        response = self.session.request("POST", url, json=body)
        if response.status_code >= 400:
            print(response.status_code)
        response.raise_for_status()
        return response.json()["createTime"]

    def create_in_list(self, payload):
        lines = self.get_list()
        if payload not in lines:
            lines.append(str(payload))
            self.update_list(lines)

    def get_list(self):
        url = f"{self.url}/v2/lists/{self.list_name}"
        response = self.session.request("GET", url)
        if response.status_code >= 400:
            print(response.status_code)
        response.raise_for_status()
        return response.json()["lines"]

    def update_in_list(self, payload):
        lines = self.get_list()
        if payload not in lines:
            lines.append(str(payload))
            self.update_list(lines)

    def delete_in_list(self, payload):
        lines = self.get_list()
        if payload in lines:
            lines.pop(str(payload))
            self.update_list(lines)

    def update_list(self, payload):
        url = f"{self.chronicle_url}/v2/lists"
        body = {
            "name": self.list_name,
            "lines": payload,
            "content_type": "CONTENT_TYPE_DEFAULT_STRING",
        }
        update_fields = ["list.lines"]
        params = {"update_mask": ",".join(update_fields)}
        response = self.session.request("PATCH", url, params=params, json=body)
        if response.status_code >= 400:
            print(response.text)
        response.raise_for_status()
        return response.json()["createTime"]


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
        ts = int(event_id.split("-")[0])
        self._current_state_gauge.labels(self.name).set(ts)

    def start_server(self):
        start_http_server(self.port, addr=self.addr)


class ChronicleConnector:
    def __init__(
            self,
            helper: OpenCTIConnectorHelper,
            chronicle_reference: ChronicleReference,
            queue: Queue,
            ignore_types: list[str],
            consumer_count: int,
            metrics: Metrics | None = None,
    ) -> None:
        self.chronicle_reference = chronicle_reference
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
        try:
            self._consume()
        except Exception as e:
            self.helper.log_error("an error occurred while consuming messages")
            self.helper.log_error(e)
            os._exit(1)

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
                    self.chronicle_reference.create_in_list(payload)
                    self.helper.log_debug(f"reference_set item with id {id} created")

                case "update":
                    self.chronicle_reference.update_in_list(payload)
                    self.helper.log_debug(f"reference_set item with id {id} updated")

                case "delete":
                    self.chronicle_reference.delete_in_list(payload)
                    self.helper.log_debug(f"reference_set item with id {id} deleted")

            if self.metrics is not None:
                self.metrics.msg(msg.event)
                self.metrics.state(msg.id)

    def start(self):
        if self.chronicle_reference.init():
            self.helper.log_info("reference_set created")
        else:
            self.helper.log_warning("unable to create reference_set")

        self.register_producer()
        self.start_consumers()


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

    # load and check config
    config = load_config_file()
    # create opencti helper
    helper = OpenCTIConnectorHelper(config)
    helper.log_info("connector helper initialized")
    check_helper(helper)

    # read config
    ignore_types = get_config_variable(
        "CHRONICLE_IGNORE_TYPES", ["chronicle", "ignore_types"], config).split(",")
    region = get_config_variable("CHRONICLE_REGION", ["chronicle", "region"], config)
    list_name = get_config_variable(
        "CHRONICLE_LIST_NAME", ["chronicle", "list_name"], config
    )
    credential_file = get_config_variable("CHRONICLE_CREDENTIAL_FILE", ["chronicle", "credential_file"], config)

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
    reference_set = ChronicleReference(
        region,
        list_name,
        credential_file,
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
    ChronicleConnector(
        helper,
        reference_set,
        queue,
        ignore_types,
        consumer_count,
        metrics=metrics,
    ).start()
