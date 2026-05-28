#################################
# Webhook Connector for OpenCTI #
#################################

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue
from typing import Literal, Optional

import requests
import yaml
from prometheus_client import Counter, Gauge, start_http_server
from pycti import OpenCTIConnectorHelper, get_config_variable
from pydantic import BaseModel, HttpUrl


class WebhookReference(BaseModel):
    url: HttpUrl
    header: Optional[str]
    auth_type: Literal["NONE", "TOKEN"]
    header: Optional[str]
    token: Optional[str]
    dest_type: Literal["URL"] = "URL"

    def model_post_init(self, ctx):
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self.dest_type == "URL" and self.auth_type == "TOKEN":
            self._headers[self.header] = self.token

    def send_event(self, payload):
        requests.post(self.url, headers=self._headers, data=payload.encode("utf-8"))

    def init(self) -> bool:
        return True

    def get_type(self, payload):
        return re.search(
            "main_observable_type': '(.*?)'", str(payload["extensions"])
        ).group(1)


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


class WebhookConnector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        webhook_reference: WebhookReference,
        queue: Queue,
        consumer_count: int,
        metrics: Metrics | None = None,
    ) -> None:
        self.queue = queue
        self.helper = helper
        self.metrics = metrics
        self.webhook_reference = webhook_reference
        self.consumer_count = consumer_count

    def is_filtered(self, data: dict):
        return "type" in data and data["type"] in self.ignore_types

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
            self.webhook_reference.send_event(msg.data)
            self.helper.log_info("messange sent")

            if self.metrics is not None:
                self.metrics.msg(msg.event)
                self.metrics.state(msg.id)

    def start(self):
        helper.log_info("register_producer")
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
    webhook_type = get_config_variable("WEBHOOK_TYPE", ["webhook", "type"], config)
    webhook_url = get_config_variable("WEBHOOK_URL", ["webhook", "url"], config)
    webhook_token = get_config_variable("WEBHOOK_TOKEN", ["webhook", "token"], config)
    webhook_header = get_config_variable(
        "WEBHOOK_HEADER", ["webhook", "header"], config
    )
    webhook_auth_type = get_config_variable(
        "WEBHOOK_AUTH_TYPE", ["webhook", "auth_type"], config
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

    webhook_reference = WebhookReference(
        url=webhook_url,
        header=webhook_header,
        auth_type=webhook_auth_type,
        token=webhook_token,
        dest_type=webhook_type,
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
    WebhookConnector(
        helper,
        webhook_reference=webhook_reference,
        queue=queue,
        consumer_count=consumer_count,
        metrics=metrics,
    ).start()
