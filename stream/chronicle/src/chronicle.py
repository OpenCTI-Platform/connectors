###################################
# Chronicle Connector for OpenCTI #
###################################

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue

import yaml
from google.oauth2 import service_account
from googleapiclient import _auth
from prometheus_client import Counter, Gauge, start_http_server
from pycti import OpenCTIConnectorHelper, get_config_variable

SCOPES = ["https://www.googleapis.com/auth/chronicle-backstory"]
BASE_URL = "https://backstory.googleapis.com"


class ChronicleReference:
    def __init__(self, list_name: str, credentials: dict, url: str) -> None:
        self.url = url
        self.credentials = credentials
        self.list_name = list_name

    @property
    def http_client(self):
        return _auth.authorized_http(credentials)

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
        response = self.http_client.request("POST", url, json=body)[0]
        if response.status >= 400:
            helper.log_debug(f"Reponse status code : {json.dumps(response.status)}")
        return response.data["createTime"]

    def create_in_list(self, payload):
        helper.log_debug("Try Verify if payload is not already inside")
        lines = self.get_list()
        helper.log_debug("Verify if payload is not already inside")
        if payload not in lines:
            lines.append(str(payload))
            helper.log_debug("Payload is nott innsode")
            self.update_list(lines)

    def get_list(self):
        url = f"{self.url}/v2/lists/{self.list_name}"
        http_client = _auth.authorized_http(self.credentials)
        header, body = http_client.request(method="GET", uri=url)
        if header.status >= 400:
            helper.log_error(f"GET Reponse status code : {header.status}")
        else:
            helper.log_info(f"GET Reponse status code : {header.status}")

        return json.loads(body)["lines"]

    def update_in_list(self, payload):
        lines = self.get_list()
        helper.log_info(f"UPDATE payload test if payload is in list {payload}")
        if payload not in lines:
            helper.log_info("UPDATE, payload not already in list")
            lines.append(str(payload))
            self.update_list(lines)
        else:
            helper.log_info("UPDATE, payload already")

    def delete_in_list(self, payload):
        lines = self.get_list()
        if payload in lines:
            lines.remove(str(payload))
            self.update_list(lines)
        else:
            helper.log_info("DELETE payload not in list")

    def update_list(self, payload):
        url = f"{self.url}/v2/lists?update_mask=list.lines"
        body = {
            "name": self.list_name,
            "lines": payload,
            "content_type": "CONTENT_TYPE_DEFAULT_STRING",
        }
        header, body = self.http_client.request(
            uri=url, method="PATCH", body=json.dumps(body).encode("utf-8")
        )
        if header.status >= 400:
            helper.log_error(f"PATCH Reponse status code : {header.status}")
        else:
            helper.log_info(f"PATCH Reponse status code : {header.status}")


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
                self.helper.log_debug(f"item with id {id} is filtered {payload}")
                continue

            self.helper.log_debug(f"item with id {id} is not filtered {payload}")

            match msg.event:
                case "create":
                    self.helper.log_debug(f"Event create {id}")
                    self.chronicle_reference.create_in_list(payload.get("name"))
                    self.helper.log_debug(f"reference_set item with id {id} created")

                case "update":
                    self.helper.log_debug(f"Event Update {id}")
                    self.chronicle_reference.update_in_list(payload.get("name"))
                    self.helper.log_debug(f"reference_set item with id {id} updated")

                case "delete":
                    self.helper.log_debug(f"Event Delete {id}")
                    self.chronicle_reference.delete_in_list(payload.get("name"))
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

    helper.log_info("connector checked")

    ignore_types = get_config_variable(
        "CHRONICLE_IGNORE_TYPES", ["chronicle", "ignore_types"], config
    ).split(",")

    helper.log_info(f"Ignored type {ignore_types}")

    chronicle_url = get_config_variable("CHRONICLE_URL", ["chronicle", "url"], config)
    list_name = get_config_variable(
        "CHRONICLE_LIST_NAME", ["chronicle", "list_name"], config
    )
    chronicle_project_id = get_config_variable(
        "CHRONICLE_PROJECT_ID", ["chronicle", "project_id"], config
    )
    chronicle_private_key = get_config_variable(
        "CHRONICLE_PRIVATE_KEY", ["chronicle", "private_key"], config
    )
    chronicle_private_key = chronicle_private_key.replace("\\n", "\n")

    chronicle_private_key_id = get_config_variable(
        "CHRONICLE_PRIVATE_KEY_ID", ["chronicle", "private_key_id"], config
    )
    chronicle_client_email = get_config_variable(
        "CHRONICLE_CLIENT_EMAIL", ["chronicle", "client_email"], config
    )
    chronicle_client_id = get_config_variable(
        "CHRONICLE_CLIENT_ID", ["chronicle", "client_id"], config
    )
    chronicle_auth_uri = get_config_variable(
        "CHRONICLE_AUTH_URI", ["chronicle", "auth_uri"], config
    )
    chronicle_token_uri = get_config_variable(
        "CHRONICLE_TOKEN_URI", ["chronicle", "token_uri"], config
    )
    chronicle_auth_provider_cert = get_config_variable(
        "CHRONICLE_AUTH_PROVIDER_CERT", ["chronicle", "auth_provider_cert"], config
    )
    chronicle_client_cert_url = get_config_variable(
        "CHRONICLE_CLIENT_CERT_URL", ["chronicle", "client_cert_url"], config
    )

    helper.log_info("after chronicle env vars")

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

    info = {
        "type": "service_account",
        "project_id": chronicle_project_id,
        "private_key": chronicle_private_key,
        "private_key_id": chronicle_private_key_id,
        "client_email": chronicle_client_email,
        "client_id": chronicle_client_id,
        "auth_uri": chronicle_auth_uri,
        "token_uri": chronicle_token_uri,
        "auth_provider_x509_cert_url": chronicle_auth_provider_cert,
        "client_x509_cert_url": chronicle_client_cert_url,
    }

    credentials = service_account.Credentials.from_service_account_info(
        info=info, scopes=SCOPES
    )

    reference_set = ChronicleReference(
        url=chronicle_url, list_name=list_name, credentials=credentials
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
    helper.log_info("Start Chronicle")
    ChronicleConnector(
        helper,
        reference_set,
        queue,
        ignore_types,
        consumer_count,
        metrics=metrics,
    ).start()
