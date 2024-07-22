################################
# Splunk Connector for OpenCTI #
################################

import json
import logging
import os
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue

import requests
import yaml
from prometheus_client import Counter, Gauge, start_http_server
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix_shifter.stix_translation import stix_translation


def sanitize_key(key):
    """Sanitize key name for Splunk usage

    Splunk KV store keys cannot contain ".". Also, keys containing
    unusual characters like "'" make their usage less convenient
    when writing SPL queries.

    Args:
        key (str): value to sanitize

    Returns:
        str: sanitized result
    """
    return key.replace(".", ":").replace("'", "")


class KVStore:
    def __init__(
        self,
        splunk_url: str,
        splunk_token: str,
        splunk_app: str,
        splunk_owner: str,
        splunk_kv_store_name: str,
        splunk_ssl_verify: bool,
    ) -> None:
        self.splunk_url = splunk_url
        self.splunk_token = splunk_token
        self.splunk_app = splunk_app
        self.splunk_owner = splunk_owner
        self.splunk_kv_store_name = splunk_kv_store_name
        self.splunk_ssl_verify = splunk_ssl_verify

    @property
    def collection_url(self) -> str:
        return f"{self.splunk_url}/servicesNS/{self.splunk_owner}/{self.splunk_app}/storage/collections"

    @property
    def headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.splunk_token}",
            "Content-Type": "application/json",
        }

    def init(self) -> bool:
        r = requests.post(
            f"{self.collection_url}/config",
            data={"name": self.splunk_kv_store_name},
            headers=self.headers,
            verify=self.splunk_ssl_verify,
        )

        return r.status_code < 300

    def create(self, id: str, payload: dict):
        if id is not None and payload is not None:
            payload["_key"] = id
            r = requests.post(
                f"{self.collection_url}/data/{self.splunk_kv_store_name}",
                json=payload,
                headers=self.headers,
                verify=self.splunk_ssl_verify,
            )
            if r.status_code != 409:
                r.raise_for_status()

    def update(self, id: str, payload: dict):
        if id is not None and payload is not None:
            payload["_key"] = id
            r = requests.put(
                f"{self.collection_url}/data/{self.splunk_kv_store_name}/{id}",
                json=payload,
                headers=self.headers,
                verify=self.splunk_ssl_verify,
            )
            if r.status_code == 404:
                self.create(id, payload)
            else:
                r.raise_for_status()

    def delete(self, id: str):
        if id is not None:
            r = requests.delete(
                f"{self.collection_url}/data/{self.splunk_kv_store_name}/{id}",
                headers=self.headers,
                verify=self.splunk_ssl_verify,
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


class SplunkConnector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        kvstore: KVStore,
        queue: Queue,
        ignore_types: list[str],
        consumer_count: int,
        metrics: Metrics | None = None,
    ) -> None:
        self.kvstore = kvstore
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

    def enrich_payload(self, payload: dict):
        # add stream name
        payload["stream_name"] = self.helper.get_stream_collection()["name"]

        if "type" in payload:
            if payload["type"] == "indicator" and payload["pattern_type"].startswith(
                "stix"
            ):
                # add splunk query
                try:
                    translation = stix_translation.StixTranslation()
                    response = translation.translate(
                        "splunk", "query", "{}", payload["pattern"]
                    )
                    payload["splunk_queries"] = response
                except:
                    pass

                # add mapped values
                try:
                    parsed = translation.translate(
                        "splunk", "parse", "{}", payload["pattern"]
                    )
                    if "parsed_stix" in parsed and len(parsed["parsed_stix"]) > 0:
                        payload["mapped_values"] = []
                        for value in parsed["parsed_stix"]:
                            formatted_value = {}
                            formatted_value[sanitize_key(value["attribute"])] = value[
                                "value"
                            ]
                            payload["mapped_values"].append(formatted_value)
                    else:
                        raise ValueError("Not parsed")
                except:
                    try:
                        splitted = payload["pattern"].split(" = ")
                        key = sanitize_key(splitted[0].replace("[", ""))
                        value = splitted[1].replace("'", "").replace("]", "")
                        formatted_value = {}
                        formatted_value[key] = value
                        payload["mapped_values"] = [formatted_value]
                    except:
                        payload["mapped_values"] = []

                # add values
                payload["values"] = sum(
                    [list(value.values()) for value in payload["mapped_values"]], []
                )
            created_by = payload.get("created_by_ref", None)
            if created_by is not None:
                org_name = self.get_org_name(created_by)
                if org_name is not None:
                    payload["created_by"] = org_name

        if "extensions" in payload:
            for extension_definition in payload["extensions"].values():
                for attribute_name in [
                    "score",
                    "created_at",
                    "updated_at",
                    "labels",
                    "is_inferred",
                    "main_observable_type",
                ]:
                    attribute_value = extension_definition.get(attribute_name)
                    if attribute_value:
                        payload[attribute_name] = attribute_value
            # remove extensions
            del payload["extensions"]

        return payload

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
        except Exception:
            error_msg = traceback.format_exc()
            self.helper.log_error("An error occurred while consuming messages")
            self.helper.log_error(error_msg)
            os._exit(1)  # exit the current process, killing all threads

    def _consume(self):
        while True:
            msg = self.queue.get()
            payload = json.loads(msg.data)["data"]
            id = OpenCTIConnectorHelper.get_attribute_in_extension("id", payload)

            self.helper.log_info(f"processing message with id {id}")

            if self.is_filtered(payload):
                self.helper.log_info(f"item with id {id} is filtered")
                continue

            payload = self.enrich_payload(payload)

            match msg.event:
                case "create":
                    self.kvstore.create(id, payload)
                    self.helper.log_info(
                        f"kvstore item with id {id} created (payload: {json.dumps(payload)})"
                    )
                case "update":
                    self.kvstore.update(id, payload)
                    self.helper.log_info(
                        f"kvstore item with id {id} updated (payload: {json.dumps(payload)})"
                    )
                case "delete":
                    self.helper.log_info(f"kvstore item with id {id} deleted")
                    self.kvstore.delete(id)
            if self.metrics is not None:
                self.metrics.msg(msg.event)
                self.metrics.state(msg.id)

    def start(self):
        if self.kvstore.init():
            self.helper.log_info("kvstore created")
        else:
            self.helper.log_warning("unable to create kvstore")

        self.register_producer()
        self.start_consumers()


def fix_loggers() -> None:
    logging.getLogger(
        "stix_shifter_modules.splunk.stix_translation.query_translator"
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
    try:
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
            "SPLUNK_IGNORE_TYPES", ["splunk", "ignore_types"], config
        ).split(",")
        splunk_url = get_config_variable("SPLUNK_URL", ["splunk", "url"], config)
        splunk_token = get_config_variable("SPLUNK_TOKEN", ["splunk", "token"], config)
        splunk_owner = get_config_variable("SPLUNK_OWNER", ["splunk", "owner"], config)
        splunk_ssl_verify = get_config_variable(
            "SPLUNK_SSL_VERIFY", ["splunk", "ssl_verify"], config, False, True
        )
        splunk_app = get_config_variable("SPLUNK_APP", ["splunk", "app"], config)
        splunk_kv_store_name = get_config_variable(
            "SPLUNK_KV_STORE_NAME", ["splunk", "kv_store_name"], config
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

        # create kvstore instance
        kvstore = KVStore(
            splunk_url,
            splunk_token,
            splunk_app,
            splunk_owner,
            splunk_kv_store_name,
            splunk_ssl_verify,
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
        SplunkConnector(
            helper,
            kvstore,
            queue,
            ignore_types,
            consumer_count,
            metrics=metrics,
        ).start()
    except Exception:
        traceback.print_exc()
        exit(1)
