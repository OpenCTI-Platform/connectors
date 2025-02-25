################################################
# PAN CORTEX XSOAR Intel Connector for OpenCTI #
################################################

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

STIX_TYPES_TO_XSOAR = {
    "user-account:account_login": "Account",
    "domain-name:value": "Domain",
    "email-addr:value": "Email",
    "file:hashes:MD5": "File",
    "file:hashes:SHA-1": "File",
    "file:hashes:SHA-256": "File",
    "file:hashes:SHA-512": "File",
    "x-opencti-hostname:value": "Host",
    "hostname:value": "Host",
    "x-opencti-mutex:name": "Mutex",
    "mutex:name": "Mutex",
    "ipv4-addr:value": "IP",
    "ipv6-addr:value": "IPv6",
    "windows-registry-key:key": "Registry Key",
    "url:value": "URL",
}


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


class XSoarAPI:
    def __init__(
        self,
        xsoar_url: str,
        xsoar_key_id: str,
        xsoar_key: str,
        xsoar_ssl_verify: bool,
    ) -> None:
        self.xsoar_url = xsoar_url
        self.xsoar_key_id = xsoar_key_id
        self.xsoar_key = xsoar_key
        self.xsoar_ssl_verify = xsoar_ssl_verify

    @property
    def indicators_url(self) -> str:
        return f"{self.xsoar_url}/xsoar/public/v1/indicator"

    @property
    def headers(self) -> dict:
        return {
            "x-xdr-auth-id": self.xsoar_key_id,
            "Authorization": self.xsoar_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def create(self, id: str, payload: dict):
        if id is not None and payload is not None:
            payload["entityId"] = id
            payload["indicator"]["id"] = id
            r = requests.post(
                f"{self.indicators_url}/create",
                json=payload,
                headers=self.headers,
                verify=self.xsoar_ssl_verify,
            )
            if r.status_code != 409:
                r.raise_for_status()

    def update(self, id: str, payload: dict):
        if id is not None and payload is not None:
            payload["entityId"] = id
            payload["indicator"]["id"] = id
            r = requests.post(
                f"{self.indicators_url}/edit",
                json=payload,
                headers=self.headers,
                verify=self.xsoar_ssl_verify,
            )
            if r.status_code == 404:
                self.create(id, payload)
            else:
                r.raise_for_status()

    def delete(self, id: str):
        if id is not None:
            payload = {"doNotWhitelist": True, "ids": [id], "filter": {}}
            r = requests.post(
                f"{self.indicators_url}s/batchDelete",
                headers=self.headers,
                verify=self.xsoar_ssl_verify,
                json=payload,
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


class XSoarConnector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        xsoar_api: XSoarAPI,
        queue: Queue,
        consumer_count: int,
        metrics: Metrics | None = None,
    ) -> None:
        self.xsoar_api = xsoar_api
        self.queue = queue
        self.helper = helper
        self.metrics = metrics
        self.consumer_count = consumer_count

        self._org_name_cache = {}

    def is_filtered(self, data: dict):
        return "type" in data and data["type"] not in ["indicator"]

    def get_org_name(self, entity_id: str) -> str | None:
        if entity_id in self._org_name_cache:
            return self._org_name_cache.get(entity_id)

        entity = self.helper.api.stix_domain_object.read(id=entity_id)
        org_name = entity.get("name")
        self._org_name_cache[entity_id] = org_name

        return org_name

    def convert_payload(self, payload: dict):
        # Add stream name
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

        indicator = None
        # create the indicator
        if len(payload["mapped_values"]) > 0:
            mapped_value = payload["mapped_values"][0]
            type = list(mapped_value.keys())[0]
            if type in STIX_TYPES_TO_XSOAR:
                payload["tags"] = payload.get("labels", None)
                payload["reportedby"] = payload.get("created_by", None)
                indicator = {
                    "indicator": {
                        "indicator_type": STIX_TYPES_TO_XSOAR[type],
                        "tags": payload.get("labels", None),
                        "manuallyEditedFields": [
                            "indicator_type",
                            "id",
                            "score",
                            "expiration",
                            "source",
                            "tags",
                        ],
                        "value": mapped_value[type],
                        "timestamp": payload.get("created", None),
                        "comment": payload.get("description", None),
                        "firstSeen": payload.get("valid_from", None),
                        "expiration": payload.get("valid_until", None),
                        "manualExpirationTime": payload.get("valid_until", None),
                        "score": payload.get("x_opencti_score", None),
                        "manualScore": True,
                        "isDetectable": True,
                        "isPreventable": True,
                        "source": "OpenCTI " + self.helper.get_name(),
                        "sourceInstances": ["OpenCTI " + self.helper.get_name()],
                        "CustomFields": payload,
                    },
                    "manually": True,
                    "seenNow": True,
                }
            else:
                self.helper.log_info(
                    "item with id " + payload["id"] + " is not supported"
                )
        return indicator

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

            payload = self.convert_payload(payload)
            if payload is None:
                self.helper.log_info(f"error converting item with id {id}, ignoring")
                continue

            try:
                match msg.event:
                    case "create":
                        self.xsoar_api.create(id, payload)
                        self.helper.log_info(
                            f"xsoar item with id {id} created (payload: {json.dumps(payload)})"
                        )
                    case "update":
                        self.xsoar_api.update(id, payload)
                        self.helper.log_info(
                            f"xsoar item with id {id} updated (payload: {json.dumps(payload)})"
                        )
                    case "delete":
                        self.helper.log_info(f"xsoar item with id {id} deleted")
                        self.xsoar_api.delete(id)
            except Exception as e:
                self.helper.log_error(e)

            if self.metrics is not None:
                self.metrics.msg(msg.event)
                self.metrics.state(msg.id)

    def start(self):
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
        helper.log_error("Missing Live Stream ID")
        exit(1)


if __name__ == "__main__":
    try:
        # Fix loggers
        fix_loggers()

        # Load and check config
        config = load_config_file()

        # Create OpenCTI helper
        helper = OpenCTIConnectorHelper(config)
        helper.log_info("connector helper initialized")
        check_helper(helper)

        # Read config
        xsoar_url = get_config_variable("XSOAR_URL", ["xsoar", "url"], config)
        xsoar_key_id = get_config_variable("XSOAR_KEY_ID", ["xsoar", "key_id"], config)
        xsoar_key = get_config_variable("XSOAR_KEY", ["xsoar", "key"], config)
        xsoar_ssl_verify = get_config_variable(
            "XSOAR_SSL_VERIFY", ["xsoar", "ssl_verify"], config, False, True
        )

        # Additional connector conf
        consumer_count: int = get_config_variable(
            "CONNECTOR_CONSUMER_COUNT",
            ["connector", "consumer_count"],
            config,
            isNumber=True,
            default=10,
        )

        # Metrics conf
        enable_prom_metrics: bool = get_config_variable(
            "METRICS_ENABLE", ["metrics", "enable"], config, default=False
        )
        metrics_port: int = get_config_variable(
            "METRICS_PORT", ["metrics", "port"], config, isNumber=True, default=9113
        )
        metrics_addr: str = get_config_variable(
            "METRICS_ADDR", ["metrics", "addr"], config, default="0.0.0.0"
        )

        # create XSoar API instance
        xsoar_api = XSoarAPI(
            xsoar_url,
            xsoar_key_id,
            xsoar_key,
            xsoar_ssl_verify,
        )

        # Create queue
        queue = Queue(maxsize=2 * consumer_count)

        # Create prom metrics
        if enable_prom_metrics:
            metrics = Metrics(helper.connect_name, metrics_addr, metrics_port)
            helper.log_info(f"starting metrics server on {metrics_addr}:{metrics_port}")
            metrics.start_server()
        else:
            metrics = None

        # Create connector and start
        XSoarConnector(
            helper,
            xsoar_api,
            queue,
            consumer_count,
            metrics=metrics,
        ).start()
    except Exception:
        traceback.print_exc()
        exit(1)
