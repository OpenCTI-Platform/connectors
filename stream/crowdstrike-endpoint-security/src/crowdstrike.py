import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from queue import Queue

import yaml
from falconpy import IOC as CrowdstrikeIOC
from prometheus_client import Counter, Gauge, start_http_server
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix_shifter.stix_translation import stix_translation

translation = stix_translation.StixTranslation()


class CrowdstrikeError(Exception): ...


@dataclass
class IOC:
    type: str
    value: str
    valid_until: str | None


class Crowdstrike:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        url: str = "https://api.eu-1.crowdstrike.com",
    ) -> None:
        self.client_id = client_id
        self.cs = CrowdstrikeIOC(
            client_id=client_id, client_secret=client_secret, base_url=url
        )

    def _handle_error(self, res: dict):
        if status_code := res.get("status_code", 0) >= 400:  # type: ignore
            errors = ", ".join([f'{e.get("code", "")} - {e.get("message", "")}' for e in res.get("body", {}).get("errors", [])])  # type: ignore
            raise CrowdstrikeError(
                f"error while creating ioc, status {status_code}: {errors}"
            )

    def id(self, value: str) -> str | None:
        res = self.cs.indicator_search(
            filter=f'value:"{value}"+created_by:"{self.client_id}"'
        )
        self._handle_error(res)

        resources: list[str] = res.get("body", {}).get("resources", [])  # type: ignore

        if len(resources) == 0:
            return None

        return resources[0]

    def create(self, ioc: IOC):
        if self.id(ioc.value) is not None:
            return

        indicator = {
            "action": "detect",  # "Detect only" on Falcon web UI
            "mobile_action": "detect",  # "Detect only" on Falcon web UI
            "severity": "medium",
            "source": "OpenCTI IOC",
            "applied_globally": True,
            "type": ioc.type,
            "value": ioc.value,
            "platforms": (
                ["windows", "mac", "linux"]
                # if ioc.type in ["md5", "sha256"]
                # else ["windows", "mac", "linux", "ios", "android"]
            ),
        }

        if ioc.valid_until is not None:
            indicator["expiration"] = ioc.valid_until

        res = self.cs.indicator_create(
            body={
                "comment": "OpenCTI IOC",
                "indicators": [indicator],
            }
        )

        self._handle_error(res)

    def delete(self, ioc: IOC) -> bool:
        id = self.id(ioc.value)

        if id is None:
            return False

        res = self.cs.indicator_delete([id])
        self._handle_error(res)

        return True


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


def to_cs_type(octi_type: str) -> str | None:
    match octi_type:
        case "hostname:value":
            return "domain"
        case "domain-name:value":
            return "domain"
        case "ipv4-addr:value":
            return "ipv4"
        case "ipv6-addr:value":
            return "ipv6"
        case "file:hashes.'SHA-256'":
            return "sha256"
        case "file:hashes.'MD5'":
            return "md5"

    return None


def extract_iocs(payload: dict) -> list[IOC]:
    parsed = translation.translate("splunk", "parse", "{}", payload["pattern"])

    if "parsed_stix" not in parsed:
        return []

    res = []

    for stix in parsed["parsed_stix"]:
        type = to_cs_type(stix["attribute"])

        if type is None:
            continue

        value = stix["value"]
        valid_until = payload.get("valid_until", None)
        res.append(IOC(type=type, value=value, valid_until=valid_until))

    return res


class CrowdstrikeConnector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        crowdstrike: Crowdstrike,
        queue: Queue,
        ignore_types: list[str],
        consumer_count: int,
        metrics: Metrics | None = None,
    ) -> None:
        self.crowdstrike = crowdstrike
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

        if entity is None:
            return None

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
            self.helper.log_error(str(e))
            import traceback

            traceback.print_exc()
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

            # extract type and values

            iocs = extract_iocs(payload)

            for ioc in iocs:
                match msg.event:
                    case "create" | "update":
                        self.helper.log_debug(f"creating item with id {id}")

                        try:
                            self.crowdstrike.create(ioc)
                            self.helper.log_debug(
                                f"crowdstrike item with id {id} created"
                            )
                        except CrowdstrikeError as e:
                            self.helper.log_error(
                                f"error while creating item with id {id}, {e}"
                            )

                    case "delete":
                        self.helper.log_debug(f"deleting item with id {id}")
                        self.crowdstrike.delete(ioc)
                        self.helper.log_debug(f"crowdstrike item with id {id} deleted")

                if self.metrics is not None:
                    self.metrics.msg(msg.event)
                    self.metrics.state(msg.id)

    def start(self):
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


def fix_loggers() -> None:
    logging.getLogger(
        "stix_shifter_utils.stix_translation.src.patterns.parser"
    ).setLevel(logging.CRITICAL)
    logging.getLogger(
        "stix_shifter_modules.splunk.stix_translation.query_translator"
    ).setLevel(logging.CRITICAL)
    logging.getLogger("stix_shifter.stix_translation.stix_translation").setLevel(
        logging.CRITICAL
    )
    logging.getLogger(
        "stix_shifter_utils.stix_translation.stix_translation_error_mapper"
    ).setLevel(logging.CRITICAL)


if __name__ == "__main__":
    # load and check config
    config = load_config_file()

    # create opencti helper
    helper = OpenCTIConnectorHelper(config)
    helper.log_info("connector helper initialized")
    check_helper(helper)

    # read config
    ignore_types = get_config_variable(
        "CONNECTOR_IGNORE_TYPES", ["connector", "ignore_types"], config
    ).split(  # type: ignore
        ","
    )

    # additional connector conf

    consumer_count: int = get_config_variable(  # type: ignore
        "CONNECTOR_CONSUMER_COUNT",
        ["connector", "consumer_count"],
        config,
        isNumber=True,
        default=10,
    )

    # metrics conf

    enable_prom_metrics: bool = get_config_variable(
        "METRICS_ENABLE", ["metrics", "enable"], config, default=False
    )  # type: ignore

    metrics_port: int = get_config_variable(
        "METRICS_PORT", ["metrics", "port"], config, isNumber=True, default=9113
    )  # type: ignore

    metrics_addr: str = get_config_variable(
        "METRICS_ADDR", ["metrics", "addr"], config, default="0.0.0.0"  # nosec
    )  # type: ignore

    crowdstrike_client_id: str = get_config_variable(
        "CROWDSTRIKE_CLIENT_ID",
        ["crowdstrike", "client_id"],
        config,
        default="CHANGEME",
    )  # type: ignore

    crowdstrike_client_secret: str = get_config_variable(
        "CROWDSTRIKE_CLIENT_SECRET",
        ["crowdstrike", "client_secret"],
        config,
        default="CHANGEME",
    )  # type: ignore

    fix_loggers()

    # create kvstore instance
    crowdstrike = Crowdstrike(crowdstrike_client_id, crowdstrike_client_secret)

    # create queue
    queue = Queue(maxsize=2 * consumer_count)

    # create prom metrics
    if enable_prom_metrics:
        metrics = Metrics(helper.connect_name, metrics_addr, metrics_port)  # type: ignore
        helper.log_info(f"starting metrics server on {metrics_addr}:{metrics_port}")
        metrics.start_server()
    else:
        metrics = None

    # create connector and start
    CrowdstrikeConnector(
        helper,
        crowdstrike,
        queue,
        ignore_types,
        consumer_count,
        metrics=metrics,
    ).start()
