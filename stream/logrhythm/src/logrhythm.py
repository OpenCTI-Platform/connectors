################################
# Logrhythm Connector for OpenCTI #
################################

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue
import base64

import requests
import yaml
from prometheus_client import Counter, Gauge, start_http_server
from pycti import OpenCTIConnectorHelper, get_config_variable


class LogrhythmList:
    def __init__(
        self,
        logrhythm_url: str,
        logrhythm_token: str,
        logrhythm_entity: str,
        logrhythm_list_name: str,
        logrhythm_ssl_verify: bool,
    ) -> None:
        self.logrhythm_url = logrhythm_url
        self.logrhythm_token = logrhythm_token
        self.logrhythm_entity = logrhythm_entity
        self.logrhythm_list_name = logrhythm_list_name
        self.logrhythm_ssl_verify = logrhythm_ssl_verify

    @property
    def headers(self) -> dict:
        return {
            "Accept": "application/json",
            "Content-type": "application/json",
            "Authorization": f"Bearer {self.logrhythm_token}",
        }

    def init(self) -> bool:
        return True

    def get_owner_id(self):
        """get the owner id from the LR token (API user id)"""
        encoded = self.logrhythm_token.split(".")[1].encode("ascii")
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += b"=" * (4 - missing_padding)
        return json.loads(base64.b64decode(encoded)).get("uid")

    def get_type(self, payload):
        return re.search(
            "main_observable_type': '(.*?)'", str(payload["extensions"])
        ).group(1)

    def check_create_list(self, name: str):
        name = self.logrhythm_list_name + "_" + name
        post_body = """{
"listType":"GeneralValue",
"status":"Active",
"name":"%s",
"shortDescription":"Innovative Solutions Threat Intelligence Feeds",
"useContext":[
            "DomainOrigin",
            "DomainImpacted",
            "Subject",
            "Object",
            "Hash"
],
"autoImportOption":{
"enabled":true,
"usePatterns":true,
"replaceExisting":true
},
"readAccess":"PublicAll",
"writeAccess":"PublicAll",
"restrictedRead":true,
"entityName":"%s",
"entryCount":0,
"timeToLiveSeconds":1200,
"needToNotify":false,
"doesExpire":false,
"owner": %d
}""" % (
            name,
            self.logrhythm_entity,
            self.get_owner_id(),
        )
        get_headers = {"name": name}
        get_headers.update(self.headers)
        req = requests.get(
            self.logrhythm_url + "/lists/", headers=get_headers, verify=False
        )
        if req.status_code != 200 or len(req.text) <= 2:
            reqP = requests.post(
                self.logrhythm_url + "/lists/",
                headers=self.headers,
                json=json.loads(post_body),
                verify=False,
            )
            return reqP.json()[0].get("guid")
        else:
            return req.json()[0].get("guid")

    def create(self, id: str, payload: dict):
        GUID = self.check_create_list(self.get_type(payload))
        item_post = """
                {
            "items": 
        [
        {
            "displayValue": "%s",
            "isExpired": false,
            "isListItem": false,
            "isPattern": false,
            "listItemDataType": "String",
            "listItemType": "StringValue",
            "value": "%s"
                }
            ]
        }""" % (
            str(payload.get("name")),
            str(payload.get("name")),
        )
        url = self.logrhythm_url + f"/lists/{GUID}/items/"
        r = requests.post(
            url, headers=self.headers, json=json.loads(item_post), verify=False
        )
        print("Items Results", r.status_code)
        if r.status_code == 404:
            id = self.check_create_list(self.get_type(payload))
            self.create(id, payload)
        else:
            r.raise_for_status()

    def update(self, id: str, payload: dict):
        """API not supporting list update"""
        return True

    def delete(self, id: str, payload):
        GUID = self.check_create_list(self.get_type(payload))
        item_post = """
                {
            "items": 
        [
        {
            "displayValue": "%s",
            "isExpired": false,
            "isListItem": false,
            "isPattern": false,
            "listItemDataType": "String",
            "listItemType": "StringValue",
            "value": "%s",
                }
            ]

        }        
                """ % (
            str(payload.get("name")),
            str(payload.get("name")),
        )

        url = self.logrhythm_url + f"/lists/{GUID}/items/"
        r = requests.delete(url, headers=self.headers, json=item_post)

        if r.status_code == 404:
            id = self.check_create_list(self.get_type(payload))
            self.delete(id, payload)
        else:
            r.raise_for_status()

    def get_data_from_dic(self, data_object, key):
        """Recursively search for item in nested Dic"""
        try:
            if type(data_object) is list:
                data_object = data_object[0]
                print(data_object.items())
            for k, v in data_object.items():
                try:
                    return v[key]
                except Exception as ex:
                    print(ex)
                    pass
        except Exception as ex:
            print(ex)
            pass
        return "N\A"


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


class LogrhythmConnector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        logrhythm_list: LogrhythmList,
        queue: Queue,
        ignore_types: list[str],
        consumer_count: int,
        metrics: Metrics | None = None,
    ) -> None:
        self.logrhythm_list = logrhythm_list
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
                    self.logrhythm_list.create(id, payload)
                    self.helper.log_debug(f"lr_list item with id {id} created")

                case "update":
                    self.logrhythm_list.update(id, payload)
                    self.helper.log_debug(f"lr_list item with id {id} updated")

                case "delete":
                    self.helper.log_debug(f"lr_list item with id {id} deleted")
                    self.logrhythm_list.delete(id, payload)

            if self.metrics is not None:
                self.metrics.msg(msg.event)
                self.metrics.state(msg.id)

    def start(self):
        if self.logrhythm_list.init():
            self.helper.log_info("lr_list created")
        else:
            self.helper.log_warning("unable to create lr_list")

        self.register_producer()
        self.start_consumers()


def fix_loggers() -> None:
    logging.getLogger(
        "stix_shifter_modules.logrhythm.stix_translation.query_translator"
    ).setLevel(logging.CRITICAL)
    logging.getLogger("stix_shifter.stix_translation.stix_translation").setLevel(
        logging.CRITICAL
    )
    logging.getLogger(
        "stix_shifter_utils.stix_translation.stix_translation_error_mapper"
    ).setLevel(logging.CRITICAL)


def load_config_file() -> dict:
    config_file = Path(__file__).parent / "config.yml.sample"

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
        "LOGRHYTHM_IGNORE_TYPES", ["logrhythm", "ignore_types"], config
    ).split(",")
    logrhythm_url = get_config_variable("LOGRHYTHM_URL", ["logrhythm", "url"], config)
    logrhythm_token = get_config_variable(
        "LOGRHYTHM_TOKEN", ["logrhythm", "token"], config
    )
    logrhythm_entity = get_config_variable(
        "LOGRHYTHM_entity", ["logrhythm", "entity"], config
    )
    logrhythm_ssl_verify = get_config_variable(
        "LOGRHYTHM_SSL_VERIFY", ["logrhythm", "ssl_verify"], config, False, True
    )
    logrhythm_list_name = get_config_variable(
        "LOGRHYTHM_LIST_NAME", ["logrhythm", "list_name"], config
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

    # create lr_list instance
    lr_list = LogrhythmList(
        logrhythm_url,
        logrhythm_token,
        logrhythm_entity,
        logrhythm_list_name,
        logrhythm_ssl_verify,
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
    LogrhythmConnector(
        helper,
        lr_list,
        queue,
        ignore_types,
        consumer_count,
        metrics=metrics,
    ).start()
