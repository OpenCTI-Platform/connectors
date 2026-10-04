################################
# Splunk Connector for OpenCTI #
################################

import copy
import json
import logging
import os
import traceback
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from queue import Queue

import requests
from connectors_sdk import DeploymentAssurance
from prometheus_client import Counter, Gauge, start_http_server
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings
from splunk_deployment import build_deployment_assurance, describe_error
from stix_shifter.stix_translation import stix_translation

KV_STORE_PAGE_SIZE = 1000
"""Items read per KV store request during the deployment reconciliation."""

KV_STORE_INDICATOR_FIELDS = (
    "_key",
    "id",
    "type",
    "name",
    "pattern",
    "pattern_type",
    "values",
    "revoked",
    "valid_until",
)
"""KV store fields read back during the deployment reconciliation."""

READ_TIMEOUT_SECONDS = 120
"""Timeout of the read-back and hit searches (the stream path keeps its behaviour)."""


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
        splunk_auth_type: str,
        splunk_app: str,
        splunk_owner: str,
        splunk_kv_store_name: str,
        splunk_ssl_verify: bool,
    ) -> None:
        self.splunk_url = (
            splunk_url.rstrip("/") if isinstance(splunk_url, str) else splunk_url
        )
        self.splunk_token = splunk_token
        self.splunk_auth_type = splunk_auth_type
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
            "Authorization": f"{self.splunk_auth_type} {self.splunk_token}",
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

    def list_indicators(self, page_size: int = KV_STORE_PAGE_SIZE) -> Iterator[dict]:
        """Read the indicator items of the collection back, page by page.

        Pages are read by ascending `_key` (keyset pagination), so items written by
        the stream consumers during the listing never shift the pages.

        Args:
            page_size: Items per request (below the `max_rows_per_query` KV store limit).

        Yields:
            The indicator items (`type` = `indicator`), restricted to the read-back fields.

        Raises:
            requests.HTTPError: When a page cannot be read.
            ValueError: When Splunk returns an unexpected payload.
        """
        last_key = None
        while True:
            query: dict = {"type": "indicator"}
            if last_key is not None:
                query = {"$and": [query, {"_key": {"$gt": last_key}}]}
            r = requests.get(
                f"{self.collection_url}/data/{self.splunk_kv_store_name}",
                params={
                    "query": json.dumps(query),
                    "fields": ",".join(KV_STORE_INDICATOR_FIELDS),
                    "sort": "_key",
                    "limit": page_size,
                },
                headers=self.headers,
                verify=self.splunk_ssl_verify,
                timeout=READ_TIMEOUT_SECONDS,
            )
            r.raise_for_status()
            items = r.json()
            if not isinstance(items, list):
                raise ValueError("Unexpected KV store response (a list is expected)")
            # A skipped item would make its deployment look absent.
            if not all(
                isinstance(item, dict)
                and isinstance(item.get("_key"), str)
                and item["_key"]
                for item in items
            ):
                raise ValueError(
                    "Unexpected KV store response (every item must carry a _key)"
                )
            yield from items
            if len(items) < page_size:
                return
            last_key = items[-1]["_key"]

    def run_saved_search(
        self, name: str, earliest: datetime, max_results: int
    ) -> list[dict]:
        """Run a saved search as a oneshot search job and return its results.

        The `savedsearch` command uses the time range of the request instead of
        the time range saved with the search. Results are sorted oldest first (then
        by OpenCTI id and value), so a bounded read is complete up to its newest
        result, and bounded twice: by `head` in the search and by the `count` of the
        oneshot output (100 by default).

        Args:
            name: The saved search name, visible in the owner/app namespace.
            earliest: Start of the time range (the end is now).
            max_results: Maximum number of results returned.

        Returns:
            The result rows.

        Raises:
            requests.HTTPError: When the search cannot be run.
            ValueError: When Splunk returns an unexpected payload.
        """
        escaped_name = name.replace("\\", "\\\\").replace('"', '\\"')
        r = requests.post(
            f"{self.splunk_url}/servicesNS/{self.splunk_owner}/{self.splunk_app}/search/jobs",
            data={
                "search": (
                    f'| savedsearch "{escaped_name}" | sort 0 _time opencti_id value '
                    f"| head {max_results}"
                ),
                "exec_mode": "oneshot",
                "output_mode": "json",
                "earliest_time": f"{earliest.timestamp():.3f}",
                "latest_time": "now",
                "count": max_results,
            },
            headers={"Authorization": f"{self.splunk_auth_type} {self.splunk_token}"},
            verify=self.splunk_ssl_verify,
            timeout=READ_TIMEOUT_SECONDS,
        )
        r.raise_for_status()
        content = r.json()
        results = content.get("results") if isinstance(content, dict) else None
        if not isinstance(results, list):
            raise ValueError("Unexpected search job response (results are missing)")
        return results


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
        assurance: DeploymentAssurance | None = None,
    ) -> None:
        self.kvstore = kvstore
        self.queue = queue
        self.helper = helper
        self.ignore_types = ignore_types
        self.metrics = metrics
        self.consumer_count = consumer_count
        self.assurance = assurance

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
                    "description",
                    "detection",
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
            # os._exit skips the exit handlers: send the queued deployment reports first
            self.flush_deployment_reports()
            os._exit(1)  # exit the current process, killing all threads

    def _consume(self):
        while True:
            self.process_message(self.queue.get())

    def process_message(self, msg):
        payload = json.loads(msg.data)["data"]
        # Without the OpenCTI extension, pycti returns the STIX id of the object.
        id = OpenCTIConnectorHelper.get_attribute_in_extension("id", payload)

        self.helper.log_info(f"processing message with id {id}")

        if self.is_filtered(payload):
            self.helper.log_info(f"item with id {id} is filtered")
            return

        # enrich_payload drops the OpenCTI extension that identifies the indicator
        stix_object = dict(payload)
        payload = self.enrich_payload(payload)

        match msg.event:
            case "create":
                self._push(stix_object, id, lambda: self.kvstore.create(id, payload))
                self.helper.log_info(
                    f"kvstore item with id {id} created (payload: {json.dumps(payload)})"
                )
            case "update":
                self._push(stix_object, id, lambda: self.kvstore.update(id, payload))
                self.helper.log_info(
                    f"kvstore item with id {id} updated (payload: {json.dumps(payload)})"
                )
            case "delete":
                self.helper.log_info(f"kvstore item with id {id} deleted")
                self.kvstore.delete(id)
                if id is not None and self.assurance is not None:
                    self.assurance.report_removed(stix_object, external_id=id)
        if self.metrics is not None:
            self.metrics.msg(msg.event)
            self.metrics.state(msg.id)

    def _push(self, stix_object: dict, key: str | None, write) -> None:
        """Write an item to the KV store and report the deployment outcome.

        Args:
            stix_object: The streamed STIX object (OpenCTI extension included).
            key: The KV store key (OpenCTI id); nothing is written without it.
            write: The KV store call.

        Raises:
            Exception: The KV store error, after the failure was reported.
        """
        try:
            write()
        except Exception as err:
            if key is not None and self.assurance is not None:
                self.assurance.report_push_failed(stix_object, describe_error(err))
            raise
        if key is not None and self.assurance is not None:
            self.assurance.report_pushed(stix_object, external_id=key)

    def push_indicator(self, stix_indicator: dict) -> str:
        """Write an indicator to the KV store with the stream create path.

        Used by the deployment reconciliation to push again an indicator whose
        deployment is pending (analyst retry).

        Args:
            stix_indicator: The indicator in the stream event shape.

        Returns:
            The KV store key of the item.

        Raises:
            ValueError: When the indicator cannot be written by this connector.
            requests.HTTPError: When Splunk rejects the item.
        """
        key = OpenCTIConnectorHelper.get_attribute_in_extension("id", stix_indicator)
        if key is None:
            raise ValueError("The indicator has no OpenCTI id to use as KV store key")
        if self.is_filtered(stix_indicator):
            raise ValueError(
                "Indicators are excluded by the connector configuration (SPLUNK_IGNORE_TYPES)"
            )
        payload = self.enrich_payload(copy.deepcopy(stix_indicator))
        self.kvstore.create(key, payload)
        self.helper.log_info(f"kvstore item with id {key} pushed again")
        return key

    def flush_deployment_reports(self) -> None:
        """Send the queued deployment reports now (never raises)."""
        if self.assurance is None:
            return
        try:
            self.assurance.flush()
        except Exception as err:
            self.helper.log_warning(f"unable to flush the deployment reports: {err}")

    def start(self):
        if self.kvstore.init():
            self.helper.log_info("kvstore created")
        else:
            self.helper.log_warning("unable to create kvstore")

        if self.assurance is not None:
            self.assurance.start()
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
        config = ConnectorSettings()
        # create opencti helper
        helper = OpenCTIConnectorHelper(config=config.to_helper_config())
        helper.log_info("connector helper initialized")
        check_helper(helper)

        # read config
        ignore_types = config.splunk.ignore_types
        splunk_url = config.splunk.url
        splunk_token = config.splunk.token.get_secret_value()
        splunk_auth_type: str = config.splunk.auth_type
        splunk_owner = config.splunk.owner
        splunk_ssl_verify = config.splunk.ssl_verify
        splunk_app = config.splunk.app
        splunk_kv_store_name = config.splunk.kv_store_name

        # additional connector conf
        consumer_count: int = config.connector.consumer_count

        # metrics conf
        enable_prom_metrics: bool = config.metrics.enable
        metrics_port: int = config.metrics.port
        metrics_addr: str = config.metrics.addr

        # create kvstore instance
        kvstore = KVStore(
            splunk_url,
            splunk_token,
            splunk_auth_type,
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
        connector = SplunkConnector(
            helper,
            kvstore,
            queue,
            ignore_types,
            consumer_count,
            metrics=metrics,
        )

        # deployment write-back (deployed-on relationships, reconciliation, hits)
        connector.assurance = build_deployment_assurance(
            helper, config, kvstore, connector.push_indicator
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
