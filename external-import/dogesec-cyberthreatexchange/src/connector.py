"""
CYBERTHREATEXCHANGE Connector
"""

import json
import os
import sys
import traceback
from contextlib import contextmanager
from datetime import UTC, datetime
from urllib.parse import urljoin

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class CTXException(Exception):
    pass


class CyberThreatExchangeConnector:
    def __init__(self):
        """Read in config variables"""

        config_file_path = "config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)
        self.base_url = self._get_param("base_url").strip("/") + "/"
        self.api_key = self._get_param("api_key")
        feed_ids = self._get_param("feed_ids")
        self.feed_ids = feed_ids.split(",") if feed_ids else []
        self.interval_hours = self._get_param("interval_hours", is_number=True)

        if not self.feed_ids:
            self.helper.log_error("at least one feed id required")
            self.helper.stop()
            sys.exit(1)

        self.session = requests.Session()
        self.session.headers = {
            "API-KEY": self.api_key,
        }

    def _get_param(
        self, param_name: str, is_number: bool = False, default_value: str = None
    ) -> int | str:
        return get_config_variable(
            f"CYBERTHREATEXCHANGE_{param_name.upper()}",
            ["cyberthreatexchange", param_name.lower()],
            self.helper.config,
            is_number,
            default_value,
        )

    def list_subbed_feeds(self):
        try:
            return self.retrieve("v1/subscriptions/", list_key="results")
        except Exception as e:
            self.helper.log_error("failed to fetch feeds")
            raise CTXException("failed to fetch feeds") from e

    def get_and_process_objects(self, feed, work_id):
        feed_id = feed["id"]
        self.helper.log_info(
            "processing feed(id={id}, title='{name}')".format_map(feed)
        )
        feed_state = self._get_state()["feeds"].get(feed_id, dict(last_run_at=""))
        filters = dict()
        self.current_run_time = datetime.now(UTC).isoformat()
        if q := feed_state.get("last_run_at"):
            filters.update(added_after=q)

        for objects in self._retrieve(
            f"v1/feeds/{feed_id}/objects/", list_key="objects", params=filters
        ):
            self.helper.log_info(
                f"processing batch of {len(objects)} objects for feed {feed_id}"
            )
            bundle = dict(
                type="bundle",
                id=f"bundle--{feed_id}",
                objects=objects,
            )
            self.helper.log_info(
                f"Feed(id={feed_id}) sending bundle with {len(objects)} items"
            )
            self.helper.send_stix2_bundle(json.dumps(bundle), work_id=work_id)

    def _retrieve(self, path, list_key, params: dict = None):
        params = params or {}
        params.update(page=1, page_size=200)
        objects_count = 0
        more = True
        url = urljoin(self.base_url, path)
        while more:
            resp = self.session.get(url, params=params)
            data = resp.json()
            yield data[list_key]
            objects_count += len(data[list_key])
            if ("next" in data and not data["next"]) or (
                "total_results_count" in data
                and data["total_results_count"] <= objects_count
            ):
                more = False
            if "next" in data:
                url = data["next"]
            if "total_results_count" in data:
                params.update(page=params["page"] + 1)
        return []

    def retrieve(self, path, list_key, params: dict = None):
        all_objects = []
        for objects in self._retrieve(path, list_key, params):
            all_objects.extend(objects)
        return all_objects

    def _run_once(self):
        self.helper.log_info("running as scheduled")
        for feed_data in self.list_subbed_feeds():
            feed = feed_data["feed"]
            feed_id = feed["id"]
            feed_name = feed["name"]
            feed_repr = f"Feed(id={feed_id}, name={repr(feed_name)})"
            if self.feed_ids and feed_id not in self.feed_ids:
                self.helper.log_info(
                    f"skipping {feed_repr} not in config.cyberthreatexchange.feed_ids"
                )
                continue
            with self._run_in_work(f"Feed: {feed['name']} ({feed_id})") as work_id:
                if feed_data["subscription"]["status"] != "active":
                    self.helper.log_info(
                        f"skipping {feed_repr} subscription not active"
                    )
                    raise CTXException("skipping feed with inactive subscription")
                self.helper.log_info(f"processing {feed_repr}")
                self.get_and_process_objects(feed, work_id)
                self.set_feed_state(feed_id, last_updated=self.current_run_time)
        self.set_feed_state(None, None)

    @contextmanager
    def _run_in_work(self, work_name: str):
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, work_name)
        message = "[CyberThreatExchange] Work done"
        in_error = False
        try:
            yield work_id
        except Exception as e:
            self.helper.log_error(f"work failed: {e}")
            message = "[CyberThreatExchange] Work failed - " + traceback.format_exc()
            in_error = True
        finally:
            self.helper.api.work.to_processed(
                work_id=work_id, message=message, in_error=in_error
            )

    def run_once(self):
        with self._run_in_work("CyberThreatExchange Connector Run"):
            self._run_once()

    def set_feed_state(self, feed_id, last_updated):
        state = self._get_state()
        if feed_id:
            feed_state: dict = state["feeds"].setdefault(feed_id, {})
            feed_state.update(
                last_run_at=max(
                    last_updated, feed_state.get("last_run_at", last_updated)
                )
            )
        self.helper.set_state(state)

    def _get_state(self) -> dict:
        state = self.helper.get_state()
        if not state or "feeds" not in state:
            state = {"feeds": {}}
        return state

    def run(self):
        self.helper.log_info("Starting CyberThreatExchange")
        self.helper.schedule_process(
            message_callback=self.run_once,
            duration_period=self.interval_hours * 3600,
        )


if __name__ == "__main__":
    try:
        CyberThreatExchangeConnector().run()
    except BaseException:
        traceback.print_exc()
        exit(1)
