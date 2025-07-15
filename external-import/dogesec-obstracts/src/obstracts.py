"""
OBSTRACTS Connector
"""

import json
import os
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin

import requests
import schedule
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class ObstractsConnector:
    def __init__(self):
        """Read in config variables"""

        config_file_path = "config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)
        self.base_url = self._get_param("base_url") + "/"
        self.api_key = self._get_param("api_key")
        feed_ids = self._get_param("feed_ids")
        self.feed_ids = feed_ids.split(",") if feed_ids else []
        self.interval_hours = self._get_param("interval_hours", is_number=True)
        self.days_to_backfill = self._get_param("days_to_backfill", is_number=True)

        self.session = requests.Session()
        self.session.headers = {
            "API-KEY": self.api_key,
        }

    def _get_param(
        self, param_name: str, is_number: bool = False, default_value: str = None
    ) -> int | str:
        return get_config_variable(
            f"OBSTRACTS_{param_name.upper()}",
            ["obstracts", param_name.lower()],
            self.helper.config,
            is_number,
            default_value,
        )

    def list_feeds(self):
        try:
            feeds = self.retrieve("v1/feeds/", list_key="feeds")
            return feeds
        except Exception:
            self.helper.log_error("failed to fetch feeds")
        return []

    def get_posts_after_last(self, feed):
        feed_id = feed["id"]
        self.helper.log_info("processing Feed(id={id}, title={title})".format_map(feed))
        feed_state = self._get_state()["feeds"].get(
            feed_id,
            dict(
                latest_post_update_time=(
                    datetime.now(UTC) - timedelta(days=self.days_to_backfill)
                ).isoformat()
            ),
        )
        feed_posts = self.retrieve(
            f"v1/feeds/{feed_id}/posts/",
            "posts",
            params=dict(
                updated_after=feed_state["latest_post_update_time"],
                sort="datetime_added_ascending",
                job_state="processed",
            ),
        )
        for post in feed_posts:
            self.process_post(feed_id, post)

    def process_post(self, feed_id, post: dict):
        post_id = post["id"]
        post_title = post["title"]
        post_name = f"Post(title={repr(post_title)}, id={post_id})"
        self.helper.log_info("Processing " + post_name)
        post_updated = post["datetime_updated"]
        try:
            objects = self.retrieve(
                f"v1/feeds/{feed_id}/posts/{post_id}/objects/", list_key="objects"
            )
            bundle = dict(
                type="bundle",
                id=f"bundle--{post_id}",
                objects=objects,
            )
            self.helper.send_stix2_bundle(json.dumps(bundle), work_id=self.work_id)
            self.set_feed_state(feed_id, last_updated=post_updated)
        except:
            self.helper.log_error("could not process post " + post_name)

    def retrieve(self, path, list_key, params: dict = None):
        params = params or {}
        params.update(page=1, page_size=200)
        objects: list[dict] = []
        total_results_count = -1
        while total_results_count < len(objects):
            resp = self.session.get(urljoin(self.base_url, path), params=params)
            params.update(page=params["page"] + 1)
            data = resp.json()
            total_results_count = data["total_results_count"]
            objects.extend(data[list_key])
        self.helper.log_info(
            f"found {len(objects)} {list_key} at {path} with filters: {params}"
        )
        return objects

    def run_once(self):
        in_error = False
        try:
            self.work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, self.helper.connect_name
            )
            self._run_once()
        except:
            self.helper.log_error("run failed")
            in_error = True
        finally:
            self.helper.api.work.to_processed(
                work_id=self.work_id,
                message="[CONNECTOR] Connector exited gracefully",
                in_error=in_error,
            )
            self.work_id = None

    def _run_once(self):
        self.helper.log_info("running as scheduled")
        for feed in self.list_feeds():
            feed_id = feed["id"]
            if feed_id not in (self.feed_ids or [feed_id]):
                self.helper.log_info(
                    f"skipping feed with id (`{feed_id}`) not in config.obstracts.feed_ids"
                )
                continue
            self.get_posts_after_last(feed)
        self.set_feed_state(None, None)

    def set_feed_state(self, feed_id, last_updated):
        state = self._get_state()
        if feed_id:
            feed_state: dict = state["feeds"].setdefault(feed_id, {})
            feed_state.update(latest_post_update_time=last_updated)
        state["last_run"] = datetime.now(UTC).isoformat()
        self.helper.last_run_datetime()
        self.helper.set_state(state)

    def _get_state(self) -> dict:
        state = self.helper.get_state()
        if not state or "feeds" not in state:
            state = {"feeds": {}}
        return state

    def run(self):
        self.helper.log_info("Starting Obstracts")
        schedule.every(self.interval_hours).hours.do(self.run_once)
        self.run_once()
        while True:
            schedule.run_pending()
            time.sleep(1)


if __name__ == "__main__":
    ObstractsConnector().run()
