import csv
import re
import threading
import time
from datetime import datetime
from urllib3.exceptions import HTTPError
from .constants import RISK_LIST_TYPE_MAPPER


class CustomBundles(threading.Thread):
    def __init__(
        self,
        helper,
        update_existing_data,
        interval,
        rfapi,
        paths,
    ):
        threading.Thread.__init__(self)
        self.helper = helper
        self.update_existing_data = update_existing_data
        self.interval = interval
        self.rfapi = rfapi
        self.paths = paths

    def run(self):
        while True:
            timestamp = int(time.time())
            now = datetime.utcfromtimestamp(timestamp)
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "Recorded Future custom bundle import "
                + now.strftime("%Y-%m-%d %H:%M:%S"),
            )
            for path in self.paths.split(',;'):
                self.helper.log_info(f"[CUSTOM BUNDLES] Pulling bundle at {path}")
                try:
                    bundle = self.rfapi.get_fusion_file(path)
                    self.helper.send_stix2_bundle(
                        bundle,
                        update=self.update_existing_data,
                        work_id=work_id,
                    )
                except (HTTPError,ValueError) as err:
                    self.helper.log_error(err)
                    continue
            self.helper.set_state({"last_bundle_run": timestamp})
            time.sleep(int(self.interval) * 3600)
