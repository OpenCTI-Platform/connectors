import csv
import threading
import time
from datetime import datetime

from .constants import RISK_LIST_TYPE_MAPPER


class RiskList(threading.Thread):
    def __init__(self, helper, update_existing_data, interval, rfapi):
        threading.Thread.__init__(self)
        self.helper = helper
        self.update_existing_data = update_existing_data
        self.interval = interval
        self.rfapi = rfapi

    def run(self):
        while True:
            # TODO call API
            for key, risk_list_type in RISK_LIST_TYPE_MAPPER.items():
                self.helper.log_info(f"[RISK LISTS] Pulling {key} risk lists")

                csv_file = self.rfapi.get_risk_list_CSV(risk_list_type["path"])
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id,
                    "Recorded Future Risk List run @ "
                    + now.strftime("%Y-%m-%d %H:%M:%S"),
                )
                # with open("rflib/enriched_rl.csv", "r") as csv_file:
                reader = csv.DictReader(csv_file)
                # TODO Handle other indicator cases
                for row in reader:
                    # Convert into stix object
                    indicator = risk_list_type["class"](row["Name"], key)
                    indicator.map_data(row)
                    indicator.build_bundle(indicator)
                    # Create bundle
                    bundle = indicator.to_stix_bundle()
                    self.helper.log_info(
                        "[RISK LISTS] Sending Bundle to server with "
                        + str(len(bundle.objects))
                        + " objects"
                    )
                    self.helper.send_stix2_bundle(
                        bundle.serialize(),
                        update=self.update_existing_data,
                        work_id=work_id,
                    )
            self.helper.set_state({"last_risk_list_run": timestamp})
            time.sleep(self.interval * 3600)
