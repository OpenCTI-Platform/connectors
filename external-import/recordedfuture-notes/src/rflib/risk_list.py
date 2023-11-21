import csv
import threading
import time
from datetime import datetime

from rflib import IPAddress


class RiskList(threading.Thread):
    def __init__(self, helper, update_existing_data, interval):
        threading.Thread.__init__(self)
        self.helper = helper
        self.update_existing_data = update_existing_data
        self.interval = interval

    def run(self):
        while True:
            # TODO call API
            timestamp = int(time.time())
            now = datetime.utcfromtimestamp(timestamp)
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "Recorded Future Risk List run @ " + now.strftime("%Y-%m-%d %H:%M:%S"),
            )
            self.helper.log_info("[RISK LISTS] Pulling risk lists")
            with open("rflib/enriched_rl.csv", "r") as csv_file:
                reader = csv.DictReader(csv_file)
                # TODO Handle other indicator cases
                for row in reader:
                    # Convert into stix object
                    ip_address = IPAddress(row["Name"], "IpAddress")
                    ip_address.map_data(row)
                    ip_address.build_bundle(ip_address)
                    # Create bundle
                    bundle = ip_address.to_stix_bundle()
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
                    # TODO test work list update after each bundle sent
            self.helper.set_state({"last_risk_list_run": timestamp})
            time.sleep(self.interval * 3600)
