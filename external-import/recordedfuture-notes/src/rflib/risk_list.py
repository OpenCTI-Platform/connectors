import csv
import time
from rflib import IPAddress
import threading


class RiskList(threading.Thread):
    def __init__(self, helper, update_existing_data, interval):
        threading.Thread.__init__(self)
        self.helper = helper
        self.update_existing_data = update_existing_data
        self.interval = interval

    def run(self):
        # TODO call API
        while True:
            timestamp = int(time.time())
            self.helper.log_info("Pulling risk lists")
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
                        "Sending Bundle to server with "
                        + str(len(bundle.objects))
                        + " objects"
                    )

                    self.helper.send_stix2_bundle(
                        bundle.serialize(),
                        update=self.update_existing_data,
                    )
            self.helper.set_state({"last_risk_list_run": timestamp})
            time.sleep(10)
