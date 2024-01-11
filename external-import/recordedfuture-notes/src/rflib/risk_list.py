import csv
import re
import threading
import time
from datetime import datetime

from .constants import RISK_LIST_TYPE_MAPPER


class RiskList(threading.Thread):
    def __init__(
        self, helper, update_existing_data, interval, rfapi, tlp, risk_list_threshold
    ):
        threading.Thread.__init__(self)
        self.helper = helper
        self.update_existing_data = update_existing_data
        self.interval = interval
        self.rfapi = rfapi
        self.tlp = tlp
        self.risk_list_threshold = risk_list_threshold

    def run(self):
        while True:
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
                reader = csv.DictReader(csv_file)
                for row in reader:
                    # Filtered by score with a threshold
                    if self.risk_list_threshold is not None:
                        row_risk_score = int(row["Risk"])
                        row_name = row["Name"]
                        if row_risk_score < self.risk_list_threshold:
                            self.helper.log_info(
                                f"[RISK LIST] Ignoring indicator '{row_name}' as its risk score ({row_risk_score}) is lower than the defined risk list threshold ({self.risk_list_threshold})"
                            )
                            continue
                    # Convert into stix object
                    indicator = risk_list_type["class"](row["Name"], key, tlp=self.tlp)

                    MALICOUS_SCORE = 3
                    rule_criticality_list = (
                        row["RuleCriticality"].strip("][").split(",")
                    )
                    risk_rules_list_str = row["RiskRules"].strip("][")
                    risk_rules_list = re.sub(r"\"", "", risk_rules_list_str).split(",")
                    description = ""

                    for index, criticality in enumerate(rule_criticality_list):
                        criticality_score = int(criticality)
                        if criticality_score >= MALICOUS_SCORE:
                            description += "- " + risk_rules_list[index] + "\n\n"

                    indicator.add_description(description)
                    indicator.map_data(row, self.tlp)
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
