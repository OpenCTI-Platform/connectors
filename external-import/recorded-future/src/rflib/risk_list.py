import csv
import re
import threading
import time
from datetime import datetime

from .constants import RISK_LIST_TYPE_MAPPER, RISK_RULES_MAPPER


class RiskList(threading.Thread):
    def __init__(
        self,
        helper,
        rfapi,
        tlp,
        risk_list_threshold,
        risklist_related_entities,
    ):
        threading.Thread.__init__(self)
        self.helper = helper
        self.rfapi = rfapi
        self.tlp = tlp
        self.risk_list_threshold = risk_list_threshold
        self.risklist_related_entities = risklist_related_entities

    def run(self):
        timestamp = int(time.time())
        for key, risk_list_type in RISK_LIST_TYPE_MAPPER.items():
            self.helper.log_info(f"[RISK LISTS] Pulling {key} risk lists")

            csv_file = self.rfapi.get_risk_list_CSV(risk_list_type["path"])
            now = datetime.utcfromtimestamp(timestamp)
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                f"Recorded Future Risk List {key} run @ "
                + now.strftime("%Y-%m-%d %H:%M:%S"),
            )
            reader = csv.DictReader(csv_file)
            for row in reader:
                # Filtered by score with a threshold
                if self.risk_list_threshold is not None:
                    try:
                        row_risk_score = int(row["Risk"])
                    except ValueError:
                        row_risk_score = 0

                    row_name = row["Name"]
                    if row_risk_score < self.risk_list_threshold:
                        self.helper.log_info(
                            f"[RISK LIST] Ignoring indicator '{row_name}' as its risk score ({row_risk_score}) is lower than the defined risk list threshold ({self.risk_list_threshold})"
                        )
                        continue
                # Convert into stix object
                indicator = risk_list_type["class"](row["Name"], key, tlp=self.tlp)

                rule_criticality_list = row["RuleCriticality"].strip("][").split(",")
                risk_rules_list_str = row["RiskRules"].strip("][")
                risk_rules_list = re.sub(r"\"", "", risk_rules_list_str).split(",")
                description = (
                    "Triggered risk rules:"
                    + "\n\n"
                    + "|Rule|Risk Rule Severity|Risk Score Severity|"
                    + "\n"
                    + "|--|--|--|"
                    + "\n"
                )

                for index, criticality in enumerate(rule_criticality_list):
                    # If criticality comes with empty string, replace value at 0
                    if not criticality:
                        criticality = 0

                    criticality_score = int(criticality)

                    for corresponding_rule in RISK_RULES_MAPPER:
                        if criticality_score == corresponding_rule["rule_score"]:
                            description += (
                                "|"
                                + risk_rules_list[index]
                                + "|"
                                + corresponding_rule["severity"]
                                + "|"
                                + corresponding_rule["risk_score"]
                                + "|"
                                + "\n"
                            )

                indicator.add_description(description)
                indicator.map_data(row, self.tlp, self.risklist_related_entities)
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
                    work_id=work_id,
                )
            message = f"{self.helper.connect_name} connector successfully run for Risk List {key}."
            self.helper.api.work.to_processed(work_id, message)
        self.helper.set_state({"last_risk_list_run": timestamp})
