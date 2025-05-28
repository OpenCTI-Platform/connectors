import csv
import re
import threading
from datetime import datetime, timezone

from .constants import RISK_LIST_TYPE_MAPPER, RISK_RULES_MAPPER


class RiskList(threading.Thread):
    def __init__(
        self,
        helper,
        rfapi,
        tlp,
        risk_list_threshold,
        risklist_related_entities,
        riskrules_as_label,
    ):
        threading.Thread.__init__(self)
        self.helper = helper
        self.rfapi = rfapi
        self.tlp = tlp
        self.risk_list_threshold = risk_list_threshold
        self.risklist_related_entities = risklist_related_entities
        self.riskrules_as_label = riskrules_as_label

    def run(self):
        try:
            # Get the current state
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state() or {}

            if current_state is not None and "last_risk_lists_run" in current_state:
                last_risk_lists_run = current_state["last_risk_lists_run"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last risk lists run",
                    {"last_run_datetime": last_risk_lists_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            # Main process to pull risk lists
            for key, risk_list_type in RISK_LIST_TYPE_MAPPER.items():
                self.helper.connector_logger.info(
                    f"[RISK LISTS] Pulling {key} risk lists"
                )

                csv_file = self.rfapi.get_risk_list_CSV(risk_list_type["path"])

                # Friendly name will be displayed on OpenCTI platform
                friendly_name = f"Recorded Future Risk List {key}"

                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id,
                    friendly_name,
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
                            self.helper.connector_logger.info(
                                f"[RISK LIST] Ignoring indicator '{row_name}' as its risk score ({row_risk_score}) is lower than the defined risk list threshold ({self.risk_list_threshold})"
                            )
                            continue
                    # Convert into stix object
                    first_seen = row["FirstSeen"] if row["FirstSeen"] else None
                    indicator = risk_list_type["class"](
                        row["Name"], key, tlp=self.tlp, first_seen=first_seen
                    )

                    rule_criticality_list = (
                        row["RuleCriticality"].strip("][").split(",")
                    )
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
                    labels = []

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
                                labels.append(risk_rules_list[index])

                    indicator.add_description(description)
                    if self.riskrules_as_label:
                        indicator.add_labels(labels)
                    indicator.map_data(row, self.tlp, self.risklist_related_entities)
                    indicator.build_bundle(indicator)
                    # Create bundle
                    bundle = indicator.to_stix_bundle()
                    self.helper.connector_logger.info(
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

            current_state = self.helper.get_state() or {}
            last_run_datetime = datetime.fromtimestamp(
                current_timestamp, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            current_state.update({"last_risk_lists_run": last_run_datetime})
            self.helper.set_state(state=current_state)

        except Exception as err:
            self.helper.connector_logger.error(str(err))
