import csv
import json
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
                last_risk_run_dt = datetime.strptime(
                    last_risk_lists_run,
                    "%Y-%m-%d %H:%M:%S",
                )

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last risk lists run",
                    {"last_run_datetime": last_risk_lists_run},
                )
            else:
                last_risk_run_dt = None

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run for risk lists..."
                )

            # Main process to pull risk lists
            for key, risk_list_type in RISK_LIST_TYPE_MAPPER.items():

                # Check access to the vulnerability module
                if key == "Vuln":
                    vuln_permission = self.rfapi.check_vul_entitlement()
                    if vuln_permission:
                        self.helper.connector_logger.info(
                            "[CONNECTOR] The subscription allows to download the vulnerability risk list"
                        )
                    else:
                        self.helper.connector_logger.info(
                            "[CONNECTOR] The subscription doesn't allow to download the vulnerability risk list"
                        )
                        continue

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
                    row_risk_score = None
                    if self.risk_list_threshold is not None:
                        try:
                            row_risk_score = int(row["Risk"])
                        except ValueError:
                            row_risk_score = 0

                        row_name = row["Name"]
                        if row_risk_score < self.risk_list_threshold:
                            self.helper.connector_logger.info(
                                f"[RISK LIST] Ignoring object '{row_name}' as its risk score ({row_risk_score}) is "
                                f"lower than the defined risk list threshold ({self.risk_list_threshold}) "
                            )
                            continue

                    first_seen = row["FirstSeen"] if row["FirstSeen"] else None
                    last_seen = row["LastSeen"] if row["LastSeen"] else None

                    # Filtered by date
                    if last_risk_run_dt is not None and last_seen is not None:
                        last_seen_dt = datetime.strptime(
                            last_seen,
                            "%Y-%m-%dT%H:%M:%S.%fZ",
                        )
                        if last_seen_dt < last_risk_run_dt:
                            continue

                    # Parse data
                    if key == "Vuln":
                        description = (
                            "Triggered risk rules:"
                            + "\n\n"
                            + "|Rule|Risk Rule Severity|Evidence|Mitigation|"
                            + "\n"
                            + "|--|--|--|--|"
                            + "\n"
                        )

                        labels = []
                        evidence_details = row.get("EvidenceDetails")
                        if evidence_details:
                            evidences = json.loads(evidence_details)
                            for evidence in evidences:
                                risk_rule_name = evidence.get("rule", "")
                                rule_criticality = int(evidence.get("criticality", "0"))
                                evidence_string = evidence.get("evidenceString", "")
                                mitigation = evidence.get("mitigationString", "")

                                for corresponding_rule in RISK_RULES_MAPPER:
                                    if (
                                        rule_criticality
                                        == corresponding_rule["rule_score"]
                                    ):
                                        description += (
                                            "|"
                                            + risk_rule_name
                                            + "|"
                                            + corresponding_rule["severity"]
                                            + "|"
                                            + evidence_string
                                            + "|"
                                            + mitigation
                                            + "|"
                                            + "\n"
                                        )
                                        labels.append(risk_rule_name)

                    else:
                        rule_criticality_list = (
                            row["RuleCriticality"].strip("][").split(",")
                        )
                        risk_rules_list_str = row["RiskRules"].strip("][")
                        risk_rules_list = re.sub(r"\"", "", risk_rules_list_str).split(
                            ","
                        )
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
                                if (
                                    criticality_score
                                    == corresponding_rule["rule_score"]
                                ):
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

                    # Convert into stix object
                    stix_obj = risk_list_type["class"](
                        row["Name"],
                        key,
                        tlp=self.tlp,
                        first_seen=first_seen,
                        last_seen=last_seen,
                    )

                    stix_obj.map_data(row, self.tlp, self.risklist_related_entities)

                    stix_obj.add_description(description)
                    if self.riskrules_as_label:
                        stix_obj.add_labels(labels)

                    stix_obj.build_bundle(stix_obj)
                    # Create bundle
                    bundle = stix_obj.to_stix_bundle()
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

            last_run_datetime = datetime.fromtimestamp(
                current_timestamp, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            current_state.update({"last_risk_lists_run": last_run_datetime})
            self.helper.set_state(state=current_state)

        except Exception as err:
            self.helper.connector_logger.error(str(err))
