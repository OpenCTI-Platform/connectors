"""Connector to bulk ingest Recorded Future Risk Lists as STIX2 bundles
############################## TERMS OF USE ####################################
# The following code is provided for demonstration purposes only, and should   #
# not be used without independent verification. Recorded Future makes no       #
# representations or warranties, express, implied, statutory, or otherwise,    #
# regarding this code, and provides it strictly "as-is".                       #
# Recorded Future shall not be liable for, and you assume all risk of          #
# using the foregoing.                                                         #
################################################################################
"""

import os
import time
import traceback
from datetime import datetime

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from rflib import (
    APP_VERSION,
    RecordedFutureAlertConnector,
    RFClient,
    RiskList,
    StixNote,
    ThreatMap,
)


class RFNotes:
    """Connector object"""

    def __init__(self):
        """Read in config variables"""

        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.rf_token = get_config_variable(
            "RECORDED_FUTURE_TOKEN", ["rf", "token"], config
        )
        self.rf_initial_lookback = get_config_variable(
            "RECORDED_FUTURE_INITIAL_LOOKBACK",
            ["rf", "initial_lookback"],
            config,
            isNumber=True,
        )
        self.rf_interval = get_config_variable(
            "RECORDED_FUTURE_INTERVAL", ["rf", "interval"], config, isNumber=True
        )
        self.rf_risk_list_interval = get_config_variable(
            "RECORDED_FUTURE_RISK_LIST_INTERVAL",
            ["rf", "risk_list_interval"],
            config,
            isNumber=True,
        )
        self.tlp = get_config_variable(
            "RECORDED_FUTURE_TLP", ["rf", "TLP"], config
        ).lower()

        self.rf_pull_signatures = get_config_variable(
            "RECORDED_FUTURE_PULL_SIGNATURES", ["rf", "pull_signatures"], config
        )
        self.rf_pull_risk_list = get_config_variable(
            "RECORDED_FUTURE_PULL_RISK_LIST", ["rf", "pull_risk_list"], config
        )
        self.rf_insikt_only = get_config_variable(
            "RECORDED_FUTURE_INSIKT_ONLY", ["rf", "insikt_only"], config
        )
        topics_value = get_config_variable(
            "RECORDED_FUTURE_TOPIC", ["rf", "topic"], config
        )
        self.rf_topics = topics_value.split(",") if topics_value else [None]
        self.rf_person_to_TA = get_config_variable(
            "RECORDED_FUTURE_PERSON_TO_TA", ["rf", "person_to_TA"], config
        )
        self.rf_TA_to_intrusion_set = get_config_variable(
            "RECORDED_FUTURE_TA_TO_INTRUSION_SET",
            ["rf", "TA_to_intrusion_set"],
            config,
        )
        self.risk_as_score = get_config_variable(
            "RECORDED_FUTURE_RISK_AS_SCORE", ["rf", "risk_as_score"], config
        )
        self.risk_threshold = get_config_variable(
            "RECORDED_FUTURE_RISK_THRESHOLD",
            ["rf", "risk_threshold"],
            config,
            True,
        )
        self.risk_list_threshold = get_config_variable(
            "RECORDED_FUTURE_RISK_LIST_THRESHOLD",
            ["rf", "risk_list_threshold"],
            config,
            True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.rfapi = RFClient(
            self.rf_token,
            self.helper,
            header=f"OpenCTI/{APP_VERSION}",
        )
        # In a crisis, smash glass and uncomment this line of code
        # self.helper.config['uri'] = self.helper.config['uri'].replace('rabbitmq', '172.19.0.6')

        self.rf_pull_threat_maps = get_config_variable(
            "RECORDED_FUTURE_PULL_THREAT_MAPS", ["rf", "pull_threat_maps"], config
        )

        self.threat_maps_interval = get_config_variable(
            "RECORDED_FUTURE_THREAT_MAPS_INTERVAL",
            ["rf", "threat_maps_interval"],
            config,
        )

        risklist_related_entities_list = get_config_variable(
            "RECORDED_FUTURE_RISKLIST_RELATED_ENTITIES",
            ["rf", "risklist_related_entities"],
            config,
        )

        if risklist_related_entities_list is None:
            raise ValueError(
                "Missing or incorrect value in configuration parameter 'Risk List Related Entities'"
            )
        else:
            self.risklist_related_entities = risklist_related_entities_list.split(",")

        self.rf_alert_enable = get_config_variable(
            "ALERT_ENABLE", ["alert", "enable"], config
        )

    def get_interval(self):
        """Converts interval hours to seconds"""
        return int(self.rf_interval) * 3600

    def run(self):
        """Run connector on a schedule"""
        while True:
            timestamp = int(time.time())
            now = datetime.utcfromtimestamp(timestamp)
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "Recorded Future Analyst Notes run @ "
                + now.strftime("%Y-%m-%d %H:%M:%S"),
            )
            self.helper.log_info("[ANALYST NOTES] Pulling analyst notes")

            current_state = self.helper.get_state()
            tas = self.rfapi.get_threat_actors()
            if current_state is not None and "last_run" in current_state:
                last_run = datetime.utcfromtimestamp(
                    current_state["last_run"]
                ).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.log_info("Connector last run: " + last_run)
                published = self.rf_interval
            else:
                last_run = None
                msg = (
                    "Connector has never run. Doing initial pull of"
                    f"{self.rf_initial_lookback} hours"
                )
                self.helper.log_info(msg)
                published = self.rf_initial_lookback

            try:
                # Import, convert and send to OpenCTI platform Analyst Notes
                self.convert_and_send(published, tas, work_id)
            except Exception as e:
                self.helper.log_error(str(e))

            self.helper.set_state({"last_run": timestamp})
            time.sleep(self.get_interval())

    def convert_and_send(self, published, tas, work_id):
        """Pulls Analyst Notes, converts to Stix2, sends to OpenCTI"""
        self.helper.log_info(
            f"[ANALYST NOTES] Pull Signatures is {str(self.rf_pull_signatures)} of type "
            f"{type(self.rf_pull_signatures)}"
        )
        self.helper.log_info(
            f"[ANALYST NOTES] Insikt Only is {str(self.rf_insikt_only)} of type {type(self.rf_insikt_only)}"
        )
        self.helper.log_info(
            f"[ANALYST NOTES] Topics are {str(self.rf_topics)} of type {type(self.rf_topics)}"
        )
        notes = []
        notes_ids = []
        for topic in self.rf_topics:
            new_notes = self.rfapi.get_notes(
                published, self.rf_pull_signatures, self.rf_insikt_only, topic
            )
            for new_note in new_notes:
                if new_note["id"] not in notes_ids:
                    notes.append(new_note)
                    notes_ids.append(new_note["id"])

        self.helper.log_info(
            f"[ANALYST NOTES] Fetched {len(notes)} Analyst notes from API"
        )
        for note in notes:
            try:
                stixnote = StixNote(
                    self.helper,
                    tas,
                    self.rfapi,
                    self.tlp,
                    self.rf_person_to_TA,
                    self.rf_TA_to_intrusion_set,
                    self.risk_as_score,
                    self.risk_threshold,
                )
                stixnote.from_json(note, self.tlp)
                stixnote.create_relations()
                bundle = stixnote.to_stix_bundle()
                self.helper.log_info(
                    "[ANALYST NOTES] Sending Bundle to server with "
                    + str(len(bundle.objects))
                    + " objects"
                )
                self.helper.send_stix2_bundle(
                    bundle.serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
            except Exception as exception:
                self.helper.log_error(
                    f"[ANALYST NOTES] Bundle has been skipped due to exception: "
                    f"{str(exception)}"
                )
                continue


if __name__ == "__main__":
    try:
        RF = RFNotes()

        # Start RF Alert Connector
        if RF.rf_alert_enable:
            RfCon = RecordedFutureAlertConnector(RF.helper)
            RfCon.run()
        # Pull RF risk lists
        if RF.rf_pull_risk_list:
            RiskList = RiskList(
                RF.helper,
                RF.update_existing_data,
                RF.rf_risk_list_interval,
                RF.rfapi,
                RF.tlp,
                RF.risk_list_threshold,
                RF.risklist_related_entities,
            )
            RiskList.start()
        else:
            RF.helper.log_info("[RISK LISTS] Risk list fetching disabled")

        # Pull RF Threat actors and Malware from Threat map
        if RF.rf_pull_threat_maps:
            ThreatMap = ThreatMap(
                RF.helper,
                RF.update_existing_data,
                RF.threat_maps_interval,
                RF.rfapi,
                RF.tlp,
                RF.risk_list_threshold,
            )
            ThreatMap.start()
        else:
            RF.helper.log_info("[THREAT MAPS] Threat maps fetching disabled")

        RF.run()
    except Exception:
        traceback.print_exc()
        time.sleep(10)
        exit(0)
