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
import traceback

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from rflib import (
    APP_VERSION,
    AnalystNote,
    RecordedFutureAlertConnector,
    RecordedFutureApiClient,
    RecordedFuturePlaybookAlertConnector,
    RFClient,
    RiskList,
    ThreatMap,
)


class BaseRFConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Extra config
        self.rf_token = get_config_variable(
            "RECORDED_FUTURE_TOKEN", ["rf", "token"], config, required=True
        )

        self.rf_initial_lookback = get_config_variable(
            "RECORDED_FUTURE_INITIAL_LOOKBACK",
            ["rf", "initial_lookback"],
            config,
            isNumber=True,
        )

        self.tlp = get_config_variable(
            "RECORDED_FUTURE_TLP", ["rf", "TLP"], config, required=True, default="red"
        ).lower()

        self.rf_pull_signatures = get_config_variable(
            "RECORDED_FUTURE_PULL_SIGNATURES", ["rf", "pull_signatures"], config
        )
        self.rf_pull_risk_list = get_config_variable(
            "RECORDED_FUTURE_PULL_RISK_LIST", ["rf", "pull_risk_list"], config
        )
        self.rf_riskrules_as_label = get_config_variable(
            "RECORDED_FUTURE_RISKRULES_AS_LABEL",
            ["rf", "riskrules_as_label"],
            config,
            default=False,
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

        self.rf_pull_analyst_notes = get_config_variable(
            "RECORDED_FUTURE_PULL_ANALYST_NOTES", ["rf", "pull_analyst_notes"], config
        )

        self.last_published_notes_interval = get_config_variable(
            "RECORDED_FUTURE_LAST_PUBLISHED_NOTES",
            ["rf", "last_published_notes"],
            config,
        )

        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD", ["connector", "duration_period"], config
        )

        self.rf_interval = get_config_variable(
            "RECORDED_FUTURE_INTERVAL",
            ["rf", "interval"],
            config,
            default=24,  # in Hours
        )

        self.priority_alerts_only = get_config_variable(
            "ALERT_PRIORITY_ALERTS_ONLY",
            ["alert", "priority_alerts_only"],
            config,
            default=False,
        )

        self.rf_alerts_api = RecordedFutureApiClient(
            x_rf_token=self.rf_token,
            helper=self.helper,
            base_url="https://api.recordedfuture.com/",
            priority_alerts_only=self.priority_alerts_only,
        )

        self.rf_alert_enable = get_config_variable(
            "ALERT_ENABLE", ["alert", "enable"], config
        )

        self.opencti_default_severity = get_config_variable(
            "ALERT_DEFAULT_OPENCTI_SEVERITY",
            ["alert", "default_opencti_severity"],
            config,
            default="low",
        )

        self.rf_playbook_alert_enable = get_config_variable(
            "PLAYBOOK_ALERT_ENABLE", ["playbook_alert", "enable"], config
        )

        self.severity_threshold_domain_abuse = get_config_variable(
            "PLAYBOOK_ALERT_SEVERITY_THRESHOLD_DOMAIN_ABUSE",
            ["playbook_alert", "severity_threshold_domain_abuse"],
            config,
            required=False,
            default="Informational",
        )
        self.severity_threshold_identity_novel_exposures = get_config_variable(
            "PLAYBOOK_ALERT_SEVERITY_THRESHOLD_IDENTITY_NOVEL_EXPOSURES",
            ["playbook_alert", "severity_threshold_identity_novel_exposures"],
            config,
            required=False,
            default="Informational",
        )

        self.severity_threshold_code_repo_leakage = get_config_variable(
            "PLAYBOOK_ALERT_SEVERITY_THRESHOLD_CODE_REPO_LEAKAGE",
            ["playbook_alert", "severity_threshold_code_repo_leakage"],
            config,
            required=False,
            default="Informational",
        )

        self.debug_var = get_config_variable(
            "PLAYBOOK_ALERT_DEBUG",
            ["playbook_alert", "debug"],
            config,
            required=False,
            default=False,
        )


class RFConnector:
    def __init__(self):
        self.RF = BaseRFConnector()
        self.analyst_notes = None
        self.risk_list = None
        self.threat_maps = None
        self.alerts = None
        self.alerts_playbook = None

    def all_processes(self):
        # Start RF Alert Connector
        if self.RF.rf_alert_enable:
            self.alerts = RecordedFutureAlertConnector(
                self.RF.helper,
                self.RF.rf_alerts_api,
                self.RF.opencti_default_severity,
                self.RF.tlp,
            )
            self.alerts.run()
        else:
            self.RF.helper.connector_logger.info("[ALERTS] Alerts fetching disabled")

        # Start RF Alert playbook
        if self.RF.rf_playbook_alert_enable:
            self.alerts_playbook = RecordedFuturePlaybookAlertConnector(
                self.RF.helper,
                self.RF.rf_alerts_api,
                self.RF.severity_threshold_domain_abuse,
                self.RF.severity_threshold_identity_novel_exposures,
                self.RF.severity_threshold_code_repo_leakage,
                self.RF.debug_var,
                self.RF.tlp,
            )
            self.alerts_playbook.run()
        else:
            self.RF.helper.connector_logger.info(
                "[PLAYBOOK ALERTS] Playbook alerts fetching disabled"
            )

        # Pull RF risk lists
        if self.RF.rf_pull_risk_list:
            self.risk_list = RiskList(
                self.RF.helper,
                self.RF.rfapi,
                self.RF.tlp,
                self.RF.risk_list_threshold,
                self.RF.risklist_related_entities,
                self.RF.rf_riskrules_as_label,
            )
            self.risk_list.start()
        else:
            self.RF.helper.connector_logger.info(
                "[RISK LISTS] Risk list fetching disabled"
            )

        # Pull RF Threat actors and Malware from Threat map
        if self.RF.rf_pull_threat_maps:
            self.threat_maps = ThreatMap(
                self.RF.helper,
                self.RF.rfapi,
                self.RF.tlp,
                self.RF.risk_list_threshold,
            )
            self.threat_maps.start()
        else:
            self.RF.helper.connector_logger.info(
                "[THREAT MAPS] Threat maps fetching disabled"
            )

        # Pull Analyst Notes if enabled
        if self.RF.rf_pull_analyst_notes:
            self.analyst_notes = AnalystNote(
                self.RF.helper,
                self.RF.rfapi,
                self.RF.last_published_notes_interval,
                self.RF.rf_initial_lookback,
                self.RF.rf_pull_signatures,
                self.RF.rf_insikt_only,
                self.RF.rf_topics,
                self.RF.tlp,
                self.RF.rf_person_to_TA,
                self.RF.rf_TA_to_intrusion_set,
                self.RF.risk_as_score,
                self.RF.risk_threshold,
            )
            self.analyst_notes.start()
        else:
            self.RF.helper.connector_logger.info(
                "[ANALYST NOTES] Analyst notes fetching disabled"
            )

    def run_all_processes(self):
        if self.RF.duration_period:
            self.RF.helper.schedule_iso(
                message_callback=self.all_processes,
                duration_period=self.RF.duration_period,
            )
        else:
            self.RF.helper.schedule_unit(
                message_callback=self.all_processes,
                duration_period=self.RF.rf_interval,
                time_unit=self.RF.helper.TimeUnit.HOURS,
            )


if __name__ == "__main__":
    try:
        RF_connector = RFConnector()
        RF_connector.run_all_processes()
    except Exception:
        traceback.print_exc()
        exit(1)
