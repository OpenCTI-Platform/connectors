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

import traceback

from models.configs.config_loader import ConfigLoader
from pycti import OpenCTIConnectorHelper
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
        # Load configuration using the new config loader
        self.config = ConfigLoader()

        # Initialize OpenCTI helper with the configuration
        self.helper = OpenCTIConnectorHelper(self.config.model_dump_pycti())

        # Extract configuration values from the loaded config
        self.rf_token = self.config.recorded_future.token.get_secret_value()
        self.rf_initial_lookback = self.config.recorded_future.initial_lookback
        self.tlp = self.config.recorded_future.tlp.lower()
        self.rf_pull_signatures = self.config.recorded_future.pull_signatures
        self.rf_pull_risk_list = self.config.recorded_future.pull_risk_list
        self.rf_riskrules_as_label = self.config.recorded_future.riskrules_as_label
        self.rf_insikt_only = self.config.recorded_future.insikt_only

        # Handle topics - convert list to comma-separated string if needed
        self.rf_topics = (
            self.config.recorded_future.topic
            if self.config.recorded_future.topic
            else [None]
        )

        self.rf_person_to_TA = self.config.recorded_future.person_to_ta
        self.rf_TA_to_intrusion_set = self.config.recorded_future.ta_to_intrusion_set
        self.risk_as_score = self.config.recorded_future.risk_as_score
        self.risk_threshold = self.config.recorded_future.risk_threshold
        self.risk_list_threshold = self.config.recorded_future.risk_list_threshold
        self.analyst_notes_guess_relationships = (
            self.config.recorded_future.analyst_notes_guess_relationships
        )

        self.rfapi = RFClient(
            self.rf_token,
            self.helper,
            header=f"OpenCTI/{APP_VERSION}",
        )

        # In a crisis, smash glass and uncomment this line of code
        # self.helper.config['uri'] = self.helper.config['uri'].replace('rabbitmq', '172.19.0.6')

        self.rf_pull_threat_maps = self.config.recorded_future.pull_threat_maps

        # Handle risk list related entities
        if self.config.recorded_future.risklist_related_entities is None:
            if self.rf_pull_risk_list:
                raise ValueError(
                    "Missing or incorrect value in configuration parameter 'Risk List Related Entities'"
                )
            self.risklist_related_entities = []
        else:
            self.risklist_related_entities = (
                self.config.recorded_future.risklist_related_entities
            )

        self.rf_pull_analyst_notes = self.config.recorded_future.pull_analyst_notes
        self.last_published_notes_interval = (
            self.config.recorded_future.last_published_notes
        )
        self.duration_period = self.config.connector.duration_period
        self.rf_interval = self.config.recorded_future.interval
        self.priority_alerts_only = self.config.alert.priority_alerts_only

        self.rf_alerts_api = RecordedFutureApiClient(
            x_rf_token=self.rf_token,
            helper=self.helper,
            base_url="https://api.recordedfuture.com/",
            priority_alerts_only=self.priority_alerts_only,
        )

        self.rf_alert_enable = self.config.alert.enable
        self.opencti_default_severity = self.config.alert.default_opencti_severity
        self.rf_playbook_alert_enable = self.config.playbook_alert.enable
        self.severity_threshold_domain_abuse = (
            self.config.playbook_alert.severity_threshold_domain_abuse
        )
        self.severity_threshold_identity_novel_exposures = (
            self.config.playbook_alert.severity_threshold_identity_novel_exposures
        )
        self.severity_threshold_code_repo_leakage = (
            self.config.playbook_alert.severity_threshold_code_repo_leakage
        )
        self.debug_var = self.config.playbook_alert.debug


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
                self.RF.analyst_notes_guess_relationships,
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
