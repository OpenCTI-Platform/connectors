import logging
import sys
from datetime import datetime

from pycti import OpenCTIConnectorHelper

from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .s1_client import SentinelOneClient


class IncidentConnector:
    def __init__(self):
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)

        self.cache = []
        self.to_process = []

        self.s1_client = SentinelOneClient(self.helper.connector_logger, self.config)
        self.stix_client = ConverterToStix(self.helper)

        # self._setup_development_logging(self.helper)

    def _setup_development_logging(self, helper):
        """
        Override json logging for more clarity in
        development :)

        """

        logging.basicConfig(
            format="%(levelname)s %(asctime)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.DEBUG,
            force=True,
        )

        logging.addLevelName(logging.DEBUG, "[*]")
        logging.addLevelName(logging.INFO, "[+]")
        logging.addLevelName(logging.WARNING, "[?]")
        logging.addLevelName(logging.ERROR, "[!]")
        logging.addLevelName(logging.CRITICAL, "[⚠️]")

    def process_message(self) -> None:
        """
        The main process for the connector, triggered
        at each interval. It first scans for any
        flagged Incidents that aren't in the cache and
        then processes each.

        """

        try:
            ############### PHASE 1: SCAN FOR INCIDENTS ###############
            friendly_name = "S1 Incident Connector: Scanning For Incidents"
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            self.helper.connector_logger.info(
                "Connector Beginning To Scan SentinelOne Instance For Flagged Incidents"
            )

            ###query new incidents
            self._query_new_incidents()

            ### after this, close that work
            self.helper.connector_logger.info(
                "Connector Completed Flagged Incidents Scan"
            )
            self.helper.api.work.to_processed(work_id, "completed scan")
            #########################################################

            ################ PHASE 2: Process Incidents ###############
            # Individual work is made and closed in the incident processing method.
            if self.to_process:
                self._process_incidents()
            #########################################################

            ################ PHASE 3: Update State ###############

            # Store the current timestamp as a last run of the connector
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.utcfromtimestamp(current_timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
            )
            self.helper.connector_logger.info(message)
            #########################################################

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped...")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """
        Schedules the connector to run at an interval
        based on the environment variables (or conf).
        """

        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )

    def _query_new_incidents(self):
        """
        Queries for new incidents that are flagged to the
        connector and adds them to the to_process list.
        """

        def is_applicable(incident_id):
            incident_notes = self.s1_client.fetch_incident_notes(incident_id)
            if incident_notes:
                for note in incident_notes:
                    if self.config.sign in note.get("text", ""):
                        return True
            else:
                return None
            return False

        # Retrieve all incidents from SentinelOne
        self.helper.connector_logger.info("Retrieving and filtering Incidents...")
        present_incidents = self.s1_client.fetch_incidents()
        if not present_incidents:
            self.helper.connector_logger.info(
                "Connector retreived no incidents from SentinelOne"
            )
            return
        self.helper.connector_logger.info(f"Found {len(present_incidents)} incidents")

        # Filter out incidents that are already cached or already in the to_process list
        uncached_incidents = [
            inc
            for inc in present_incidents
            if inc not in self.cache and inc not in self.to_process
        ]

        # Check if each incident is flagged via the sign in the notes
        for incident in uncached_incidents:
            applicability = is_applicable(incident)
            if applicability:
                self.to_process.append(incident)
                self.helper.connector_logger.info(
                    f"Found applicable incident with ID: {incident}"
                )
            elif applicability is None:
                self.helper.connector_logger.debug(
                    "Unable to determine applicability due to a SentinelOne API error"
                )
            else:
                self.helper.connector_logger.debug(
                    f"Sign not found in notes, incident not applicable with ID: {incident}"
                )

        self.helper.connector_logger.info("Retrieval process complete")

    def _process_incidents(self):
        """
        Processes each incident in the to_process list by creating
        corresponding stix objects.

        Incident objects are mandatory whereas the rest of objects
        are optional and depend on the incident data: UserAccount,
        Notes, Indicators, Attack Patterns.
        """

        self.helper.log_info(
            f"Connector Beginning creation of {len(self.to_process)} applicable Incidents"
        )
        for i, s1_incident_id in enumerate(self.to_process):
            friendly_name = f"S1 Incident Connector: Creating Incident From Threat with ID: {s1_incident_id}"

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            self.helper.log_info(
                f"Connector Beggining Creation of Incident for S1 ID: {s1_incident_id}"
            )

            s1_incident = self.s1_client.fetch_incident(s1_incident_id)
            if not s1_incident:
                self.helper.log_info(
                    "Unable to retrieve the Incident from SentinelOne, halting process."
                )
                return False

            stix_objects = []

            ### Incident + Source
            incident_items = self.stix_client.create_incident(
                s1_incident, s1_incident_id, self.config.s1_url
            )
            if not incident_items:
                self.helper.connector_logger.error(
                    "Connector unable to create Incident, creation process cannot continue."
                )
                break

            cti_incident_id = incident_items[0].get("id")
            stix_objects.extend(incident_items)

            ### UserAccount + Relationship to Incident
            account_items = self.stix_client.create_user_account_observable(
                s1_incident, cti_incident_id
            )
            stix_objects.extend(account_items)

            ### List Of Notes
            s1_incident_notes = self.s1_client.fetch_incident_notes(s1_incident_id)
            notes_items = self.stix_client.create_notes(
                s1_incident_notes, cti_incident_id
            )
            stix_objects.extend(notes_items)

            ### List Of Indicators  with Relationships to Incident
            indicators_items = self.stix_client.create_hash_indicators(
                s1_incident, cti_incident_id
            )
            stix_objects.extend(indicators_items)

            ### List Of Attack Patterns with Relationships to Incident and Sub Attack Patterns with
            ### Relationships to the Attack Patterns
            attack_patterns_items = self.stix_client.create_attack_patterns(
                s1_incident, cti_incident_id
            )
            stix_objects.extend(attack_patterns_items)

            ### Informative log of all created objects
            message = ""
            if incident_items:
                message += "Incident"
            if account_items:
                message += ", UserAccount"
            if notes_items:
                message += ", Notes"
            if indicators_items:
                message += ", Indicators"
            if attack_patterns_items:
                message += ", Attack Patterns"
            self.helper.connector_logger.info(
                f"Connector created the following objects for the Incident: {message}"
            )

            ### Send the bundle to OpenCTI
            bundle = self.helper.stix2_create_bundle(stix_objects)
            bundles_sent = self.helper.send_stix2_bundle(
                bundle, work_id=work_id, cleanup_inconsistent_bundle=True
            )
            self.helper.connector_logger.info(
                f"Connector Sent Bundle of {len(bundles_sent)} STIX objects to OpenCTI"
            )

            self.helper.api.work.to_processed(work_id, "completed creation of incident")
            self.cache.append(s1_incident_id)

        self.to_process = [inc for inc in self.to_process if inc not in self.cache]
        self.helper.log_info("Completed Incident Creation Process.")
