from datetime import datetime

from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .utils import validate_incident, format_incident
from dateutil.parser import parse


class SentinelSightingsConnector:
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables
        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.
        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

    def _get_last_incident_date(self):
        state = self.helper.get_state()
        if state and "lastIncidentTimestamp" in state:
            last_timestamp = state["lastIncidentTimestamp"]
        else:
            last_timestamp = 0
        return last_timestamp

    def _set_last_incident_date(self, incident_timestamp):
        state = self.helper.get_state()
        if state is not None:
            state["lastIncidentTimestamp"] = incident_timestamp
            self.helper.set_state(state)
        else:
            self.helper.set_state({"lastIncidentTimestamp": incident_timestamp})

    def _collect_intelligence(self) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        stix_objects = []

        # ===========================
        # === Add your code below ===
        # ===========================

        # Get entities from external sources
        entities = self.client.get_entities()

        # Convert into STIX2 object and add it on a list
        for entity in entities:
            entity_to_stix = self.converter_to_stix.create_obs(entity["value"])
            stix_objects.append(entity_to_stix)

        return stix_objects

        # ===========================
        # === Add your code above ===
        # ===========================

    # def process_message(self) -> None:
    #     """
    #     Connector main process to collect intelligence
    #     :return: None
    #     """
    #     self.helper.connector_logger.info(
    #         "[CONNECTOR] Starting connector...",
    #         {"connector_name": self.helper.connect_name},
    #     )
    #
    #     try:
    #         # Get the current state
    #         now = datetime.now()
    #         current_timestamp = int(datetime.timestamp(now))
    #         current_state = self.helper.get_state()
    #
    #         if current_state is not None and "last_run" in current_state:
    #             last_run = current_state["last_run"]
    #
    #             self.helper.connector_logger.info(
    #                 "[CONNECTOR] Connector last run",
    #                 {"last_run_datetime": last_run},
    #             )
    #         else:
    #             self.helper.connector_logger.info(
    #                 "[CONNECTOR] Connector has never run..."
    #             )
    #
    #         # Friendly name will be displayed on OpenCTI platform
    #         friendly_name = "Connector template feed"
    #
    #         # Initiate a new work
    #         work_id = self.helper.api.work.initiate_work(
    #             self.helper.connect_id, friendly_name
    #         )
    #
    #         self.helper.connector_logger.info(
    #             "[CONNECTOR] Running connector...",
    #             {"connector_name": self.helper.connect_name},
    #         )
    #
    #         # Performing the collection of intelligence
    #         # ===========================
    #         # === Add your code below ===
    #         # ===========================
    #         stix_objects = self._collect_intelligence()
    #
    #         if stix_objects is not None and len(stix_objects) is not None:
    #             stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
    #             bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)
    #
    #             self.helper.connector_logger.info(
    #                 "Sending STIX objects to OpenCTI...",
    #                 {"bundles_sent": {str(len(bundles_sent))}},
    #             )
    #         # ===========================
    #         # === Add your code above ===
    #         # ===========================
    #
    #         # Store the current timestamp as a last run of the connector
    #         self.helper.connector_logger.debug(
    #             "Getting current state and update it with last run of the connector",
    #             {"current_timestamp": current_timestamp},
    #         )
    #         current_state = self.helper.get_state()
    #         current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
    #         last_run_datetime = datetime.utcfromtimestamp(current_timestamp).strftime(
    #             "%Y-%m-%d %H:%M:%S"
    #         )
    #         if current_state:
    #             current_state["last_run"] = current_state_datetime
    #         else:
    #             current_state = {"last_run": current_state_datetime}
    #         self.helper.set_state(current_state)
    #
    #         message = (
    #             f"{self.helper.connect_name} connector successfully run, storing last_run as "
    #             + str(last_run_datetime)
    #         )
    #
    #         self.helper.api.work.to_processed(work_id, message)
    #         self.helper.connector_logger.info(message)
    #
    #     except (KeyboardInterrupt, SystemExit):
    #         self.helper.connector_logger.info(
    #             "[CONNECTOR] Connector stopped...",
    #             {"connector_name": self.helper.connect_name},
    #         )
    #         sys.exit(0)
    #     except Exception as err:
    #         self.helper.connector_logger.error(str(err))

    def process_message(self):
        incidents = self.client.get_incidents()
        last_timestamp = self._get_last_incident_date()

        for incident in reversed(incidents):
            incident = format_incident(incident)
            if validate_incident(incident, last_timestamp):
                incident_date = parse(incident["createdDateTime"]).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                # Mark as processed
                self._set_last_incident_date(incident["lastUpdateDateTime"])
                # Create the bundle
                case_objects = []
                bundle_objects = []

                for alert in incident["alerts"]:
                    stix_incident = self.converter_to_stix.create_incident(alert)
                    case_objects.append(stix_incident)
                    bundle_objects.append(stix_incident)
                    for technique in alert["mitreTechniques"]:
                        stix_attack_pattern = (
                            self.converter_to_stix.create_mitre_attack_pattern(
                                technique
                            )
                        )
                        case_objects.append(stix_attack_pattern)
                        bundle_objects.append(stix_attack_pattern)
                        stix_relationship_attack_pattern = (
                            self.converter_to_stix.create_relationship(
                                source_id=stix_incident.id,
                                target_id=stix_attack_pattern.id,
                                relationship_type="uses",
                            )
                        )
                        case_objects.append(stix_relationship_attack_pattern)
                        bundle_objects.append(stix_relationship_attack_pattern)
                    for evidence in alert["evidence"]:
                        if (
                            evidence["@odata.type"]
                            == "#microsoft.graph.security.userEvidence"
                        ):
                            stix_account = (
                                self.converter_to_stix.create_alert_user_account(
                                    evidence
                                )
                            )
                            case_objects.append(stix_account)
                            bundle_objects.append(stix_account)

                            stix_relationship_account = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_account.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            case_objects.append(stix_relationship_account)
                            bundle_objects.append(stix_relationship_account)
                        if (
                            evidence["@odata.type"]
                            == "#microsoft.graph.security.ipEvidence"
                        ):
                            stix_ip = self.converter_to_stix.create_alert_ipv4(evidence)
                            case_objects.append(stix_ip)
                            bundle_objects.append(stix_ip)
                            stix_relationship_ip = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_ip.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            case_objects.append(stix_relationship_ip)
                            bundle_objects.append(stix_relationship_ip)
                        if (
                            evidence["@odata.type"]
                            == "#microsoft.graph.security.urlEvidence"
                        ):
                            stix_url = self.converter_to_stix.create_alert_url(evidence)
                            case_objects.append(stix_url)
                            bundle_objects.append(stix_url)
                            stix_relationship_url = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_url.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            case_objects.append(stix_relationship_url)
                            bundle_objects.append(stix_relationship_url)
                        if (
                            evidence["@odata.type"]
                            == "#microsoft.graph.security.deviceEvidence"
                        ):
                            stix_hostname = self.converter_to_stix.create_custom_observable_hostname(
                                evidence
                            )
                            case_objects.append(stix_hostname)
                            bundle_objects.append(stix_hostname)
                            stix_relationship_hostname = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_hostname.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            case_objects.append(stix_relationship_hostname)
                            bundle_objects.append(stix_relationship_hostname)
                        if (
                            evidence["@odata.type"]
                            == "#microsoft.graph.security.processEvidence"
                        ):
                            stix_file = self.converter_to_stix.create_alert_file(
                                evidence
                            )
                            case_objects.append(stix_file)
                            bundle_objects.append(stix_file)
                            stix_relationship_file = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_file.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            case_objects.append(stix_relationship_file)
                            bundle_objects.append(stix_relationship_file)

                stix_case = self.converter_to_stix.create_custom_case_incident(incident)
                bundle_objects.append(stix_case)

                if bundle_objects:
                    stix_bundle = self.helper.stix2_create_bundle(bundle_objects)
                    now = datetime.now()
                    friendly_name = "Sentinel run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    self.helper.send_stix2_bundle(
                        stix_bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                    )
                    message = "Connector successfully run"
                    self.helper.api.work.to_processed(work_id, message)

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
