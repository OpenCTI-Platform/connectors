import sys

from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .utils import format_incident, validate_incident


class SentinelIncidentsConnector:
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

    def _get_last_incident_date(self) -> int:
        """
        Get last incident timestamp from connector's state.
        :return: Connector's state last incident timestamp
        """
        state = self.helper.get_state()
        if state and "last_incident_timestamp" in state:
            last_timestamp = state["last_incident_timestamp"]
        else:
            last_timestamp = 0
        return last_timestamp

    def _set_last_incident_date(self, incident_timestamp: int):
        """
        Set last incident timestamp to connector's state.'
        :param incident_timestamp: Last incident timestamp
        """
        state = self.helper.get_state()
        if state is not None:
            state["last_incident_timestamp"] = incident_timestamp
            self.helper.set_state(state)
        else:
            self.helper.set_state({"last_incident_timestamp": incident_timestamp})

    def _extract_intelligence(self, incident) -> list[object]:
        """
        Extract intelligence from incident and convert it to STIX 2.1 objects.
        :param incident: Incident to extract intelligence from
        :return: STIX 2.1 objects
        """
        stix_objects = []

        for alert in incident["alerts"]:
            stix_incident = self.converter_to_stix.create_incident(alert)
            stix_objects.append(stix_incident)

            for technique in alert["mitreTechniques"]:
                stix_attack_pattern = (
                    self.converter_to_stix.create_mitre_attack_pattern(technique)
                )
                stix_objects.append(stix_attack_pattern)
                stix_relationship_attack_pattern = (
                    self.converter_to_stix.create_relationship(
                        source_id=stix_incident.id,
                        target_id=stix_attack_pattern.id,
                        relationship_type="uses",
                    )
                )
                stix_objects.append(stix_relationship_attack_pattern)
            for evidence in alert["evidence"]:
                evidence_type = evidence["@odata.type"]
                match evidence_type:
                    case "#microsoft.graph.security.userEvidence":
                        stix_account = (
                            self.converter_to_stix.create_evidence_user_account(
                                evidence
                            )
                        )
                        stix_objects.append(stix_account)
                        stix_relationship_account = (
                            self.converter_to_stix.create_relationship(
                                source_id=stix_account.id,
                                target_id=stix_incident.id,
                                relationship_type="related-to",
                            )
                        )
                        stix_objects.append(stix_relationship_account)
                    case "#microsoft.graph.security.ipEvidence":
                        stix_ip = self.converter_to_stix.create_evidence_ipv4(evidence)
                        stix_objects.append(stix_ip)
                        stix_relationship_ip = (
                            self.converter_to_stix.create_relationship(
                                source_id=stix_ip.id,
                                target_id=stix_incident.id,
                                relationship_type="related-to",
                            )
                        )
                        stix_objects.append(stix_relationship_ip)
                    case "#microsoft.graph.security.urlEvidence":
                        stix_url = self.converter_to_stix.create_evidence_url(evidence)
                        stix_objects.append(stix_url)
                        stix_relationship_url = (
                            self.converter_to_stix.create_relationship(
                                source_id=stix_url.id,
                                target_id=stix_incident.id,
                                relationship_type="related-to",
                            )
                        )
                        stix_objects.append(stix_relationship_url)
                    case "#microsoft.graph.security.deviceEvidence":
                        stix_hostname = self.converter_to_stix.create_evidence_custom_observable_hostname(
                            evidence
                        )
                        stix_objects.append(stix_hostname)
                        stix_relationship_hostname = (
                            self.converter_to_stix.create_relationship(
                                source_id=stix_hostname.id,
                                target_id=stix_incident.id,
                                relationship_type="related-to",
                            )
                        )
                        stix_objects.append(stix_relationship_hostname)
                    case "#microsoft.graph.security.processEvidence":
                        stix_file = self.converter_to_stix.create_evidence_file(
                            evidence
                        )
                        stix_objects.append(stix_file)
                        stix_relationship_file = (
                            self.converter_to_stix.create_relationship(
                                source_id=stix_file.id,
                                target_id=stix_incident.id,
                                relationship_type="related-to",
                            )
                        )
                        stix_objects.append(stix_relationship_file)

        stix_case = self.converter_to_stix.create_custom_case_incident(
            incident, stix_objects
        )
        stix_objects.append(stix_case)
        return stix_objects

    def process_message(self):
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            last_incident_timestamp = self._get_last_incident_date()
            if last_incident_timestamp:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last imported incident timestamp:",
                    {"last_incident_datetime": last_incident_timestamp},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, self.helper.connect_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            incidents = self.client.get_incidents()
            for incident in reversed(incidents):
                incident = format_incident(incident)
                if validate_incident(incident, last_incident_timestamp):
                    stix_objects = self._extract_intelligence(incident)
                    if stix_objects:
                        stix_bundle = self.helper.stix2_create_bundle(stix_objects)
                        self.helper.send_stix2_bundle(
                            stix_bundle,
                            work_id=work_id,
                            cleanup_inconsistent_bundle=True,
                        )

                        self._set_last_incident_date(incident["lastUpdateDateTime"])

                        message = (
                            f"{self.helper.connect_name} connector successfully run, storing last_incident_timestamp as "
                            + str(incident["lastUpdateDateTime"])
                        )
                        self.helper.api.work.to_processed(work_id, message)
                        self.helper.connector_logger.info(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

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
