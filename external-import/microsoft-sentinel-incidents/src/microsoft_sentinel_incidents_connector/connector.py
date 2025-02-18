import json
import re
import sys
from datetime import datetime

import stix2
from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .utils import find_matching_file_ids, format_date


def detect_ip_version(value):
    if re.match(
        r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/([1-9]|[1-2]\d|3[0-2]))?$",
        value,
    ):
        return "ipv4"
    else:
        return "ipv6"


class MicrosoftSentinelIncidentsConnector:
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
        self.tlp_marking = stix2.TLP_RED
        self.converter_to_stix = ConverterToStix(
            self.helper, self.config, self.tlp_marking
        )

    def _get_last_incident_date(self) -> int:
        """
        Get last incident timestamp from connector's state.
        :return: Connector's state last incident timestamp
        """
        state = self.helper.get_state()
        if state and "last_incident_timestamp" in state:
            last_timestamp = state["last_incident_timestamp"]
            return last_timestamp

        if self.config.import_start_date:
            datetime_obj = datetime.fromisoformat(self.config.import_start_date)
            last_timestamp = int(round(datetime_obj.timestamp()))
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

    def _extract_intelligence(
        self, last_incident_timestamp: int, incident: dict
    ) -> list[object]:
        """
        Extract intelligence from incident and convert it to STIX 2.1 objects.
        :param incident: Incident to extract intelligence from
        :return: STIX 2.1 objects.
        """
        stix_objects = []

        # Get alerts
        alerts = self.client.get_alerts(
            last_incident_timestamp, incident.get("AlertIds", "")
        )

        for alert in alerts:
            # Create Stix Incident
            stix_incident = self.converter_to_stix.create_incident(alert)
            stix_objects.append(stix_incident)

            for technique in json.loads(
                alert.get("Techniques", "[]")
                if len(alert.get("Techniques", "[]")) > 0
                else "[]"
            ):
                # Create Stix AttackPattern
                stix_attack_pattern = (
                    self.converter_to_stix.create_mitre_attack_pattern(technique)
                )
                if stix_attack_pattern:
                    stix_objects.append(stix_attack_pattern)
                    stix_relationship_attack_pattern = (
                        self.converter_to_stix.create_relationship(
                            source_id=stix_incident.id,
                            target_id=stix_attack_pattern.id,
                            relationship_type="uses",
                        )
                    )
                    stix_objects.append(stix_relationship_attack_pattern)

            for technique in json.loads(
                alert.get("SubTechniques", "[]")
                if len(alert.get("SubTechniques", "[]")) > 0
                else "[]"
            ):
                # Create Stix AttackPattern
                stix_attack_pattern = (
                    self.converter_to_stix.create_mitre_attack_pattern(technique)
                )
                if stix_attack_pattern:
                    stix_objects.append(stix_attack_pattern)
                    stix_relationship_attack_pattern = (
                        self.converter_to_stix.create_relationship(
                            source_id=stix_incident.id,
                            target_id=stix_attack_pattern.id,
                            relationship_type="uses",
                        )
                    )
                    stix_objects.append(stix_relationship_attack_pattern)

            priority_evidence_files = {
                "process": 1,
                "file": 2,
                "filehash": 3,
            }
            entities = json.loads(
                alert.get("Entities", "[]")
                if len(alert.get("Entities", "[]")) > 0
                else "[]"
            )
            files_index = {}
            for entity in entities:
                evidence_type = entity.get("Type", None)
                match evidence_type:
                    # Account
                    case "account":
                        # Create Stix UserAccount
                        stix_account = (
                            self.converter_to_stix.create_evidence_user_account(entity)
                        )
                        if stix_account:
                            stix_objects.append(stix_account)
                            stix_relationship_account = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_account.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_account)

                    # IP Address
                    case "ip":
                        version = detect_ip_version(entity.get("Address"))
                        # Create Stix IPv4Address
                        if version == "ipv4":
                            stix_ip = self.converter_to_stix.create_evidence_ipv4(
                                entity
                            )
                        else:
                            stix_ip = self.converter_to_stix.create_evidence_ipv6(
                                entity
                            )
                        if stix_ip:
                            stix_objects.append(stix_ip)
                            stix_relationship_ip = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_ip.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_ip)

                    # URL
                    case "url":
                        # Create Stix Url
                        stix_url = self.converter_to_stix.create_evidence_url(entity)
                        if stix_url:
                            stix_objects.append(stix_url)
                            stix_relationship_url = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_url.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_url)

                    # Host
                    case "host":
                        # Create Identity system
                        stix_identity_system = (
                            self.converter_to_stix.create_evidence_identity_system(
                                entity
                            )
                        )
                        if stix_identity_system:
                            stix_objects.append(stix_identity_system)
                            stix_relationship_identity_system = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_incident.id,
                                    target_id=stix_identity_system.id,
                                    relationship_type="targets",
                                )
                            )
                            stix_objects.append(stix_relationship_identity_system)
                        # Create Hostname
                        stix_custom_observable_hostname = self.converter_to_stix.create_evidence_custom_observable_hostname(
                            entity
                        )
                        if stix_custom_observable_hostname:
                            stix_objects.append(stix_custom_observable_hostname)
                            stix_relationship_custom_observable_hostname_to_incident = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_custom_observable_hostname.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(
                                stix_relationship_custom_observable_hostname_to_incident
                            )
                            if stix_identity_system:
                                stix_relationship_custom_observable_hostname_to_system = self.converter_to_stix.create_relationship(
                                    source_id=stix_custom_observable_hostname.id,
                                    target_id=stix_identity_system.id,
                                    relationship_type="related-to",
                                )
                                stix_objects.append(
                                    stix_relationship_custom_observable_hostname_to_system
                                )

                    # process, file and filehash
                    case evidence_file if (
                        evidence_file in priority_evidence_files.keys()
                    ):
                        if evidence_type == "file":
                            file = entity
                        elif evidence_type == "process":
                            file = entity.get("ImageFile")
                        else:
                            file = entity.get("Value")

                        # Create Stix Directory
                        stix_directory = (
                            self.converter_to_stix.create_evidence_directory(file)
                            if isinstance(file, dict)
                            else None
                        )
                        # Create Stix File
                        stix_file = self.converter_to_stix.create_evidence_file(
                            entity, stix_directory
                        )
                        if stix_file:
                            # Add Stix File in stix_objects and relationship with incident
                            files_index[entity.get("$id")] = stix_file
                            stix_objects.append(stix_file)
                            stix_relationship_file = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_file.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_file)
                        if stix_directory:
                            # Add Stix Directory in stix_objects and relationship with incident
                            stix_objects.append(stix_directory)
                            stix_relationship_directory = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_directory.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_directory)
                        else:
                            self.helper.connector_logger.debug(
                                "The creation of the stix file will be ignored as it already exists "
                                "or no hashes are available.",
                                {"evidence": evidence_file, "hashes": file},
                            )

                    # malware
                    case "malware":
                        # Matching malware to files by name
                        files = entity.get("Files")
                        stix_files_objects = []
                        if files is not None and len(files) > 0:
                            for file in files:
                                file_ref = file.get("$ref")
                                if files_index.get(file_ref) is not None:
                                    stix_files_objects.append(files_index.get(file_ref))

                        # Create stix Malware
                        stix_malware = self.converter_to_stix.create_evidence_malware(
                            entity, stix_files_objects
                        )
                        if stix_malware:
                            stix_objects.append(stix_malware)
                            stix_relationship_malware = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_malware.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_malware)

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
                    {"last_incident_timestamp": last_incident_timestamp},
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

            # A token is valid for 1 hour so we get a fresh one on every run
            self.client.set_oauth_token()

            # Get incidents
            stix_objects = []
            incidents = self.client.get_incidents(last_incident_timestamp)
            for incident in incidents:
                incident_stix_objects = self._extract_intelligence(
                    last_incident_timestamp, incident
                )
                stix_objects.extend(incident_stix_objects)
                last_incident_timestamp = format_date(incident["LastModifiedTime"])

            if stix_objects:
                # Add author and default TLP marking for consistent bundle
                stix_objects.append(self.converter_to_stix.author)
                stix_objects.append(self.tlp_marking)

                stix_bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(
                    stix_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self._set_last_incident_date(last_incident_timestamp)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_incident_timestamp as "
                + str(last_incident_timestamp)
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
