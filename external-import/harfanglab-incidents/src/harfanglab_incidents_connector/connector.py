import sys
from datetime import datetime

from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper

from .client_api import HarfanglabClient
from .config_variables import ConfigConnector
from .constants import EPOCH_DATETIME
from .converter_to_stix import ConverterToStix
from .models import harfanglab, opencti


class HarfanglabIncidentsConnector:
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
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.api = HarfanglabClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

        self.should_import_case_incidents = self.config.harfanglab_import_threats
        self.last_import_datetime_key = (
            "last_case_incident_datetime"
            if self.should_import_case_incidents
            else "last_incident_datetime"
        )
        self.last_import_datetime_value = self._get_state_last_datetime()

    def _initiate_work(self) -> str:
        """
        Initiate an atomic unit of work that will be handled by the worker.
        A work can contain one or many STIX bundles.
        :return: Initialized work ID
        """
        if self.last_import_datetime_value > EPOCH_DATETIME:
            self.helper.connector_logger.info(
                f"[CONNECTOR] Connector {self.last_import_datetime_key}:",
                {self.last_import_datetime_key: self.last_import_datetime_value},
            )
        else:
            self.helper.connector_logger.info("[CONNECTOR] Connector has never run...")

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, self.helper.connect_name
        )
        return work_id

    def _terminate_work(self, work_id):
        """
        Terminate and send a work to the worker in order to process it.
        :param work_id: ID of the work to send
        """
        message = (
            f"{self.helper.connect_name} connector successfully run, "
            f"storing {self.last_import_datetime_key} as {self.last_import_datetime_value.isoformat()}"
        )
        self.helper.api.work.to_processed(work_id, message)
        self.helper.connector_logger.info(message)

    def _get_state_last_datetime(self) -> datetime:
        """
        Get either "last_incident_datetime" or "last_case_incident_datetime" from connector's state.
        The state key is "Last_case_incident_datetime" if the connector imports Harfanglab threats,
        otherwise it's "last_incident_datetime".
        :return: Datetime of the state key
        """
        state_last_datetime = None
        state = self.helper.get_state()
        if state:
            state_last_datetime = state.get(self.last_import_datetime_key)
            state_last_datetime = (
                parse(state_last_datetime) if state_last_datetime else None
            )
        if state_last_datetime is None:
            state_last_datetime = self.config.harfanglab_import_start_datetime
        return state_last_datetime

    def _set_state_last_datetime(self, value: datetime):
        """
        Set either "last_incident_datetime" or "last_case_incident_datetime" in connector's state.
        It sets "Last_case_incident_datetime" if the connector imports Harfanglab threats, otherwise "last_incident_datetime".
        :param value: Datetime to set as key's value
        """
        state = self.helper.get_state()
        if state:
            state[self.last_import_datetime_key] = value.isoformat()
        else:
            state = {self.last_import_datetime_key: value.isoformat()}
        self.helper.set_state(state)

    def _collect_incident_intelligence(
        self, threat: harfanglab.Threat | None = None
    ) -> list[opencti.BaseModel]:
        """
        Collect intelligence from Harfanglab and convert into STIX object
        If `threat` is provided, all the alerts related to the threat are collected,
        otherwise alerts are filtered by creation date according to connector's state.
        :param threat: [optional] Threat to collect alert intelligence for.
        :return: List of STIX objects
        """
        stix_objects = []

        if threat:
            alerts = self.api.generate_alerts(threat_id=threat.id)
        else:
            alerts = self.api.generate_alerts(since=self.last_import_datetime_value)
        for alert in alerts:
            alert_intelligence = None
            match alert.type.lower():
                case "ioc":
                    alert_intelligence = self.api.get_alert_ioc_rule(alert)
                case "sigma":
                    alert_intelligence = self.api.get_alert_sigma_rule(alert)
                case "yara":
                    alert_intelligence = self.api.get_alert_yara_signature(alert)
            if alert_intelligence:
                stix_incident = self.converter_to_stix.create_incident(
                    alert=alert, alert_intelligence=alert_intelligence
                )
                stix_objects.append(stix_incident)

                stix_indicator = self.converter_to_stix.create_indicator(
                    alert=alert, alert_intelligence=alert_intelligence
                )
                stix_objects.append(stix_indicator)

                stix_sighting = self.converter_to_stix.create_sighting(
                    alert=alert, sighted_ref=stix_indicator
                )
                stix_objects.append(stix_sighting)

                stix_observables = self.converter_to_stix.create_observables(
                    alert=alert, alert_intelligence=alert_intelligence
                )
                stix_objects.extend(stix_observables)

                for stix_observable in stix_observables:
                    based_on_observable_types = [
                        "ipv4-addr",
                        "ipv6-addr",
                        "domain-name",
                        "url",
                    ]
                    related_to_observable_types = [
                        "file",
                        "hostname",
                        "directory",
                        "user-account",
                    ]

                    observable_type = stix_observable.stix2_representation.type
                    if observable_type in based_on_observable_types:
                        stix_based_on_relationship = (
                            self.converter_to_stix.create_relationship(
                                relationship_type="based-on",
                                source=stix_observable,
                                target=stix_indicator,
                            )
                        )
                        stix_objects.append(stix_based_on_relationship)
                    if observable_type in related_to_observable_types:
                        stix_based_on_relationship = (
                            self.converter_to_stix.create_relationship(
                                relationship_type="related-to",
                                source=stix_observable,
                                target=stix_incident,
                            )
                        )
                        stix_objects.append(stix_based_on_relationship)
                if isinstance(alert_intelligence, harfanglab.YaraSignature):
                    for technique_tag in alert_intelligence.rule_technique_tags:
                        stix_attack_pattern = (
                            self.converter_to_stix.create_attack_pattern(
                                technique_tag=technique_tag
                            )
                        )
                        stix_objects.append(stix_attack_pattern)

                        stix_uses_relationship = (
                            self.converter_to_stix.create_relationship(
                                relationship_type="uses",
                                source=stix_incident,
                                target=stix_attack_pattern,
                            )
                        )
                        stix_objects.append(stix_uses_relationship)
            self.last_import_datetime_value = alert.created_at

        self.helper.log_info("[INCIDENTS] Incidents creation completed")
        return stix_objects

    def _collect_case_incident_intelligence(self) -> list[opencti.BaseModel]:
        """
        Collect threats from Harfanglab and convert them into STIX objects.
        Threats are filtered by creation date, according to connector's state.
        :return: List of STIX objects
        """
        stix_objects = []

        threats = self.api.generate_threats(since=self.last_import_datetime_value)
        for threat in threats:
            alert_stix_objects = self._collect_incident_intelligence(threat)
            stix_objects.extend(alert_stix_objects)

            stix_case_incident = self.converter_to_stix.create_case_incident(
                threat=threat, object_refs=alert_stix_objects
            )
            stix_objects.append(stix_case_incident)

            threat_note = self.api.get_threat_note(threat.id)
            if threat_note:
                stix_note = self.converter_to_stix.create_note(
                    threat_note=threat_note, object_refs=[stix_case_incident]
                )
                stix_objects.append(stix_note)
            self.last_import_datetime_value = threat.created_at

        self.helper.log_info("[CASE-INCIDENTS] Case-Incidents creation completed")
        return stix_objects

    def create_stix_bundle(self) -> str | None:
        """
        Create a STIX 2.1 bundle containing intelligence from Harfanglab.
        :return: A bundle of STIX 2.1 objects
        """
        if self.should_import_case_incidents:
            stix_objects = self._collect_case_incident_intelligence()
        else:
            stix_objects = self._collect_incident_intelligence()

        if stix_objects:
            # Convert to STIX 2.1 ordered dicts
            stix_objects = [
                stix_object.stix2_representation for stix_object in stix_objects
            ]
            # Ensure consistent bundle
            stix_objects.append(self.converter_to_stix.author.stix2_representation)
            stix_objects.append(self.converter_to_stix.marking_definition)
            # Create and return bundle
            stix_bundle = self.helper.stix2_create_bundle(stix_objects)
            return stix_bundle

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            self.helper.log_info("[CONNECTOR] Starting alerts gatherer")

            work_id = self._initiate_work()

            stix_bundle = self.create_stix_bundle()
            if stix_bundle:
                self.helper.send_stix2_bundle(
                    stix_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                self.helper.log_info("[CONNECTOR] STIX bundle sent successfully")

                self._set_state_last_datetime(self.last_import_datetime_value)

            self._terminate_work(work_id)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(err)

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
