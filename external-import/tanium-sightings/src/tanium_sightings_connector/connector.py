import sys
from datetime import datetime

import pytz
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorAPI
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .utils import (
    format_alert,
    has_file_details,
    has_mitre_attack_details,
    has_user_details,
    validate_alert,
)

MITRE_PROCESS_INJECTION_ID = 1055


class TaniumSightingsConnector:
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
        self.api = ConnectorAPI(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

        self.author = ConverterToStix.create_author_identity(
            name=self.helper.connect_name,
            identity_class="organization",
            description="Import Sightings according to alerts found in Tanium API",
        )

    def _get_last_alert_date(self) -> datetime:
        """
        Get last alert date from connector's state (or its config).
        :return: Connector's state last alert date
        """
        state = self.helper.get_state()
        if state and "last_alert_date" in state:
            last_alert_date = parse(state["last_alert_date"])
        elif self.config.tanium_import_start_date:
            last_alert_date = self.config.tanium_import_start_date
        else:
            last_alert_date = datetime.now().astimezone(pytz.UTC) - relativedelta(
                years=1
            )
        return last_alert_date

    def _set_last_alert_date(self, alert) -> None:
        """
        Set last alert date of connector's state
        :param alert: Last alert to set connector's state from
        """
        alert_date = alert["createdAt"].isoformat()

        state = self.helper.get_state()
        if state is not None:
            state["last_alert_date"] = alert_date
            self.helper.set_state(state)
        else:
            self.helper.set_state({"last_alert_date": alert_date})

    def _get_sighted_entity(self, alert) -> dict:
        entity = None

        external_reference = self.helper.api.external_reference.read(
            filters={
                "mode": "and",
                "filters": [
                    {
                        "key": "source_name",
                        "values": ["Tanium", self.helper.connect_name],
                    },
                    {
                        "key": "external_id",
                        "values": [alert["intelDocId"]],
                    },
                ],
                "filterGroups": [],
            }
        )
        if external_reference is not None:
            entity = self.helper.api.stix_domain_object.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {
                            "key": "externalReferences",
                            "values": [external_reference["id"]],
                        }
                    ],
                    "filterGroups": [],
                }
            )
            if entity is None:
                entity = self.helper.api.stix_cyber_observable.read(
                    filters={
                        "mode": "and",
                        "filters": [
                            {
                                "key": "externalReferences",
                                "values": [external_reference["id"]],
                            }
                        ],
                        "filterGroups": [],
                    }
                )
        return entity

    def _collect_intelligence(self, alert) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :param alert: Alert to collect intelligence for
        :return: List of STIX objects
        """
        stix_objects = []

        # Check if the intel is in OpenCTI
        entity = self._get_sighted_entity(alert)
        if entity is not None:
            stix_sighting = self.converter_to_stix.create_sighting(
                source_id=entity["id"],
                target_id=self.author["id"],
                first_seen=alert["createdAt"],
                last_seen=alert["createdAt"],
            )
            stix_objects.append(stix_sighting)

        if self.config.tanium_import_alerts:
            intel = self.api.get_intel(alert["intelDocId"])
            alert["name"] = intel["name"] + " on " + alert["computerName"]

            stix_incident = self.converter_to_stix.create_alert_incident(alert)
            stix_objects.append(stix_incident)

            if entity is not None:
                relationship_type = (
                    "indicates" if entity["type"] == "indicator" else "related-to"
                )
                stix_entity_relationship = self.converter_to_stix.create_relationship(
                    source_id=entity["id"],
                    target_id=stix_incident["id"],
                    relationship_type=relationship_type,
                )
                stix_objects.append(stix_entity_relationship)

            stix_custom_observable_hostname = (
                self.converter_to_stix.create_custom_observable_hostname(alert)
            )
            stix_objects.append(stix_custom_observable_hostname)
            stix_hostname_relationship = self.converter_to_stix.create_relationship(
                source_id=stix_custom_observable_hostname["id"],
                target_id=stix_incident["id"],
                relationship_type="related-to",
            )
            stix_objects.append(stix_hostname_relationship)

            stix_ip = self.converter_to_stix.create_alert_ipv4(alert)
            stix_objects.append(stix_ip)
            stix_ip_relationship = self.converter_to_stix.create_relationship(
                source_id=stix_ip["id"],
                target_id=stix_incident["id"],
                relationship_type="related-to",
            )
            stix_objects.append(stix_ip_relationship)

            if has_user_details(alert):
                stix_user_account = self.converter_to_stix.create_alert_user_account(
                    alert
                )
                stix_objects.append(stix_user_account)
                stix_user_account_relationship = (
                    self.converter_to_stix.create_relationship(
                        source_id=stix_user_account["id"],
                        target_id=stix_incident["id"],
                        relationship_type="related-to",
                    )
                )
                stix_objects.append(stix_user_account_relationship)
            if has_file_details(alert):
                stix_file = self.converter_to_stix.create_alert_file(alert)
                stix_objects.append(stix_file)
                stix_file_relationship = self.converter_to_stix.create_relationship(
                    source_id=stix_file["id"],
                    target_id=stix_incident["id"],
                    relationship_type="related-to",
                )
                stix_objects.append(stix_file_relationship)
            if intel["type"] == "processInjection":
                stix_attack_pattern = (
                    self.converter_to_stix.create_mitre_attack_pattern(
                        name=MITRE_PROCESS_INJECTION_ID, id=MITRE_PROCESS_INJECTION_ID
                    )
                )
                stix_objects.append(stix_attack_pattern)
                stix_attack_pattern_relationship = (
                    self.converter_to_stix.create_relationship(
                        source_id=stix_incident["id"],
                        target_id=stix_attack_pattern["id"],
                        relationship_type="uses",
                    )
                )
                stix_objects.append(stix_attack_pattern_relationship)
            if has_mitre_attack_details(intel):
                for technique in intel["mitreAttack"]["techniques"]:
                    stix_attack_pattern = (
                        self.converter_to_stix.create_mitre_attack_pattern(
                            name=technique["name"], id=technique["id"]
                        )
                    )
                    stix_objects.append(stix_attack_pattern)
                    stix_attack_pattern_relationship = (
                        self.converter_to_stix.create_relationship(
                            source_id=stix_incident["id"],
                            target_id=stix_attack_pattern["id"],
                            relationship_type="uses",
                        )
                    )
                    stix_objects.append(stix_attack_pattern_relationship)
        return stix_objects

    def _process_message(self):
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            alerts = self.api.get_alerts()
            for alert in reversed(alerts):
                alert = format_alert(alert)
                last_alert_date = self._get_last_alert_date()
                if validate_alert(alert, last_alert_date):
                    stix_objects = self._collect_intelligence(alert)
                    if stix_objects:
                        stix_objects.append(self.author)
                        stix_bundle = self.helper.stix2_create_bundle(stix_objects)

                        friendly_name = (
                            self.helper.connect_name
                            + "run @ "
                            + datetime.now().astimezone(pytz.UTC).isoformat()
                        )
                        work_id = self.helper.api.work.initiate_work(
                            self.helper.connect_id, friendly_name
                        )

                        bundles_sent = self.helper.send_stix2_bundle(
                            stix_bundle, work_id=work_id
                        )
                        self.helper.connector_logger.info(
                            "Sending STIX objects to OpenCTI...",
                            {"bundles_sent": str(len(bundles_sent))},
                        )

                        self._set_last_alert_date(alert)
                        message = (
                            f"{self.helper.connect_name} connector successfully run, storing last_alert_date as "
                            + str(last_alert_date)
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
            message_callback=self._process_message,
            duration_period=self.helper.connect_duration_period,
        )
