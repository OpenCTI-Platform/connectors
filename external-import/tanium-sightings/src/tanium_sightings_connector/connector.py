import sys
import json
import time
from datetime import datetime

from pycti import OpenCTIConnectorHelper
import pytz
import stix2
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from pycti import (
    AttackPattern,
    CustomObservableHostname,
    Identity,
    Incident,
    StixCoreRelationship,
    StixSightingRelationship,
)

from .client_api import ConnectorAPI
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix




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

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.api = ConnectorAPI(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)

        self.identity = stix2.Identity(
            id=Identity.generate_id(name=self.config.connector_name, identity_class="organization"),
            name=self.config.connector_name,
            identity_class="organization",
            description="DESCRIPTION",
        )

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
        entities = self.api.get_entities()

        # Convert into STIX2 object and add it on a list
        for entity in entities:
            entity_to_stix = self.converter_to_stix.create_obs(entity["value"])
            stix_objects.append(entity_to_stix)

        return stix_objects

        # ===========================
        # === Add your code above ===
        # ===========================

    def run(self):
        self.helper.log_info("[SIGHTINGS/INCIDENTS] Starting alerts gatherer")

        while True:
            alerts = self.api.query(
                "get",
                "/plugin/products/threat-response/api/v1/alerts",
                {"sort": "-createdAt"},
            )
            state = self.helper.get_state()
            if state and "lastAlertDate" in state:
                last_alert_date = parse(state["lastAlertDate"])
            else:
                last_alert_date = datetime.now().astimezone(pytz.UTC) - relativedelta(
                    years=1
                )

            alerts = reversed(alerts)
            for alert in alerts:
                alert_date = parse(alert["createdAt"]).astimezone(pytz.UTC)
                if alert_date > last_alert_date and alert["state"] != "suppressed":
                    # Get intel
                    intel = self.api.query(
                        "get",
                        "/plugin/products/threat-response/api/v1/intels/"
                        + str(alert["intelDocId"]),
                        )
                    alert_details = json.loads(alert["details"])
                    # Mark as processed
                    if state is not None:
                        state["lastAlertDate"] = alert_date.isoformat()
                        self.helper.set_state(state)
                    else:
                        self.helper.set_state({"lastAlertDate": alert_date.isoformat()})
                    # Create the bundle
                    objects = []
                    # Check if the intel is in OpenCTI
                    external_reference = self.helper.api.external_reference.read(
                        filters={
                            "mode": "and",
                            "filters": [
                                {"key": "source_name", "values": ["Tanium"]},
                                {
                                    "key": "external_id",
                                    "values": [str(alert["intelDocId"])],
                                },
                            ],
                            "filterGroups": [],
                        }
                    )
                    entity = None
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
                        if entity is not None:
                            stix_sighting = stix2.Sighting(
                                id=StixSightingRelationship.generate_id(
                                    entity["standard_id"],
                                    self.identity["id"],
                                    alert_date,
                                    alert_date,
                                ),
                                sighting_of_ref=entity["standard_id"],
                                where_sighted_refs=[self.identity["id"]],
                                count=1,
                                confidence=self.helper.connect_confidence_level,
                            )
                            objects.append(stix_sighting)
                    if self.config.tanium_import_alerts:
                        incident_name = intel["name"] + " on " + alert["computerName"]
                        stix_incident = stix2.Incident(
                            id=Incident.generate_id(incident_name, alert_date),
                            created=alert_date,
                            name=incident_name,
                            description="Type: "
                                        + alert["type"]
                                        + " | MatchType:"
                                        + alert["matchType"],
                            object_marking_refs=[stix2.TLP_RED],
                            created_by_ref=self.identity["id"],
                            confidence=self.helper.connect_confidence_level,
                            external_references=[
                                {
                                    "source_name": "Tanium Threat Response",
                                    "url": self.config.tanium_url_console
                                           + "/ui/threatresponse/alerts?guid="
                                           + alert["guid"],
                                    "external_id": alert["guid"],
                                }
                            ],
                            allow_custom=True,
                            custom_properties={
                                "source": "Tanium Threat Response",
                                "severity": alert["priority"],
                                "incident_type": "alert",
                            },
                        )
                        objects.append(stix_incident)
                        if entity is not None:
                            if entity["entity_type"] == "Indicator":
                                stix_relation_indicator = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "indicates",
                                        entity["standard_id"],
                                        stix_incident.id,
                                    ),
                                    relationship_type="indicates",
                                    source_ref=entity["standard_id"],
                                    target_ref=stix_incident.id,
                                    object_marking_refs=[stix2.TLP_RED],
                                    created_by_ref=self.identity["id"],
                                )
                                objects.append(stix_relation_indicator)
                            else:
                                stix_relation_observable = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "related-to",
                                        entity["standard_i"],
                                        stix_incident.id,
                                    ),
                                    relationship_type="related-to",
                                    source_ref=entity["standard_id"],
                                    target_ref=stix_incident.id,
                                    object_marking_refs=[stix2.TLP_RED],
                                    created_by_ref=self.identity["id"],
                                )
                                objects.append(stix_relation_observable)

                        stix_hostname = CustomObservableHostname(
                            value=alert["computerName"],
                            object_marking_refs=[stix2.TLP_RED],
                            custom_properties={
                                "created_by_ref": self.identity["id"],
                            },
                        )
                        objects.append(stix_hostname)
                        stix_relation_hostname = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", stix_hostname.id, stix_incident.id
                            ),
                            relationship_type="related-to",
                            source_ref=stix_hostname.id,
                            target_ref=stix_incident.id,
                            object_marking_refs=[stix2.TLP_RED],
                            created_by_ref=self.identity["id"],
                        )
                        objects.append(stix_relation_hostname)
                        stix_ip = stix2.IPv4Address(
                            value=alert["computerIpAddress"],
                            object_marking_refs=[stix2.TLP_RED],
                            custom_properties={
                                "created_by_ref": self.identity["id"],
                            },
                        )
                        objects.append(stix_ip)
                        stix_relation_ip = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", stix_ip.id, stix_incident.id
                            ),
                            relationship_type="related-to",
                            source_ref=stix_ip.id,
                            target_ref=stix_incident.id,
                            object_marking_refs=[stix2.TLP_RED],
                            created_by_ref=self.identity["id"],
                        )
                        objects.append(stix_relation_ip)
                        if (
                                "match" in alert_details
                                and alert_details["match"] is not None
                                and "properties" in alert_details["match"]
                                and "user" in alert_details["match"]["properties"]
                        ):
                            login = alert_details["match"]["properties"]["user"].split(
                                "\\"
                            )[-1]
                            stix_user = stix2.UserAccount(
                                account_login=login,
                                object_marking_refs=[stix2.TLP_RED],
                                custom_properties={
                                    "created_by_ref": self.identity["id"],
                                },
                            )
                            objects.append(stix_user)
                            stix_relation_user = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "related-to", stix_user.id, stix_incident.id
                                ),
                                relationship_type="related-to",
                                source_ref=stix_user.id,
                                target_ref=stix_incident.id,
                                object_marking_refs=[stix2.TLP_RED],
                                created_by_ref=self.identity["id"],
                            )
                            objects.append(stix_relation_user)
                        if (
                                "match" in alert_details
                                and alert_details["match"] is not None
                                and "properties" in alert_details["match"]
                                and "file" in alert_details["match"]["properties"]
                        ):
                            file = alert_details["match"]["properties"]["file"]
                            hashes = {}
                            if "md5" in file:
                                hashes["MD5"] = file["md5"]
                            if "sha1" in file:
                                hashes["SHA-1"] = file["sha1"]
                            if "sha256" in file:
                                hashes["SHA-256"] = file["sha256"]
                            stix_file = stix2.File(
                                hashes=hashes,
                                object_marking_refs=[stix2.TLP_RED],
                                custom_properties={
                                    "created_by_ref": self.identity["id"],
                                },
                            )
                            objects.append(stix_file)
                            stix_relation_file = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "related-to", stix_file.id, stix_incident.id
                                ),
                                relationship_type="related-to",
                                source_ref=stix_file.id,
                                target_ref=stix_incident.id,
                                object_marking_refs=[stix2.TLP_RED],
                                created_by_ref=self.identity["id"],
                            )
                            objects.append(stix_relation_file)
                        if intel["type"] == "processInjection":
                            stix_attack_pattern = stix2.AttackPattern(
                                id=AttackPattern.generate_id("T1055", "T1055"),
                                name="T1055",
                                allow_custom=True,
                                custom_properties={"x_mitre_id": "T1055"},
                            )
                            objects.append(stix_attack_pattern)
                            stix_relation_attack_pattern = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "uses", stix_incident.id, stix_attack_pattern.id
                                ),
                                relationship_type="uses",
                                source_ref=stix_incident.id,
                                target_ref=stix_attack_pattern.id,
                                object_marking_refs=[stix2.TLP_RED],
                                created_by_ref=self.identity["id"],
                            )
                            objects.append(stix_relation_attack_pattern)
                        if (
                                "mitreAttack" in intel
                                and intel["mitreAttack"] is not None
                                and "techniques" in intel["mitreAttack"]
                        ):
                            for technique in intel["mitreAttack"]["techniques"]:
                                stix_attack_pattern = stix2.AttackPattern(
                                    id=AttackPattern.generate_id(
                                        technique["name"], technique["id"]
                                    ),
                                    name=technique["name"],
                                    allow_custom=True,
                                    custom_properties={"x_mitre_id": technique["id"]},
                                )
                                objects.append(stix_attack_pattern)
                                stix_relation_attack_pattern = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "uses", stix_incident.id, stix_attack_pattern.id
                                    ),
                                    relationship_type="uses",
                                    source_ref=stix_incident.id,
                                    target_ref=stix_attack_pattern.id,
                                    object_marking_refs=[stix2.TLP_RED],
                                    created_by_ref=self.identity["id"],
                                )
                                objects.append(stix_relation_attack_pattern)

                    if len(objects) > 0:
                        objects.append(self.identity)

                        stix_bundle = self.helper.stix2_create_bundle(objects)
                        friendly_name = (
                                "Tanium run @ "
                                + datetime.now().astimezone(pytz.UTC).isoformat()
                        )
                        work_id = self.helper.api.work.initiate_work(
                            self.helper.connect_id, friendly_name
                        )
                        self.helper.send_stix2_bundle(stix_bundle, work_id=work_id)
                        message = "Connector successfully run"
                        self.helper.api.work.to_processed(work_id, message)
            time.sleep(60)

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
    #         friendly_name = "Tanium sightings connector"
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

    # def run(self) -> None:
    #     """
    #     Run the main process encapsulated in a scheduler
    #     It allows you to schedule the process to run at a certain intervals
    #     This specific scheduler from the pycti connector helper will also check the queue size of a connector
    #     If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
    #     the connector's main process will not run until the queue is ingested and reduced sufficiently,
    #     allowing it to restart during the next scheduler check. (default is 500MB)
    #     It requires the `duration_period` connector variable in ISO-8601 standard format
    #     Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
    #     :return: None
    #     """
    #     self.helper.schedule_iso(
    #         message_callback=self.process_message,
    #         duration_period=self.config.duration_period,
    #     )
