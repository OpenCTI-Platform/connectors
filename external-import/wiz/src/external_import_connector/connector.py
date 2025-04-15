import datetime
import sys
import warnings

from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix


class ConnectorWiz:

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

    def _collect_intelligence(self) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """

        # Get entities from external sources
        entities = self.client.get_entities()["objects"]
        state = self.helper.get_state()

        stix_objects = []
        for entity in entities:

            # Filter entities
            if "modified" in entity and state is not None:
                entity_modified = datetime.datetime.fromisoformat(entity["modified"])
                last_run = datetime.datetime.fromisoformat(state["last_run"])
                if last_run.tzinfo is None:
                    warning_message = (
                        "ISOFORMAT without timezone is deprecated and will be replaced "
                        "by ISOFORMAT with timezone."
                    )
                    warnings.warn(
                        warning_message,
                        DeprecationWarning,
                        stacklevel=2,
                    )
                    self.helper.connector_logger.warning(
                        warning_message, {"last_run": last_run}
                    )
                    last_run = last_run.replace(tzinfo=datetime.UTC)
                if entity_modified < last_run:
                    continue

            if entity["type"] == "malware":
                if (
                    "malware_types" in entity
                    and len(entity["malware_types"]) == 1
                    and entity["malware_types"][0] == ""
                ):
                    del entity["malware_types"]

            if (
                entity["type"] == "threat-actor"
                and self.config.threat_actor_to_intrusion_set
            ):
                entity["type"] = "intrusion-set"
                entity["id"] = entity["id"].replace("threat-actor", "intrusion-set")

            if (
                entity["type"] == "relationship"
                and self.config.threat_actor_to_intrusion_set
            ):
                entity["source_ref"] = entity["source_ref"].replace(
                    "threat-actor", "intrusion-set"
                )
                entity["target_ref"] = entity["target_ref"].replace(
                    "threat-actor", "intrusion-set"
                )

            if not entity.get("created_by_ref"):
                entity["created_by_ref"] = self.converter_to_stix.author["id"]

            if "object_marking_refs" not in entity:
                entity["object_marking_refs"] = [
                    self.converter_to_stix.tlp_marking["id"]
                ]

            if "external_references" not in entity:
                entity["external_references"] = [
                    dict(self.converter_to_stix.external_reference)
                ]

            stix_objects.append(entity)

        # Ensure consistent bundle by adding the author
        if stix_objects:
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)
        return stix_objects

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
            # Get the current state
            now = datetime.datetime.now(tz=datetime.UTC)
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = "WIZ Threat Landscape"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            stix_objects = self._collect_intelligence()

            if stix_objects is not None and len(stix_objects) is not None:
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": {str(len(bundles_sent))}},
                )

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": now.timestamp()},
            )
            current_state = self.helper.get_state()
            if current_state:
                current_state["last_run"] = now.isoformat(sep=" ", timespec="seconds")
            else:
                current_state = {"last_run": now.isoformat(sep=" ", timespec="seconds")}
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(now)
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
