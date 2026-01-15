import sys
from datetime import datetime, timezone

import requests
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connectors_sdk.models import Indicator, IPV4Address, Malware, Relationship
from connectors_sdk.models.enums import RelationshipType
from montysecurity_c2_tracker_client import MontysecurityC2TrackerClient
from pycti import OpenCTIConnectorHelper


class MontysecurityC2TrackerConnector:
    """
    Specifications of the external import connector:

    This class encapsulates the main actions, expected to be run by any connector of type `EXTERNAL_IMPORT`.
    This type of connector aim to fetch external data to create STIX bundle and send it to OpenCTI.
    The STIX bundle in the queue will be processed by OpenCTI workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes:
        config (ConnectorSettings):
            Store the connector's configuration. It defines how to connector will behave.
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
            _All connectors MUST use the connector helper with connector's configuration._
        client (MontysecurityC2TrackerClient):
            Provide methods to request the external API.
        converter_to_stix (ConnectorConverter):
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices:
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to schedule connector's runs frequency
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to OpenCTI
        - `self.helper.set_state()` is used to store persistent data in connector's state

    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `MontysecurityC2TrackerConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.client = MontysecurityC2TrackerClient(
            self.helper,
            # Pass any arguments necessary to the client
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.montysecurity_c2_tracker.tlp_level,
            # Pass any arguments necessary to the converter
        )

    def _collect_intelligence(self) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """

        # ===========================
        # === Add your code below ===
        # ===========================

        # Get entities from external sources
        malware_list = self.client.get_malwares()
        entities = []
        self.helper.connector_logger.info("Get Malware IPs")

        malwareIPsBaseUrl = (
            "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/"
        )
        malware_list = [str(malware).strip('"') for malware in malware_list]
        self.helper.connector_logger.debug(malware_list)
        for malware in malware_list:
            malware_name = str(malware).split(" IPs.txt")[0]
            self.helper.connector_logger.info("Looking at: ", malware_name)
            url = str(malwareIPsBaseUrl + str(malware).replace(" ", "%20"))
            self.helper.connector_logger.debug("URL: ", url)
            malware_stix = None
            malware_stix = Malware(
                name=malware_name,
                is_family=True,
                author=self.converter_to_stix.author,
                markings=[self.converter_to_stix.tlp_marking],
            )
            entities.append(malware_stix)
            self.helper.connector_logger.debug(malware_stix.name)

            ips = self.client.get_ips(malware)

            # request = requests.get(url)
            # ips = str(request.text).split("\n")
            for ip in ips:
                indicatorIPV4 = Indicator(
                    name=ip,
                    pattern="[ipv4-addr:value = '" + ip + "']",
                    pattern_type="stix",
                    main_observable_type="IPv4-Addr",
                    create_observables=True,
                    author=self.converter_to_stix.author,
                    markings=[self.converter_to_stix.tlp_marking],
                )
                entities.append(indicatorIPV4)

                relationship = self.converter_to_stix.create_relationship(
                    source_obj=indicatorIPV4,
                    target_obj=malware_stix,
                    relationship_type=RelationshipType.INDICATES,
                )
                entities.append(relationship)

        # Convert into STIX2 object and add it on a list
        # for entity in entities:
        # entity_to_stix = self.converter_to_stix.create_obs(entity["value"])
        # stix_objects.append(entity)

        # ===========================
        # === Add your code above ===
        # ===========================

        # Ensure consistent bundle by adding the author and TLP marking
        if len(entities):
            entities.append(self.converter_to_stix.author)
            entities.append(self.converter_to_stix.tlp_marking)

        return entities

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
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
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
            friendly_name = "Connector montysecurity_c2_tracker feed"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            # ===========================
            # === Add your code below ===
            # ===========================
            stix_objects = self._collect_intelligence()

            if len(stix_objects):
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=False,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": {str(len(bundles_sent))}},
                )
            # ===========================
            # === Add your code above ===
            # ===========================

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.fromtimestamp(
                current_timestamp, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
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
        Start the connector, schedule its runs and trigger the first run.
        It allows you to schedule the process to run at a certain interval.
        This specific scheduler from the `OpenCTIConnectorHelper` will also check the queue size of a connector.
        If `CONNECTOR_QUEUE_THRESHOLD` is set, and if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)

        Example:
            - If `CONNECTOR_DURATION_PERIOD=PT5M`, then the connector is running every 5 minutes.
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
