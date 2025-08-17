import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List

import stix2
from pycti import ObservedData as PyCTIObservedData
from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .models import C2, C2ScanResult
from .utils import convert_timestamp_to_iso_format


class ConnectorHuntIo:
    """
    Specifications of the external import connector
    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)

    def _collect_intelligence_and_ingest(self) -> None:
        """
        Collect intelligence from the source, convert into STIX objects and send
          incrementally to OpenCTI.
        """

        def process_entity(entity: C2ScanResult):
            """
            Process a single entity into STIX objects and send it to OpenCTI.
            """
            try:
                relationships = []
                confidence = int(entity.confidence)

                timestamp = convert_timestamp_to_iso_format(entity.timestamp)

                ipv4_object = self.converter_to_stix.create_ipv4_observable(entity.ip)

                malware_object = self.converter_to_stix.create_malware_object(
                    entity.malware_name, entity.malware_subsystem
                )

                url_indicator = self.converter_to_stix.create_url_indicator(
                    entity.scan_uri, timestamp
                )

                domain_object = self.converter_to_stix.create_domain_observable(
                    entity.hostname
                )

                c2_infrastructure = self.converter_to_stix.create_c2_infrastructure(
                    entity.malware_name, "command-and-control", timestamp
                )

                if ipv4_object:
                    network_traffic_object = (
                        self.converter_to_stix.create_network_traffic(
                            entity.port, ipv4_object.id
                        )
                    )

                    if c2_infrastructure.id and malware_object:
                        c2_infrastructure_malware_relationship = (
                            self.converter_to_stix.create_relationship(
                                "controls",
                                timestamp,
                                c2_infrastructure.id,
                                malware_object.id,
                                confidence,
                            )
                        )

                        relationships.append(
                            c2_infrastructure_malware_relationship.stix2_object
                        )

                    if c2_infrastructure.id and ipv4_object:
                        c2_infrastructure_ipv4_relationship = (
                            self.converter_to_stix.create_relationship(
                                "consists-of",
                                timestamp,
                                c2_infrastructure.id,
                                ipv4_object.id,
                                confidence,
                            )
                        )

                        relationships.append(
                            c2_infrastructure_ipv4_relationship.stix2_object
                        )

                    if c2_infrastructure.id and domain_object:
                        c2_infrastructure_domain_relationship = (
                            self.converter_to_stix.create_relationship(
                                "consists-of",
                                timestamp,
                                c2_infrastructure.id,
                                domain_object.id,
                                confidence,
                            )
                        )

                        relationships.append(
                            c2_infrastructure_domain_relationship.stix2_object
                        )

                    if url_indicator.id and malware_object:
                        c2_infrastructure_url_malware_relationship = (
                            self.converter_to_stix.create_relationship(
                                "indicates",
                                timestamp,
                                url_indicator.id,
                                malware_object.id,
                                confidence,
                            )
                        )

                        relationships.append(
                            c2_infrastructure_url_malware_relationship.stix2_object
                        )

                # Create ObservedData with only valid objects
                observed_data_refs = [
                    obj
                    for obj in [
                        ipv4_object.stix2_object,
                        domain_object.stix2_object,
                        network_traffic_object.stix2_object,
                    ]
                    if obj
                ]

                if observed_data_refs:
                    observed_data = stix2.ObservedData(
                        id=PyCTIObservedData.generate_id("observed-data"),
                        first_observed=timestamp,
                        last_observed=timestamp,
                        number_observed=1,
                        object_refs=observed_data_refs,
                    )
                else:
                    observed_data = None

                # Collect all STIX objects and filter None
                stix_objects = [
                    obj
                    for obj in [
                        ipv4_object.stix2_object,
                        domain_object.stix2_object,
                        url_indicator.stix2_object,
                        c2_infrastructure.stix2_object,
                        malware_object.stix2_object,
                        network_traffic_object.stix2_object,
                        observed_data,
                    ]
                    if obj
                ]
                stix_objects.extend(relationships)

                # Create STIX bundle
                if stix_objects:
                    stix_bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)

                    # Send the STIX bundle to OpenCTI incrementally
                    self.helper.send_stix2_bundle(stix_bundle.serialize(), update=True)

            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error processing entity {entity}: {e}"
                )

        # Fetch entities from the external source
        entities: List[C2] = self.client.get_entities() or []

        # Use ThreadPoolExecutor to process entities concurrently
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(process_entity, C2ScanResult(entity)): entity
                for entity in entities
            }
            for future in as_completed(futures):
                future.result()

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
            friendly_name = "Connector Hunt IO feed"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            self._collect_intelligence_and_ingest()

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
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
        This specific scheduler from the pycti connector helper will also check the queue size
          of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue
          threshold,
        the connector's main process will not run until the queue is ingested and reduced
          sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
