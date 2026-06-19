import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from workshop_connector_client import WorkshopConnectorClient


class WorkshopConnectorConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `WorkshopConnectorConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.client = WorkshopConnectorClient(
            self.helper,
            sample_file_path=self.config.workshop_connector.sample_file_path,
            # Pass any arguments necessary to the client
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.workshop_connector.tlp_level,
            # Pass any arguments necessary to the converter
        )

    def _transform_intelligence(self, entities):
        stix_entities = []
        stix_relationships = []
        for entity in entities:
            if entity["type"] == "ip_address":
                stix_entities.append(self.converter_to_stix.create_obs(entity["id"]))

            if entity["type"] == "domain":
                stix_entities.append(self.converter_to_stix.create_obs(entity["id"]))

            if entity["type"] == "vulnerability":
                # Transform vulnerability
                vulnerability = {
                    "name": entity["attributes"]["name"],
                    "tags": entity["attributes"]["tags"],
                    "description": entity["attributes"]["description"],
                    "epss_score": entity["attributes"]["epss"]["score"],
                    "epss_percentile": entity["attributes"]["epss"]["percentile"],
                    "cvss_v3_vector_string": entity["attributes"]["cvss"]["cvssv3_x"][
                        "vector"
                    ],
                    "cvss_v3_base_score": entity["attributes"]["cvss"]["cvssv3_x"][
                        "base_score"
                    ],
                    "cvss_v4_vector_string": entity["attributes"]["cvss"]["cvssv4_0"][
                        "vector"
                    ],
                    "cvss_v4_base_score": entity["attributes"]["cvss"]["cvssv4_0"][
                        "base_score"
                    ],
                }
                stix_vulnerability = self.converter_to_stix.create_vulnerability(
                    vulnerability
                )
                stix_entities.append(stix_vulnerability)

                # Create and transform related CPEs
                affected_software = entity["attributes"]["cpes"]

                for software in affected_software:
                    software_details = {
                        "name": software["product"],
                        "cpe": software["uri"],
                        "vendor": software["vendor"],
                        "version": software["version"],
                    }
                    stix_software = self.converter_to_stix.create_software(
                        software_details
                    )

                    # Create relationship STIX object
                    software_has_vulnerability = (
                        self.converter_to_stix.create_relationship(
                            source=stix_software,
                            relationship_type="has",
                            target=stix_vulnerability,
                        )
                    )

                    stix_entities.append(stix_software)
                    stix_relationships.append(software_has_vulnerability)

        return stix_entities + stix_relationships

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
        domain_entities = self.client.get_domain_entities()
        ip_entities = self.client.get_ip_entities()
        vulnerability_entities = self.client.get_vulnerability_entities()

        # Convert into STIX2 object and add it on a list
        stix_domain_entities = self._transform_intelligence(domain_entities["response"])
        stix_ip_entities = self._transform_intelligence(ip_entities["response"])
        stix_vulnerability_entities = self._transform_intelligence(
            vulnerability_entities["response"]
        )

        # Complete STIX objects list
        stix_objects.extend(
            stix_domain_entities + stix_ip_entities + stix_vulnerability_entities
        )

        # ===========================
        # === Add your code above ===
        # ===========================

        # Ensure consistent bundle by adding the author and TLP marking
        if len(stix_objects):
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
            friendly_name = "Connector workshop_connector feed"

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
                    cleanup_inconsistent_bundle=True,
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
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
