import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from cyfirma_client import CyfirmaClient
# pyrefly: ignore [missing-import]
from pycti import OpenCTIConnectorHelper


class CyfirmaConnector:
    """
    Specifications of the CYFIRMA external import connector:

    This class encapsulates the main actions expected to be run by the CYFIRMA connector.
    Fetches CYFIRMA intelligence data, creates STIX 2.1 bundles, and sends them to OpenCTI.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `CyfirmaConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.client = CyfirmaClient(
            self.helper,
            base_url=self.config.cyfirma.api_base_url,
            api_key=self.config.cyfirma.api_key,
            tailored_iocs=self.config.cyfirma.tailored_iocs,
            tailored_vulnerabilities=self.config.cyfirma.tailored_vulnerabilities,
            look_back_days=self.config.cyfirma.look_back_days,
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.cyfirma.tlp_level,
        )

    def _collect_intelligence(self) -> list:
        """
        Collect intelligence from CYFIRMA API and convert into STIX objects
        :return: List of STIX objects
        """
        stix_objects = []



        # Get entities from external CYFIRMA source
        entities = self.client.get_entities()

        if isinstance(entities, dict):
            stix_objects = entities.get("objects", [])
        elif isinstance(entities, list):
            stix_objects = entities

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
            friendly_name = "CYFIRMA feed"

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

            if len(stix_objects):
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": str(len(bundles_sent))},
                )

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
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
