"""First EPSS external import Connector"""

import sys
from datetime import datetime

from pycti import OpenCTIConnectorHelper
from pytz import UTC

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .utils import is_cve_format


class FirstEPSSConnector:
    """Connector to bulk import EPSS scores and enrich CVEs with them."""

    def __init__(self):
        """Initialize the Connector with necessary configurations."""

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load, playbook_compatible=True)
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)

        self.author = None

    def run(self) -> None:
        """
        Schedules the connector to run periodically.
        This method uses the provided duration period in the config to schedule the main processing function.

        Returns:
            None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector_duration_period,
        )

    def _get_opencti_vulnerability_data(self) -> list:
        self.helper.log_info("Fetching OpenCTI vulnerability data...")

        custom_attributes = """
            name
        """
        opencti_data = self.helper.api.vulnerability.list(
            getAll=True, customAttributes=custom_attributes
        )
        opencti_data = [item["name"] for item in opencti_data]
        return opencti_data

    def _update_vuln_data_with_epss(
        self, vuln_data: list, epss_data: dict
    ) -> list[dict]:
        """Update vulnerability data with EPSS score and convert into STIX object
        :param vuln_data: Vulnerability names from OpenCTI
        :param epss_data: EPSS data from First EPSS
        :return: list of STIX objects
        """

        self.helper.connector_logger.info("[CONNECTOR] Updating vulnerability data...")

        self.author = self.converter_to_stix.create_author()

        stix_objects = []

        for vuln_name in vuln_data:
            epss_info = epss_data.get(vuln_name)
            if epss_info and is_cve_format(vuln_name):
                vulnerability_stix_object = self.converter_to_stix.create_vulnerability(
                    {
                        "name": vuln_name,
                        "x_opencti_epss_score": float(epss_info["epss"]),
                        "x_opencti_epss_percentile": float(epss_info["percentile"]),
                    },
                )
                stix_objects.append(vulnerability_stix_object)

        if stix_objects:
            stix_objects.append(self.author)

        return stix_objects

    def _process_submission(self, stix_objects: list) -> list:
        """Submit STIX bundle
        :param stix_objects: list of STIX objects
        :return: list of sent bundles
        """
        self.helper.connector_logger.info("[CONNECTOR] Submitting bundles...")
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        return bundles_sent

    def process_message(self) -> None:
        """Get the current state and check if connector is already running"""
        try:
            now_utc = datetime.now(UTC)
            connector_start_timestamp = int(now_utc.timestamp())
            connector_start_isoformat = now_utc.isoformat()

            self.helper.connector_logger.info(
                "[CONNECTOR] Starting the connector...",
                {
                    "connector_name": self.helper.connect_name,
                    "connector_start": connector_start_isoformat,
                },
            )

            # Get the current state
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                last_run_isoformat = datetime.fromtimestamp(last_run).isoformat(
                    sep=" ", timespec="seconds"
                )
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run...",
                    {
                        "last_run_timestamp": last_run,
                        "last_run_isoformat": last_run_isoformat,
                    },
                )
            else:
                last_run = "Never run"
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            friendly_name = (
                f"{self.config.connector_name} run @ {connector_start_isoformat}"
            )
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            epss_data = self.client.request_data(self.config.api_base_url)
            vuln_data = self._get_opencti_vulnerability_data()
            updated_stix_objects = self._update_vuln_data_with_epss(
                vuln_data, epss_data
            )
            self._process_submission(updated_stix_objects)

            # Store the current timestamp as a last run of the connector
            connector_stop = datetime.now(UTC).isoformat()
            self.helper.connector_logger.info(
                "[CONNECTOR] Getting current state and update it with last run of the connector.",
                {"current_state": current_state},
            )

            if current_state:
                current_state["last_run"] = connector_start_timestamp
            else:
                current_state = {"last_run": connector_start_timestamp}
            self.helper.set_state(current_state)

            message = f"Connector successfully run, storing last_run as {connector_start_isoformat}"
            self.helper.api.work.to_processed(work_id, message)

            self.helper.connector_logger.info(
                "[CONNECTOR] The connector has been successfully run, saving the last_run.",
                {
                    "old_last_run_timestamp": last_run,
                    "new_last_run_timestamp": connector_start_timestamp,
                    "connector_startup": connector_start_isoformat,
                    "connector_stop": connector_stop,
                },
            )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))
