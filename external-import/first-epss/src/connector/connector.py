"""First EPSS external import Connector"""

import sys
import time
from datetime import datetime

from pycti import OpenCTIConnectorHelper
from pytz import UTC

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .utils import is_cve_format, time_from_unixtime


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
        """Main execution loop procedure for First EPSS connector
        :return: None
        """
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
            return

        while True:
            try:
                self.process_data()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                self.helper.metric.state("stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
            finally:
                self.helper.metric.state("idle")
                time.sleep(60)

    def _initiate_work(self, timestamp: int) -> str:
        """Initialize work
        :param timestamp: Timestamp as integer
        :return: Work ID as string
        """
        now = datetime.fromtimestamp(timestamp, tz=UTC)
        friendly_name = (
            f"{self.helper.connect_name} run @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        info_msg = f"[CONNECTOR] New work {work_id} initiated..."
        self.helper.log_info(info_msg)

        return work_id

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

    def process_data(self) -> None:
        """Get the current state and check if connector is already running"""
        unixtime_now = int(datetime.now().timestamp())
        time_now = time_from_unixtime(unixtime_now)
        current_state = self.helper.get_state()
        last_run = current_state.get("last_run", 0) if current_state else 0

        if last_run and self.config.interval_seconds > unixtime_now - last_run:
            self.helper.log_debug("Connector will not run this time.")
            return
        self.helper.log_debug(f"Connector last run: {time_from_unixtime(last_run)}")
        self.helper.log_info(f"Connector will run now {time_now}")
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")

        friendly_name = f"{self.config.connector_name} run @ {time_now}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        epss_data = self.client.request_data(self.config.api_base_url)
        vuln_data = self._get_opencti_vulnerability_data()
        updated_stix_objects = self._update_vuln_data_with_epss(vuln_data, epss_data)
        self._process_submission(updated_stix_objects)

        message = f"Connector successfully run, storing last_run as {time_now}"
        self.helper.log_info(message)
        self.helper.set_state({"last_run": unixtime_now})
        self.helper.api.work.to_processed(work_id, message)

        interval_in_hours = round(self.config.interval_hours, 2)
        self.helper.log_info(
            f"[CONNECTOR] last_run stored, next run in: {interval_in_hours} hours"
        )
