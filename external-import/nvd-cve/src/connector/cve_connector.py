import sys
import time
from datetime import datetime

from pycti import OpenCTIConnectorHelper  # type: ignore
from services import CVEConverter  # type: ignore
from services.utils._version import __version__ as APP_VERSION  # type: ignore
from services.utils.config_variables import ConfigCVE  # type: ignore


class CVEConnector:
    def __init__(self):
        """
        Initialize the CVEConnector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigCVE()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.converter = CVEConverter()

    def run(self) -> None:
        """
        Main execution loop procedure for CVE connector
        """
        self.helper.log_info("[CONNECTOR] Fetching datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                try:
                    self.process_data()
                    time.sleep(60)
                except Exception as e:
                    error_msg = f"[CONNECTOR] Error while processing data: {str(e)}"
                    self.helper.log_error(error_msg)

    def _initiate_work(self, timestamp: int) -> str:
        """
        Initialize a work
        :param timestamp:
        :return:
        """
        now = datetime.utcfromtimestamp(timestamp)
        friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        info_msg = f"[CONNECTOR] New work '{work_id}' initiated..."
        self.helper.log_info(info_msg)

        return work_id

    def process_data(self):
        try:
            """
            Get the current timestamp and check
            """
            current_time = int(time.time())
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                msg = "[CONNECTOR] Connector last run: " + datetime.utcfromtimestamp(
                    last_run
                ).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.log_info(msg)
            else:
                last_run = None
                msg = "[CONNECTOR] Connector has never run..."
                self.helper.log_info(msg)

            """
            If the last run is more than current interval
            """
            if last_run is None or (
                (current_time - last_run) >= int(self.config.interval)
            ):
                """
                Initiate work_id to track the job
                """
                work_id = self._initiate_work(current_time)

                """
                ======================================================
                Main process if connector successfully works
                ======================================================
                """
                """
                
                """
                cve_params = {
                    "startIndex": 0,
                    "resultsPerPage": 2000,
                    "lastModStartDate": "2023-10-28T00:00:00",
                    "lastModEndDate": "2023-12-31T23:59:59",
                }

                # TODO can only get data max range 120 days, send an error if wanted history
                self.converter.convert_and_send(cve_params, work_id)

                msg = (
                    f"[CONNECTOR] Connector successfully run, storing last_run as "
                    f"{datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')}"
                )
                self.helper.log_info(msg)
                self.helper.api.work.to_processed(work_id, msg)
                self.helper.set_state({"last_run": current_time})

                interval_in_hours = round(self.config.interval / 60 / 60, 2)
                self.helper.log_info(
                    "[CONNECTOR] Last_run stored, next run in: "
                    + str(interval_in_hours)
                    + " hours"
                )
            else:
                new_interval = self.config.interval - (current_time - last_run)
                new_interval_in_hours = round(new_interval / 60 / 60, 2)
                self.helper.log_info(
                    "[CONNECTOR] Connector will not run, next run in: "
                    + str(new_interval_in_hours)
                    + " hours"
                )
            time.sleep(5)

        except (KeyboardInterrupt, SystemExit):
            msg = "[CONNECTOR] Connector stop..."
            self.helper.log_info(msg)
            sys.exit(0)
        except Exception as e:
            error_msg = f"[CONNECTOR] {str(e)}"
            self.helper.log_error(error_msg)
