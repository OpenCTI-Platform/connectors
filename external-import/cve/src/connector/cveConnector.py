import sys
import time
from datetime import datetime, timedelta

from pycti import OpenCTIConnectorHelper  # type: ignore
from services import CVEConverter  # type: ignore
from services.utils import MAX_AUTHORIZED, ConfigCVE  # type: ignore


class CVEConnector:
    def __init__(self):
        """
        Initialize the CVEConnector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigCVE()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.converter = CVEConverter(self.helper)

    def run(self) -> None:
        """
        Main execution loop procedure for CVE connector
        """
        self.helper.connector_logger.info("[CONNECTOR] Fetching datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)

    def _initiate_work(self, timestamp: int) -> str:
        """
        Initialize a work
        :param timestamp: Timestamp in integer
        :return: Work id in string
        """
        now = datetime.utcfromtimestamp(timestamp)
        friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        info_msg = f"[CONNECTOR] New work '{work_id}' initiated..."
        self.helper.connector_logger.info(info_msg)

        return work_id

    def update_connector_state(self, current_time: int, work_id: str) -> None:
        """
        Update the connector state
        :param current_time: Time in int
        :param work_id: Work id in string
        """
        msg = (
            f"[CONNECTOR] Connector successfully run, storing last_run as "
            f"{datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.helper.connector_logger.info(msg)
        self.helper.api.work.to_processed(work_id, msg)
        self.helper.set_state({"last_run": current_time})

        interval_in_hours = round(self.config.interval / 60 / 60, 2)
        self.helper.connector_logger.info(
            "[CONNECTOR] Last_run stored, next run in: "
            + str(interval_in_hours)
            + " hours"
        )

    def _import_recent(self, now: datetime, work_id: str) -> None:
        """
        Import the most recent CVEs depending on date range chosen
        :param now: Current date in datetime
        :param work_id: Work id in string
        """
        if self.config.max_date_range > MAX_AUTHORIZED:
            error_msg = "The max_date_range cannot exceed {} days".format(
                MAX_AUTHORIZED
            )
            raise Exception(error_msg)

        date_range = timedelta(days=self.config.max_date_range)
        start_date = now - date_range

        cve_params = self._update_cve_params(start_date, now)

        self.converter.send_bundle(cve_params, work_id)

    def _import_history(
        self, start_date: datetime, end_date: datetime, work_id: str
    ) -> None:
        """
        Import CVEs history if pull_history config is True
        :param start_date: Start date in datetime
        :param end_date: End date in datetime
        :param work_id: Work id in string
        """
        years = range(start_date.year, end_date.year + 1)
        start, end = start_date, end_date + timedelta(1)

        for year in years:
            year_start = datetime(year, 1, 1, 0, 0)
            year_end = datetime(year + 1, 1, 1, 0, 0)

            date_range = min(end, year_end) - max(start, year_start)
            days_in_year = date_range.days

            # If the year is the current year, get all days from start year to now
            if year == end_date.year:
                date_range = end_date - year_start
                days_in_year = date_range.days

            start_date_current_year = year_start

            while days_in_year > 0:
                end_date_current_year = start_date_current_year + timedelta(
                    days=MAX_AUTHORIZED
                )
                info_msg = (
                    f"[CONNECTOR] Connector retrieve CVE history for year {year}, "
                    f"{days_in_year} days left"
                )
                self.helper.connector_logger.info(info_msg)

                """
                If retrieve history for this year and days_in_year left are less than 120 days
                Retrieve CVEs from the rest of days
                """
                if year == end_date.year and days_in_year < MAX_AUTHORIZED:
                    end_date_current_year = start_date_current_year + timedelta(
                        days=days_in_year
                    )
                    # Update date range
                    cve_params = self._update_cve_params(
                        start_date_current_year, end_date_current_year
                    )

                    self.converter.send_bundle(cve_params, work_id)
                    days_in_year = 0

                """
                Retrieving for each year MAX_AUTHORIZED = 120 days
                1 year % 120 days => 5 or 6 (depends if it is a leap year or not)
                """
                if days_in_year > 6:
                    # Update date range
                    cve_params = self._update_cve_params(
                        start_date_current_year, end_date_current_year
                    )

                    self.converter.send_bundle(cve_params, work_id)
                    start_date_current_year += timedelta(days=MAX_AUTHORIZED)
                    days_in_year -= MAX_AUTHORIZED
                else:
                    end_date_current_year = start_date_current_year + timedelta(
                        days=days_in_year
                    )
                    # Update date range
                    cve_params = self._update_cve_params(
                        start_date_current_year, end_date_current_year
                    )
                    self.converter.send_bundle(cve_params, work_id)
                    days_in_year = 0

            info_msg = f"[CONNECTOR] Importing CVE history for year {year} finished"
            self.helper.connector_logger.info(info_msg)

    def _maintain_data(self, now: datetime, last_run: float, work_id: str) -> None:
        """
        Maintain data updated if maintain_data config is True
        :param now: Current date in datetime
        :param last_run: Last run date in float
        :param work_id: Work id in str
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Getting the last CVEs since the last run..."
        )

        last_run_ts = datetime.utcfromtimestamp(last_run)

        # Update date range
        cve_params = self._update_cve_params(last_run_ts, now)
        self.converter.send_bundle(cve_params, work_id)

    @staticmethod
    def _update_cve_params(start_date: datetime, end_date: datetime) -> dict:
        """
        Update CVE params to handle date range
        :param start_date: Start date in datetime
        :param end_date: End date in datetime
        :return: Dict of CVE params
        """
        return {
            "lastModStartDate": start_date.isoformat(),
            "lastModEndDate": end_date.isoformat(),
        }

    def process_data(self) -> None:
        try:
            """
            Get the current state and check if connector already runs
            """
            now = datetime.now()
            current_time = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                msg = "[CONNECTOR] Connector last run: " + datetime.utcfromtimestamp(
                    last_run
                ).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.connector_logger.info(msg)
            else:
                last_run = None
                msg = "[CONNECTOR] Connector has never run..."
                self.helper.connector_logger.info(msg)

            """
            ======================================================
            Main process if connector successfully works
            ======================================================
            """

            """
            ================================================================
            If the connector never runs, import the most recent CVEs
            from the last max_date_range (can be configured) to now
            ================================================================
            """
            if last_run is None:
                # Initiate work_id to track the job
                work_id = self._initiate_work(current_time)
                """
                =================================================================
                If the connector never runs and user wants to pull CVE history
                =================================================================
                """
                if self.config.pull_history:
                    start_date = datetime(self.config.history_start_year, 1, 1)
                    end_date = now
                    self._import_history(start_date, end_date, work_id)
                else:
                    self._import_recent(now, work_id)

                self.update_connector_state(current_time, work_id)

                """
                ===================================================================
                Import CVEs from the last run to now if maintain data is True
                If the connector runs, and last run is more than current interval
                ===================================================================
                """
            elif (
                last_run is not None
                and self.config.maintain_data
                and (current_time - last_run) >= int(self.config.interval)
            ):
                # Initiate work_id to track the job
                work_id = self._initiate_work(current_time)
                self._maintain_data(now, last_run, work_id)
                self.update_connector_state(current_time, work_id)

            else:
                new_interval = self.config.interval - (current_time - last_run)
                new_interval_in_hours = round(new_interval / 60 / 60, 2)
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector will not run, next run in: "
                    + str(new_interval_in_hours)
                    + " hours"
                )

            time.sleep(5)

        except (KeyboardInterrupt, SystemExit):
            msg = "[CONNECTOR] Connector stop..."
            self.helper.connector_logger.info(msg)
            sys.exit(0)
        except Exception as e:
            error_msg = f"[CONNECTOR] Error while processing data: {str(e)}"
            self.helper.connector_logger.error(error_msg, meta={"error": str(e)})
