import asyncio
import sys
import time
from datetime import datetime, timedelta, timezone

from pycti import OpenCTIConnectorHelper
from src import ConfigLoader
from src.services import CVEConverter
from src.services.utils import (
    MAX_AUTHORIZED,
    convert_hours_to_seconds,
)


class CVEConnector:
    def __init__(self):
        """
        Initialize the CVEConnector with necessary configurations
        """
        # Load configuration file and connection helper
        # Instantiate the connector helper from config
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(config=self.config.model_dump_pycti())

        self.interval = convert_hours_to_seconds(self.config.cve.interval)
        self.converter = CVEConverter(self.helper, self.config)

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

    def update_connector_state(self, current_time: int) -> None:
        """
        Update the connector state
        :param current_time: Time in int
        """
        last_run_dt = datetime.fromtimestamp(current_time, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        msg = (
            f"[CONNECTOR] Connector successfully run, storing last_run as {last_run_dt}"
        )
        self.helper.connector_logger.info(msg)
        if self.converter.work_id is not None:
            self.helper.api.work.to_processed(self.converter.work_id, msg)
        self.helper.set_state({"last_run": current_time})

        interval_in_hours = round(self.interval / 60 / 60, 2)
        self.helper.connector_logger.info(
            f"[CONNECTOR] Last_run stored, next run in: {interval_in_hours} hours"
        )

    async def _async_ingest(self, cve_params: dict) -> None:
        """Run the streaming async ingestion pipeline.

        CVE bundles are sent as pages arrive from the NVD API.
        CPE resolution starts immediately and runs concurrently
        with further CVE fetching (bounded by cpe_max_concurrency).
        """
        # Reset rate limiter state to avoid stale asyncio.Lock across runs
        self.converter._rate_limiter.reset()
        try:
            self.helper.connector_logger.info(
                "[CONNECTOR] Starting CVE+CPE streaming pipeline"
            )
            await self.converter.ingest(cve_params)
        finally:
            await self.converter.close()

    def _import_recent(self, now: datetime) -> None:
        """
        Import the most recent CVEs depending on date range chosen
        :param now: Current date in datetime
        """
        if self.config.cve.max_date_range > MAX_AUTHORIZED:
            error_msg = f"The max_date_range cannot exceed {MAX_AUTHORIZED} days"
            raise Exception(error_msg)

        date_range = timedelta(days=self.config.cve.max_date_range)
        start_date = now - date_range

        cve_params = self._update_cve_params(start_date, now)

        asyncio.run(self._async_ingest(cve_params))

    def _import_history(self, start_date: datetime, end_date: datetime) -> None:
        """
        Import CVEs history if pull_history config is True
        :param start_date: Start date in datetime
        :param end_date: End date in datetime
        """
        years = range(start_date.year, end_date.year + 1)
        start, end = start_date, end_date + timedelta(1)

        for year in years:
            year_start = datetime(year, 1, 1, 0, 0, tzinfo=timezone.utc)
            year_end = datetime(year + 1, 1, 1, 0, 0, tzinfo=timezone.utc)

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
                    cve_params = self._update_cve_params(
                        start_date_current_year, end_date_current_year
                    )

                    asyncio.run(self._async_ingest(cve_params))
                    days_in_year = 0

                """
                Retrieving for each year MAX_AUTHORIZED = 120 days
                1 year % 120 days => 5 or 6 (depends if it is a leap year or not)
                """
                if days_in_year > 6:
                    cve_params = self._update_cve_params(
                        start_date_current_year, end_date_current_year
                    )

                    asyncio.run(self._async_ingest(cve_params))
                    start_date_current_year += timedelta(days=MAX_AUTHORIZED)
                    days_in_year -= MAX_AUTHORIZED
                else:
                    end_date_current_year = start_date_current_year + timedelta(
                        days=days_in_year
                    )
                    cve_params = self._update_cve_params(
                        start_date_current_year, end_date_current_year
                    )
                    asyncio.run(self._async_ingest(cve_params))
                    days_in_year = 0

            info_msg = f"[CONNECTOR] Importing CVE history for year {year} finished"
            self.helper.connector_logger.info(info_msg)

    def _maintain_data(self, now: datetime, last_run: float) -> None:
        """
        Maintain data updated if maintain_data config is True
        :param now: Current date in datetime
        :param last_run: Last run date in float
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Getting the last CVEs since the last run..."
        )

        last_run_ts = datetime.fromtimestamp(last_run, tz=timezone.utc)

        cve_params = self._update_cve_params(last_run_ts, now)
        asyncio.run(self._async_ingest(cve_params))

    @staticmethod
    def _update_cve_params(start_date: datetime, end_date: datetime) -> dict:
        """
        Update CVE params to handle date range
        :param start_date: Start date in datetime
        :param end_date: End date in datetime
        :return: Dict of CVE params
        """
        return {
            "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def process_data(self) -> None:
        try:
            """
            Get the current state and check if connector already runs
            """
            now = datetime.now(tz=timezone.utc)
            current_time = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                last_run_dt = datetime.fromtimestamp(
                    last_run, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
                msg = f"[CONNECTOR] Connector last run: {last_run_dt}"
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
                """
                =================================================================
                If the connector never runs and user wants to pull CVE history
                =================================================================
                """
                if self.config.cve.pull_history:
                    start_date = datetime(
                        self.config.cve.history_start_year, 1, 1, tzinfo=timezone.utc
                    )
                    end_date = now
                    self._import_history(start_date, end_date)
                else:
                    self._import_recent(now)

                self.update_connector_state(current_time)

                """
                ===================================================================
                Import CVEs from the last run to now if maintain data is True
                If the connector runs, and last run is more than current interval
                ===================================================================
                """
            elif (
                last_run is not None
                and self.config.cve.maintain_data
                and (current_time - last_run) >= int(self.interval)
            ):
                self._maintain_data(now, last_run)
                self.update_connector_state(current_time)

            else:
                new_interval = self.interval - (current_time - last_run)
                new_interval_in_hours = round(new_interval / 60 / 60, 2)
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Connector will not run, next run in: "
                    f"{new_interval_in_hours} hours"
                )

            time.sleep(5)

        except (KeyboardInterrupt, SystemExit):
            msg = "[CONNECTOR] Connector stop..."
            self.helper.connector_logger.info(msg)
            sys.exit(0)
        except Exception as e:
            error_msg = f"[CONNECTOR] Error while processing data: {e}"
            self.helper.connector_logger.error(error_msg, meta={"error": str(e)})
