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

# Connector state keys of an interrupted history import. They are written after
# each history window is sent and replaced by last_run once the history is done.
HISTORY_PROGRESS_KEY = "history_last_window_end"
HISTORY_START_YEAR_KEY = "history_start_year"


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
        # Drop the stale asyncio.Lock from the previous asyncio.run() while
        # keeping the sliding-window request history, so the rate limiter stays
        # continuous across consecutive runs (e.g. historical-backfill chunks)
        # instead of allowing a fresh burst at every chunk boundary.
        self.converter._rate_limiter.invalidate_lock()
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

    @staticmethod
    def _history_windows(start_date: datetime, end_date: datetime):
        """
        Split the history range into consecutive NVD windows.

        Windows never cross a year boundary and never exceed MAX_AUTHORIZED
        days (the NVD API rejects longer lastModStartDate/lastModEndDate
        ranges). The last window ends at end_date.
        :param start_date: Start date in datetime
        :param end_date: End date in datetime
        :return: Iterator of (year, window_start, window_end)
        """
        max_date_range = timedelta(days=MAX_AUTHORIZED)
        window_start = start_date
        while window_start < end_date:
            year = window_start.year
            year_end = datetime(year + 1, 1, 1, 0, 0, tzinfo=timezone.utc)
            window_end = min(window_start + max_date_range, year_end, end_date)
            yield year, window_start, window_end
            window_start = window_end

    def _save_history_progress(self, window_end: datetime) -> None:
        """
        Save the end of the last history window sent, so a restart of the
        connector or of the OpenCTI API resumes the history from there
        instead of starting it again from CVE_HISTORY_START_YEAR.
        The maintain mode's last_run is never written here: it is written
        once, when the whole history is imported.
        :param window_end: End of the last window sent, in datetime
        """
        self.helper.set_state(
            {
                HISTORY_START_YEAR_KEY: self.config.cve.history_start_year,
                HISTORY_PROGRESS_KEY: int(window_end.timestamp()),
            }
        )

    def _history_resume_date(self, current_state: dict | None) -> datetime | None:
        """
        Read where an interrupted history import stopped.
        :param current_state: Connector state
        :return: End of the last history window sent, or None to start the
            history from CVE_HISTORY_START_YEAR
        """
        if not current_state or HISTORY_PROGRESS_KEY not in current_state:
            return None
        if (
            current_state.get(HISTORY_START_YEAR_KEY)
            != self.config.cve.history_start_year
        ):
            self.helper.connector_logger.info(
                "[CONNECTOR] CVE_HISTORY_START_YEAR changed since the history "
                "import was interrupted, starting the history again"
            )
            return None
        return datetime.fromtimestamp(
            current_state[HISTORY_PROGRESS_KEY], tz=timezone.utc
        )

    def _import_history(self, start_date: datetime, end_date: datetime) -> None:
        """
        Import CVEs history if pull_history config is True.
        The progress is saved after each window is sent: if the run is
        interrupted (connector or OpenCTI API restart, failed send), the next
        run starts again at the first window not sent.
        :param start_date: Start date in datetime
        :param end_date: End date in datetime
        """
        current_year = None
        for year, window_start, window_end in self._history_windows(
            start_date, end_date
        ):
            if current_year is not None and year != current_year:
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Importing CVE history for year {current_year} finished"
                )
            current_year = year
            days_left = (
                min(end_date, datetime(year + 1, 1, 1, tzinfo=timezone.utc))
                - window_start
            ).days
            self.helper.connector_logger.info(
                f"[CONNECTOR] Connector retrieve CVE history for year {year}, "
                f"{days_left} days left"
            )
            cve_params = self._update_cve_params(window_start, window_end)
            asyncio.run(self._async_ingest(cve_params))
            self._save_history_progress(window_end)

        if current_year is not None:
            self.helper.connector_logger.info(
                f"[CONNECTOR] Importing CVE history for year {current_year} finished"
            )

    def _maintain_data(self, now: datetime, last_run: float) -> None:
        """
        Maintain data updated if maintain_data config is True
        :param now: Current date in datetime
        :param last_run: Last run date in float
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Getting the last CVEs since the last run..."
        )

        start_date = datetime.fromtimestamp(last_run, tz=timezone.utc)
        max_date_range = timedelta(days=MAX_AUTHORIZED)

        # The NVD API rejects any date range longer than MAX_AUTHORIZED days,
        # so split the last_run-to-now range into consecutive windows of at
        # most MAX_AUTHORIZED days each.
        while start_date < now:
            end_date = min(start_date + max_date_range, now)
            cve_params = self._update_cve_params(start_date, end_date)
            asyncio.run(self._async_ingest(cve_params))
            start_date = end_date

    @staticmethod
    def _format_exception(err: BaseException) -> str:
        """Format an exception for logging.

        `asyncio.TaskGroup` (used by the streaming ingestion pipeline) wraps
        any failure — including ones with a clear, actionable message like
        "[API] Error: Invalid apiKey." — into a `BaseExceptionGroup` whose
        own `str()` is just the generic "unhandled errors in a TaskGroup
        (N sub-exception(s))". Unwrap it (recursively, in case of nested
        groups) so the real underlying reason ends up in the single log
        line the connector emits for a failed run, instead of a second,
        uninformative one.
        """
        if isinstance(err, BaseExceptionGroup):
            return "; ".join(
                CVEConnector._format_exception(sub) for sub in err.exceptions
            )
        return str(err)

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
        # Each run starts with no work: the converter creates one with the
        # first bundle the run sends, so a work never outlives its run.
        self.converter.work_id = None
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
                    start_date = self._history_resume_date(current_state)
                    if start_date is None:
                        start_date = datetime(
                            self.config.cve.history_start_year,
                            1,
                            1,
                            tzinfo=timezone.utc,
                        )
                    else:
                        self.helper.connector_logger.info(
                            "[CONNECTOR] Resuming the interrupted CVE history "
                            f"import from {start_date.strftime('%Y-%m-%d %H:%M:%S')}"
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
            detail = self._format_exception(e)
            error_msg = f"[CONNECTOR] Error while processing data: {detail}"
            self.helper.connector_logger.error(error_msg, meta={"error": detail})
            self._close_work_in_error(error_msg)

    def _close_work_in_error(self, message: str) -> None:
        """Close the work of a failed run in error."""
        work_id = self.converter.work_id
        if work_id is None:
            return
        try:
            self.helper.api.work.to_processed(work_id, message, in_error=True)
        except Exception as err:  # pylint: disable=broad-except
            # The run has already failed: do not hide its error behind this one.
            self.helper.connector_logger.warning(
                "[CONNECTOR] Unable to close the work of the failed run",
                meta={"work_id": work_id, "error": str(err)},
            )
