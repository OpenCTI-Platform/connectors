import asyncio
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Literal

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

    def update_connector_state(
        self, current_time: int, extra_state: dict | None = None
    ) -> None:
        """
        Update the connector state
        :param current_time: Time in int
        :param extra_state: additional keys to persist with last_run, such as the
            history_done marker that stops the history import from running again
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
        state = {"last_run": current_time}
        if extra_state:
            state.update(extra_state)
        self.helper.set_state(state)

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

    def _import_history(self, start_date: datetime, end_date: datetime) -> None:
        """
        Import CVEs history if pull_history config is True
        :param start_date: Start date in datetime
        :param end_date: End date in datetime
        """
        if end_date < start_date:
            msg = (
                "[CONNECTOR] Invalid history range: start "
                f"{start_date:%Y-%m-%d %H:%M:%S} is after end "
                f"{end_date:%Y-%m-%d %H:%M:%S}; nothing to import"
            )
            self.helper.connector_logger.warning(msg)
            return

        years = range(start_date.year, end_date.year + 1)
        one_second = timedelta(seconds=1)

        for year in years:
            year_start = datetime(year, 1, 1, 0, 0, tzinfo=timezone.utc)
            # Both NVD bounds are inclusive, so the last second of the year is
            # 23:59:59 - not the next midnight, which would leak a row into two
            # windows.
            year_limit = min(
                end_date,
                datetime(year + 1, 1, 1, 0, 0, tzinfo=timezone.utc) - one_second,
            )

            # Honour the requested start date inside the first year, not January 1
            cursor = max(start_date, year_start)
            if cursor > year_limit:
                continue

            while cursor <= year_limit:
                # Step back one second from the next window's start so adjacent
                # requests are disjoint: an instant sitting on the boundary would
                # otherwise be returned twice and queued as a duplicate bundle.
                # The final window ends on the requested timestamp, not on a
                # midnight, so a run ending mid-day still covers that day.
                window_end = min(
                    cursor + timedelta(days=MAX_AUTHORIZED) - one_second, year_limit
                )
                if window_end < cursor:
                    # MAX_AUTHORIZED <= 0 would otherwise spin forever on the
                    # same cursor instead of failing.
                    raise ValueError(
                        f"MAX_AUTHORIZED={MAX_AUTHORIZED} does not advance the "
                        f"window at {cursor}"
                    )
                info_msg = (
                    f"[CONNECTOR] Connector retrieve CVE history: "
                    f"{cursor:%Y-%m-%d %H:%M:%S} -> {window_end:%Y-%m-%d %H:%M:%S}"
                )
                self.helper.connector_logger.info(info_msg)

                cve_params = self._update_cve_params(
                    cursor, window_end, date_field="pub"
                )
                asyncio.run(self._async_ingest(cve_params))

                # Persist progress after every window. If the run dies mid-import
                # (NVD error, DNS failure, pod restart) the next one resumes at
                # the last completed window instead of re-walking the years that
                # already landed. A production run lost four months of 2018 to
                # this and left no record of where it had stopped.
                self.helper.set_state(
                    {"history_cursor": window_end.strftime("%Y-%m-%dT%H:%M:%SZ")}
                )

                cursor = window_end + one_second

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

        start_date = datetime.fromtimestamp(last_run, tz=timezone.utc)
        max_date_range = timedelta(days=MAX_AUTHORIZED)

        # Windows here share a boundary with the next one, unlike the history
        # path: an overlapping lastMod row is merely re-upserted, while an
        # overlapping pub row would re-run CPE resolution for the same CVE.
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
    def _parse_history_bound(value: str) -> datetime:
        """Parse a configured history bound as an absolute UTC instant.

        `replace(tzinfo=utc)` relabels an offset-bearing timestamp instead of
        converting it: "2026-03-01T00:00:00+05:00" is 2026-02-28T19:00Z, not
        midnight UTC, and treating it as midnight would import past the bound.
        """
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _update_cve_params(
        start_date: datetime,
        end_date: datetime,
        date_field: Literal["lastMod", "pub"] = "lastMod",
    ) -> dict:
        """
        Update CVE params to handle date range
        :param start_date: Start date in datetime
        :param end_date: End date in datetime
        :param date_field: which NVD date dimension to query. "lastMod" is the
            incremental one and is correct for scheduled runs. "pub" must be used
            for historical imports: the modification index does not retain
            history, so a lastMod-based history import silently returns nothing.
        :return: Dict of CVE params
        """
        if date_field not in ("lastMod", "pub"):
            # Coercing an unknown value to lastMod is exactly the silent-empty-
            # history failure this change exists to fix, so refuse it loudly.
            raise ValueError(
                f"date_field must be 'lastMod' or 'pub', got {date_field!r}"
            )
        prefix = date_field
        return {
            f"{prefix}StartDate": start_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            f"{prefix}EndDate": end_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def process_data(self) -> None:
        try:
            """
            Get the current state and check if connector already runs
            """
            now = datetime.now(tz=timezone.utc).replace(microsecond=0)
            current_time = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            state = current_state or {}
            last_run = state.get("last_run")
            history_cursor = state.get("history_cursor")
            history_done = bool(state.get("history_done"))

            if last_run is not None:
                last_run_dt = datetime.fromtimestamp(
                    last_run, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
                msg = f"[CONNECTOR] Connector last run: {last_run_dt}"
                self.helper.connector_logger.info(msg)
            else:
                msg = "[CONNECTOR] Connector has never run..."
                self.helper.connector_logger.info(msg)

            """
            ======================================================
            Main process if connector successfully works
            ======================================================
            """

            """
            ================================================================
            History takes precedence over the incremental run. It is pending
            when a previous run was interrupted (a cursor is stored), when the
            connector has never run, or when pull_history was enabled on a
            connector that has already been running. That last case is why
            turning pull_history on for an existing deployment imported nothing:
            the history branch was only reachable while last_run was absent.
            ================================================================
            """
            if history_cursor or (self.config.cve.pull_history and not history_done):
                start_date = datetime(
                    self.config.cve.history_start_year, 1, 1, tzinfo=timezone.utc
                )
                # Resume after an interrupted run instead of starting over.
                if history_cursor:
                    resume_from = self._parse_history_bound(history_cursor)
                    if resume_from > now:
                        msg = (
                            "[CONNECTOR] Stored history cursor "
                            f"{history_cursor} is in the future; restarting the "
                            "history import from history_start_year"
                        )
                        self.helper.connector_logger.warning(msg)
                        resume_from = start_date
                    start_date = max(start_date, resume_from)

                self._import_history(start_date, now)
                self.update_connector_state(current_time, {"history_done": True})

                """
                ===================================================================
                Import CVEs from the last run to now if maintain data is True
                If the connector runs, and last run is more than current interval
                ===================================================================
                """
            elif last_run is None:
                self._import_recent(now)
                self.update_connector_state(current_time)

            elif self.config.cve.maintain_data and (current_time - last_run) >= int(
                self.interval
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
