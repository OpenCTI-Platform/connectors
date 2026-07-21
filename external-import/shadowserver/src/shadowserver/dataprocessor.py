"""Shadowserver data processor."""

from __future__ import annotations

from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from typing import Any

from connectors_sdk import BaseDataProcessor
from shadowserver.api import ShadowserverAPI
from shadowserver.constants import TLP_MAP
from shadowserver.stix_transform import ShadowserverStixTransformation
from shadowserver.utils import remove_duplicates


class ShadowserverProcessor(BaseDataProcessor):
    """Collect Shadowserver reports and convert them to STIX bundles.

    Pipeline:
        collect() → fetches report list per day, downloads each report in parallel,
                    yields (date_str, report_meta, report_rows) per report
        transform() → converts raw report rows to STIX objects, yields bundle per report
    """

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def post_init(self) -> None:
        """Post-initialization hook for setting up the processor after dependencies are injected."""
        self._config = self.settings.shadowserver  # type: ignore[attr-defined]
        self._marking_refs = TLP_MAP[self._config.marking]

    # ------------------------------------------------------------------
    # DataProcessor pipeline
    # ------------------------------------------------------------------

    def collect(self) -> Generator[tuple[str, dict, list], None, None]:
        """Fetch report lists and download report data, yielding one item per report.

        For each day in the lookback window the report list is retrieved, then all
        reports for that day are downloaded in parallel.  Only reports that contain
        data are yielded.

        Yields:
            Tuples of (date_str, report_meta, report_rows) for each non-empty report.
        """
        lookback = self._get_lookback()
        api_key = self._config.api_key.get_secret_value()
        api_secret = self._config.api_secret.get_secret_value()
        report_types = self._config.report_types
        report_names = self._config.report_names
        max_threads = self._config.max_threads

        shadowserver_api = ShadowserverAPI(
            api_key=api_key,
            api_secret=api_secret,
        )

        if report_types:
            self.logger.info(f"Report types to retrieve: {', '.join(report_types)}.")
        if report_names:
            self.logger.info(f"Report names to retrieve: {', '.join(report_names)}.")

        def _download(report: dict) -> tuple[dict, list]:
            worker_api = ShadowserverAPI(
                api_key=api_key,
                api_secret=api_secret,
            )
            return report, worker_api.get_report_data(report=report)

        start_time = datetime.now(tz=UTC)
        for days_lookback in range(lookback, -1, -1):
            date = start_time - timedelta(days=days_lookback)
            date_str = date.strftime("%Y-%m-%d")

            self.logger.info(f"Getting reports for {date_str}.")
            self.work_name = f"Shadowserver import for {date_str}"
            report_list = shadowserver_api.get_report_list(
                date=date_str, reports=report_names, type=report_types
            )
            if not report_list:
                self.logger.info(f"No reports found for {date_str}.")
                continue

            self.logger.info(
                f"Found {len(report_list)} reports for {date_str}. Downloading..."
            )
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {
                    executor.submit(_download, report): report for report in report_list
                }
                for future in as_completed(futures):
                    try:
                        report_meta, report_rows = future.result()
                        if report_rows:
                            yield date_str, report_meta, report_rows
                    except Exception as e:
                        self.logger.error(f"Error downloading report: {e}")

    def transform(
        self, data: Generator[tuple[str, dict, list], None, None]
    ) -> Generator[list[Any], None, None]:
        """Convert raw report rows to STIX objects, yielding one bundle per report.

        Updates ``self.work_name`` per day so the WorkManager creates one work per day.

        Args:
            data: Generator of (date_str, report_meta, report_rows) tuples from collect().

        Yields:
            Deduplicated list of STIX objects per report.
        """
        incident = {
            "create": self._config.create_incident,
            "severity": self._config.incident_severity,
            "priority": self._config.incident_priority,
        }

        for date_str, report_meta, report_rows in data:
            try:
                stix_objects = ShadowserverStixTransformation(
                    marking_refs=self._marking_refs,
                    report_list=report_rows,
                    report=report_meta,
                    incident=incident,
                    logger=self.logger,
                ).get_stix_objects()
                report_stix_objects = [obj for obj in stix_objects if obj]
                if not report_stix_objects:
                    continue
                unique_objects = remove_duplicates(report_stix_objects)
                self.logger.info(
                    f"Sending {len(unique_objects)} STIX2 objects for {date_str}..."
                )
                yield unique_objects
            except Exception as e:
                self.logger.error(f"Error transforming report: {e}")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_lookback(self) -> int:
        """Compute the lookback in days based on state."""
        if self.state.last_run:
            now = datetime.now(tz=UTC)
            return (now - self.state.last_run).days + self._config.lookback
        return self._config.initial_lookback
