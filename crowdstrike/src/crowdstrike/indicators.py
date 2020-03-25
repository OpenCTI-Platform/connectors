# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike indicator importer module."""

from typing import Any, Dict, Generator, List, Mapping, Optional

from crowdstrike_client.api.intel import Indicators, Reports
from crowdstrike_client.api.models import Indicator, Response
from crowdstrike_client.api.models.report import Report

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper

from stix2 import Bundle, Identity, MarkingDefinition

from crowdstrike.indicator_bundle_builder import IndicatorBundleBuilder, IndicatorReport
from crowdstrike.utils import (
    create_file_from_download,
    datetime_to_timestamp,
    paginate,
    timestamp_to_datetime,
)


class IndicatorImporter:
    """CrowdStrike indicator importer."""

    _LATEST_INDICATOR_TIMESTAMP = "latest_indicator_timestamp"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        indicators_api: Indicators,
        reports_api: Reports,
        update_existing_data: bool,
        author: Identity,
        default_latest_timestamp: int,
        tlp_marking: MarkingDefinition,
        exclude_types: List[str],
        report_status: int,
        report_type: str,
    ) -> None:
        """Initialize CrowdStrike indicator importer."""
        self.helper = helper
        self.indicators_api = indicators_api
        self.reports_api = reports_api
        self.update_existing_data = update_existing_data
        self.author = author
        self.default_latest_timestamp = default_latest_timestamp
        self.tlp_marking = tlp_marking
        self.exclude_types = exclude_types
        self.report_status = report_status
        self.report_type = report_type

        self.run_reports_cache: Dict[str, IndicatorReport] = {}

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self._info("Running indicator importer with state: {0}...", state)

        self._clear_run_reports_cache()

        fetch_timestamp = state.get(
            self._LATEST_INDICATOR_TIMESTAMP, self.default_latest_timestamp
        )

        latest_fetched_indicator_timestamp = None

        for indicator_batch in self._fetch_indicators(fetch_timestamp):
            if not indicator_batch:
                break

            if latest_fetched_indicator_timestamp is None:
                first_in_batch = indicator_batch[0]

                latest_fetched_indicator_timestamp = datetime_to_timestamp(
                    first_in_batch.published_date
                )

            self._process_indicators(indicator_batch)

        state_timestamp = latest_fetched_indicator_timestamp or fetch_timestamp

        self._info(
            "Indicator importer completed, latest fetch {0}.",
            timestamp_to_datetime(state_timestamp),
        )

        return {self._LATEST_INDICATOR_TIMESTAMP: state_timestamp}

    def _clear_run_reports_cache(self) -> None:
        self.run_reports_cache.clear()

    def _get_run_reports_cache(self, report_code: str) -> Optional[IndicatorReport]:
        return self.run_reports_cache.get(report_code)

    def _put_run_reports_cache(
        self, report_code: str, indicator_report: IndicatorReport
    ) -> None:
        self.run_reports_cache[report_code] = indicator_report

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

    def _fetch_indicators(
        self, fetch_timestamp: int
    ) -> Generator[List[Indicator], None, None]:
        limit = 10000
        sort = "published_date|desc"
        fql_filter = f"published_date:>{fetch_timestamp}"

        if self.exclude_types:
            fql_filter = f"{fql_filter}+type:!{self.exclude_types}"

        paginated_query = paginate(self._query_indicator_entities)

        return paginated_query(limit=limit, sort=sort, fql_filter=fql_filter)

    def _query_indicator_entities(
        self,
        limit: int = 50,
        offset: int = 0,
        sort: Optional[str] = None,
        fql_filter: Optional[str] = None,
    ) -> Response[Indicator]:
        self._info(
            "Query indicators limit: {0}, offset: {1}, sort: {2}, filter: {3}",
            limit,
            offset,
            sort,
            fql_filter,
        )

        return self.indicators_api.query_entities(
            limit=limit, offset=offset, sort=sort, fql_filter=fql_filter
        )

    def _process_indicators(self, indicators: List[Indicator]) -> None:
        indicator_count = len(indicators)
        self._info("Processing {0} indicators...", indicator_count)

        failed = 0
        for indicator in indicators:
            result = self._process_indicator(indicator)
            if not result:
                failed += 1

        imported = indicator_count - failed
        total = imported + failed

        self._info(
            "Processing indicators completed (imported: {0}, failed: {1}, total: {2})",
            imported,
            failed,
            total,
        )

    def _process_indicator(self, indicator: Indicator) -> bool:
        self._info("Processing indicator {0}...", indicator.id)

        indicator_reports = self._get_indicator_reports(indicator.reports)

        indicator_bundle = self._create_indicator_bundle(indicator, indicator_reports)
        if indicator_bundle is None:
            self._error("Discarding {0} indicator bundle", indicator.id)
            return False

        self._send_bundle(indicator_bundle)

        return True

    def _create_indicator_bundle(
        self, indicator: Indicator, indicator_reports: List[IndicatorReport]
    ) -> Optional[Bundle]:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        confidence_level = self._confidence_level()
        report_status = self.report_status
        report_type = self.report_type

        try:
            bundle_builder = IndicatorBundleBuilder(
                indicator,
                author,
                source_name,
                object_marking_refs,
                confidence_level,
                report_status,
                report_type,
                indicator_reports,
            )
            return bundle_builder.build()
        except TypeError as te:
            self._error(str(te))
            return None

    def _get_indicator_reports(self, report_codes: List[str]) -> List[IndicatorReport]:
        indicator_reports = []
        for report_code in report_codes:
            cached_indicator_report = self._get_run_reports_cache(report_code)
            if cached_indicator_report is not None:
                indicator_reports.append(cached_indicator_report)
                continue

            report = self._fetch_report(report_code)
            if report is None:
                continue

            files = []
            report_file = self._get_report_pdf(report.id)
            if report_file is not None:
                files.append(report_file)

            indicator_report = IndicatorReport(report=report, files=files)

            self._put_run_reports_cache(report_code, indicator_report)

            indicator_reports.append(indicator_report)
        return indicator_reports

    def _fetch_report(self, report_code: str) -> Optional[Report]:
        self._info("Fetching report {0}...", report_code)

        ids = [report_code]
        fields = ["__full__"]

        response = self.reports_api.get_entities(ids, fields)

        errors = response.errors
        if errors:
            self._error("Fetching report completed with errors")
            for error in errors:
                self._error("Error: {0} (code: {1})", error.message, error.code)

        resources = response.resources
        resources_count = len(resources)

        if resources_count == 0:
            self._info("Report code {0} returned nothing", report_code)
            return None

        if resources_count > 1:
            self._error("Report code {0} returned more than one result", report_code)
            return None

        report = resources[0]
        return report

    def _get_report_pdf(self, report_id: int) -> Optional[Mapping[str, str]]:
        download = self.reports_api.get_pdf(str(report_id))

        if download is None:
            return None

        return create_file_from_download(download)

    def _source_name(self) -> str:
        return self.helper.connect_name

    def _confidence_level(self) -> int:
        return self.helper.connect_confidence_level

    def _send_bundle(self, bundle: Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle, None, self.update_existing_data, False
        )
