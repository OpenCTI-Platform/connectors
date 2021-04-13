# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike indicator importer module."""

from typing import Any, Generator, List, Mapping, Optional

from crowdstrike_client.api.intel import Indicators, Reports
from crowdstrike_client.api.models import Indicator

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper  # type: ignore  # noqa: E501

from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore

from crowdstrike.importer import BaseImporter
from crowdstrike.indicator.builder import IndicatorBundleBuilder
from crowdstrike.utils.report_fetcher import FetchedReport, ReportFetcher
from crowdstrike.utils import datetime_to_timestamp, timestamp_to_datetime


class IndicatorImporter(BaseImporter):
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
        create_observables: bool,
        create_indicators: bool,
        exclude_types: List[str],
        report_status: int,
        report_type: str,
    ) -> None:
        """Initialize CrowdStrike indicator importer."""
        super().__init__(helper, author, tlp_marking, update_existing_data)

        self.indicators_api = indicators_api
        self.create_observables = create_observables
        self.create_indicators = create_indicators
        self.default_latest_timestamp = default_latest_timestamp
        self.exclude_types = exclude_types
        self.report_status = report_status
        self.report_type = report_type

        if not (self.create_observables or self.create_indicators):
            msg = "'create_observables' and 'create_indicators' false at the same time"
            raise ValueError(msg)

        self.report_fetcher = ReportFetcher(reports_api)

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self._info("Running indicator importer with state: {0}...", state)

        self._clear_report_fetcher_cache()

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

    def _clear_report_fetcher_cache(self) -> None:
        self.report_fetcher.clear_cache()

    def _fetch_indicators(
        self, fetch_timestamp: int
    ) -> Generator[List[Indicator], None, None]:
        limit = 10000
        sort = "_marker"
        fql_filter = f"published_date:>{fetch_timestamp}"

        if self.exclude_types:
            fql_filter = f"{fql_filter}+type:!{self.exclude_types}"

        return self._query_indicators(limit, sort, fql_filter)

    def _query_indicators(
        self, limit, sort, fql_filter
    ) -> Generator[List[Indicator], None, None]:
        _limit = limit
        _sort = sort
        _fql_filter = fql_filter

        total_count = 0

        while True:
            response = self.indicators_api.query_entities(
                limit=_limit, sort=_sort, fql_filter=_fql_filter, deep_pagination=True
            )

            errors = response.errors
            if errors:
                self._error("Indicator query completed with errors")
                for error in errors:
                    self._error("Error: {0} (code: {1})", error.message, error.code)

            meta = response.meta
            if meta.pagination is not None:
                pagination = meta.pagination

                _meta_limit = pagination.limit
                _meta_offset = pagination.offset
                _meta_total = pagination.total

                self._info(
                    "Indicator query pagination limit: {0}, offset: {1}, total: {2}",
                    _meta_limit,
                    _meta_offset,
                    _meta_total,
                )

            resources = response.resources
            resources_count = len(resources)

            self._info("Indicator query fetched {0} resources", resources_count)

            total_count += resources_count

            yield resources

            next_page_params = response.get_next_page_params()
            if next_page_params is not None:
                _limit = int(next_page_params["limit"][0])
                _sort = next_page_params["sort"][0]
                _fql_filter = next_page_params["filter"][0]
            else:
                self._info("Fetched {0} indicators in total", total_count)
                return

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

        indicator_reports = self._get_reports_by_code(indicator.reports)

        indicator_bundle = self._create_indicator_bundle(indicator, indicator_reports)
        if indicator_bundle is None:
            self._error("Discarding indicator {0} bundle", indicator.id)
            return False

        # with open(f"indicator_bundle_{indicator_bundle['id']}.json", "w") as f:
        #     f.write(indicator_bundle.serialize(pretty=True))

        self._send_bundle(indicator_bundle)

        return True

    def _get_reports_by_code(self, codes: List[str]) -> List[FetchedReport]:
        return self.report_fetcher.get_by_codes(codes)

    def _create_indicator_bundle(
        self, indicator: Indicator, indicator_reports: List[FetchedReport]
    ) -> Optional[Bundle]:
        author = self.author
        source_name = self._source_name()
        object_markings = [self.tlp_marking]
        confidence_level = self._confidence_level()
        create_observables = self.create_observables
        create_indicators = self.create_indicators
        report_status = self.report_status
        report_type = self.report_type

        try:
            bundle_builder = IndicatorBundleBuilder(
                indicator,
                author,
                source_name,
                object_markings,
                confidence_level,
                create_observables,
                create_indicators,
                report_status,
                report_type,
                indicator_reports,
            )
            return bundle_builder.build()
        except TypeError as te:
            self._error(
                "Failed to build indicator bundle for '{0}': {1}",
                indicator.id,
                te,
            )
            return None
