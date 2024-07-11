# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike indicator importer module."""

from typing import Any, Dict, Generator, List, NamedTuple, Optional, Set

from crowdstrike_feeds_services.client.indicators import IndicatorsAPI
from crowdstrike_feeds_services.utils import (
    datetime_to_timestamp,
    timestamp_to_datetime,
)
from crowdstrike_feeds_services.utils.report_fetcher import FetchedReport, ReportFetcher
from pycti.connector.opencti_connector_helper import (  # type: ignore  # noqa: E501
    OpenCTIConnectorHelper,
)
from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore

from ..importer import BaseImporter
from .builder import IndicatorBundleBuilder, IndicatorBundleBuilderConfig


class IndicatorImporterConfig(NamedTuple):
    """CrowdStrike indicator importer configuration."""

    helper: OpenCTIConnectorHelper
    update_existing_data: bool
    author: Identity
    default_latest_timestamp: int
    tlp_marking: MarkingDefinition
    create_observables: bool
    create_indicators: bool
    exclude_types: List[str]
    report_status: int
    report_type: str
    indicator_low_score: int
    indicator_low_score_labels: Set[str]
    indicator_unwanted_labels: Set[str]


class IndicatorImporter(BaseImporter):
    """CrowdStrike indicator importer."""

    _LATEST_INDICATOR_TIMESTAMP = "latest_indicator_timestamp"

    def __init__(self, config: IndicatorImporterConfig) -> None:
        """Initialize CrowdStrike indicator importer."""
        super().__init__(
            config.helper,
            config.author,
            config.tlp_marking,
            config.update_existing_data,
        )

        self.indicators_api_cs = IndicatorsAPI(config.helper)
        self.create_observables = config.create_observables
        self.create_indicators = config.create_indicators
        self.default_latest_timestamp = config.default_latest_timestamp
        self.exclude_types = config.exclude_types
        self.report_status = config.report_status
        self.report_type = config.report_type
        self.indicator_low_score = config.indicator_low_score
        self.indicator_low_score_labels = config.indicator_low_score_labels
        self.indicator_unwanted_labels = config.indicator_unwanted_labels
        self.next_page: Optional[str] = None

        if not (self.create_observables or self.create_indicators):
            msg = "'create_observables' and 'create_indicators' false at the same time"
            raise ValueError(msg)

        self.report_fetcher = ReportFetcher(config.helper)

    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run importer."""
        self._info("Running indicator importer with state: {0}...", state)

        self._clear_report_fetcher_cache()

        fetch_timestamp = state.get(
            self._LATEST_INDICATOR_TIMESTAMP, self.default_latest_timestamp
        )

        latest_indicator_published_datetime = None

        for indicator_batch in self._fetch_indicators(fetch_timestamp):
            if not indicator_batch:
                break

            latest_batch_published_datetime = self._process_indicators(indicator_batch)

            if latest_batch_published_datetime is not None and (
                latest_indicator_published_datetime is None
                or latest_batch_published_datetime > latest_indicator_published_datetime
            ):
                latest_indicator_published_datetime = latest_batch_published_datetime

        latest_indicator_published_timestamp = fetch_timestamp

        if latest_indicator_published_datetime is not None:
            latest_indicator_published_timestamp = datetime_to_timestamp(
                latest_indicator_published_datetime
            )

        self._info(
            "Indicator importer completed, latest fetch {0}.",
            timestamp_to_datetime(latest_indicator_published_timestamp),
        )

        return {self._LATEST_INDICATOR_TIMESTAMP: latest_indicator_published_timestamp}

    def _clear_report_fetcher_cache(self) -> None:
        self.report_fetcher.clear_cache()

    def _fetch_indicators(self, fetch_timestamp: int) -> Generator[List, None, None]:
        limit = 10000
        sort = "_marker"
        fql_filter = f"published_date:>{fetch_timestamp}"

        if self.exclude_types:
            fql_filter = f"{fql_filter}+type:!{self.exclude_types}"

        return self._query_indicators(limit, sort, fql_filter)

    def _query_indicators(
        self, limit, sort, fql_filter
    ) -> Generator[List, None, None] | None:
        _limit = limit
        _sort = sort
        _fql_filter = fql_filter

        total_count = 0

        while True:
            response = self.indicators_api_cs.get_combined_indicator_entities(
                limit=_limit, sort=_sort, fql_filter=_fql_filter, deep_pagination=True
            )
            meta = response["meta"]
            if meta["pagination"] is not None:
                pagination = meta["pagination"]

                _meta_limit = pagination["limit"]
                _meta_offset = pagination["offset"]
                _meta_total = pagination["total"]

                self._info(
                    "Indicator query pagination limit: {0}, offset: {1}, total: {2}",
                    _meta_limit,
                    _meta_offset,
                    _meta_total,
                )

            resources = response["resources"]
            resources_count = len(resources)

            self._info("Indicator query fetched {0} resources", resources_count)

            total_count += resources_count

            yield resources

            next_page_params = response["next_page_details"]
            if next_page_params is not None:
                _limit = int(next_page_params["limit"][0])
                _sort = next_page_params["sort"][0]
                _fql_filter = next_page_params["filter"][0]
            else:
                self._info("Fetched {0} indicators in total", total_count)
                return

    def _process_indicators(self, indicators: List) -> Optional[int]:
        indicator_count = len(indicators)
        self._info("Processing {0} indicators...", indicator_count)

        latest_published_datetime = None

        failed = 0
        for indicator in indicators:
            result = self._process_indicator(indicator)
            if not result:
                failed += 1

            published_date = timestamp_to_datetime(indicator["published_date"])
            if (
                latest_published_datetime is None
                or published_date > latest_published_datetime
            ):
                latest_published_datetime = published_date

        imported = indicator_count - failed
        total = imported + failed

        self._info(
            "Processing indicators completed (imported: {0}, failed: {1}, total: {2}, latest: {3})",  # noqa: E501
            imported,
            failed,
            total,
            latest_published_datetime,
        )

        return latest_published_datetime

    def _process_indicator(self, indicator: dict) -> bool:
        self._info("Processing indicator {0}...", indicator["id"])

        indicator_reports = self._get_reports_by_code(indicator["reports"])

        indicator_bundle = self._create_indicator_bundle(indicator, indicator_reports)
        if indicator_bundle is None:
            self._error("Discarding indicator {0} bundle", indicator["id"])
            return False

        # with open(f"indicator_bundle_{indicator_bundle['id']}.json", "w") as f:
        #     f.write(indicator_bundle.serialize(pretty=True))

        self._send_bundle(indicator_bundle)

        return True

    def _get_reports_by_code(self, codes: List[str]) -> List[FetchedReport]:
        return self.report_fetcher.get_by_codes(codes)

    def _create_indicator_bundle(
        self, indicator: dict, indicator_reports: List[FetchedReport]
    ) -> Optional[Bundle]:
        bundle_builder_config = IndicatorBundleBuilderConfig(
            indicator=indicator,
            author=self.author,
            source_name=self._source_name(),
            object_markings=[self.tlp_marking],
            confidence_level=self._confidence_level(),
            create_observables=self.create_observables,
            create_indicators=self.create_indicators,
            indicator_report_status=self.report_status,
            indicator_report_type=self.report_type,
            indicator_reports=indicator_reports,
            indicator_low_score=self.indicator_low_score,
            indicator_low_score_labels=self.indicator_low_score_labels,
            indicator_unwanted_labels=self.indicator_unwanted_labels,
        )

        try:
            bundle_builder = IndicatorBundleBuilder(bundle_builder_config)
            return bundle_builder.build()
        except TypeError as te:
            self._error(
                "Failed to build indicator bundle for '{0}': {1}",
                indicator["id"],
                te,
            )
            return None
