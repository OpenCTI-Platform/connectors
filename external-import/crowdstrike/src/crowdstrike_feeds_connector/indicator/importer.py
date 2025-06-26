# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike indicator importer module."""

from typing import Any, Dict, List, NamedTuple, Optional, Set

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
    author: Identity
    default_latest_timestamp: int
    tlp_marking: MarkingDefinition
    create_observables: bool
    create_indicators: bool
    exclude_types: List[str]
    report_status: int
    report_type: str
    default_x_opencti_score: int
    indicator_low_score: int
    indicator_low_score_labels: Set[str]
    indicator_medium_score: int
    indicator_medium_score_labels: Set[str]
    indicator_high_score: int
    indicator_high_score_labels: Set[str]
    indicator_unwanted_labels: Set[str]


class IndicatorImporter(BaseImporter):
    """CrowdStrike indicator importer."""

    _NAME = "Indicator"

    _LATEST_INDICATOR_TIMESTAMP = "latest_indicator_timestamp"

    def __init__(self, config: IndicatorImporterConfig) -> None:
        """Initialize CrowdStrike indicator importer."""
        super().__init__(
            config.helper,
            config.author,
            config.tlp_marking,
        )

        self.indicators_api_cs = IndicatorsAPI(config.helper)
        self.create_observables = config.create_observables
        self.create_indicators = config.create_indicators
        self.default_latest_timestamp = config.default_latest_timestamp
        self.exclude_types = config.exclude_types
        self.report_status = config.report_status
        self.report_type = config.report_type
        self.default_x_opencti_score = config.default_x_opencti_score
        self.indicator_low_score = config.indicator_low_score
        self.indicator_low_score_labels = config.indicator_low_score_labels
        self.indicator_medium_score = config.indicator_medium_score
        self.indicator_medium_score_labels = config.indicator_medium_score_labels
        self.indicator_high_score = config.indicator_high_score
        self.indicator_high_score_labels = config.indicator_high_score_labels
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

        latest_indicator_updated_datetime = None

        indicator_batch = self._fetch_indicators(fetch_timestamp)
        if indicator_batch:

            latest_batch_updated_datetime = self._process_indicators(indicator_batch)

            if latest_batch_updated_datetime is not None and (
                latest_indicator_updated_datetime is None
                or latest_batch_updated_datetime > latest_indicator_updated_datetime
            ):
                latest_indicator_updated_datetime = latest_batch_updated_datetime

        latest_indicator_updated_timestamp = fetch_timestamp

        if latest_indicator_updated_datetime is not None:
            latest_indicator_updated_timestamp = datetime_to_timestamp(
                latest_indicator_updated_datetime
            )

        self._info(
            "Indicator importer completed, latest fetch {0}.",
            timestamp_to_datetime(latest_indicator_updated_timestamp),
        )

        return {self._LATEST_INDICATOR_TIMESTAMP: latest_indicator_updated_timestamp}

    def _clear_report_fetcher_cache(self) -> None:
        self.report_fetcher.clear_cache()

    def _fetch_indicators(self, fetch_timestamp: int) -> [List, None, None]:
        limit = 1000
        sort = "last_updated|asc"
        fql_filter = f"last_updated:>{fetch_timestamp}"

        if self.exclude_types:
            fql_filter = f"{fql_filter}+type:!{self.exclude_types}"

        return self._query_indicators(limit, sort, fql_filter)

    def _query_indicators(self, limit, sort, fql_filter) -> [List]:
        _limit = limit
        _sort = sort
        _fql_filter = fql_filter

        response = self.indicators_api_cs.get_combined_indicator_entities(
            limit=_limit, sort=_sort, fql_filter=_fql_filter, deep_pagination=True
        )

        # Add info to know how much data needs to be retrieved until now
        meta = response["meta"]
        _meta_total = None

        if meta["pagination"] is not None:
            pagination = meta["pagination"]

            _meta_total = pagination["total"]

            self.helper.connector_logger.info(
                "Indicator total resources to query until now", {"total": _meta_total}
            )

        resources = response["resources"]
        resources_count = len(resources)
        remaining_resources = None
        if _meta_total is not None:
            remaining_resources = _meta_total - resources_count

        self.helper.connector_logger.info(
            "Indicators fetched to be processed (Crowdstrike max limit = 10000)",
            {
                "resources_count": resources_count,
                "remaining_resources": remaining_resources,
            },
        )

        return resources

    def _process_indicators(self, indicators: List) -> Optional[int]:
        indicator_count = len(indicators)
        self._info("Processing {0} indicators...", indicator_count)

        latest_updated_datetime = None

        failed = 0
        for indicator in indicators:
            result = self._process_indicator(indicator)
            if not result:
                failed += 1

            updated_date = timestamp_to_datetime(indicator["last_updated"])
            if (
                latest_updated_datetime is None
                or updated_date > latest_updated_datetime
            ):
                latest_updated_datetime = updated_date

        imported = indicator_count - failed
        total = imported + failed

        self._info(
            "Processing indicators completed (imported: {0}, failed: {1}, total: {2}, latest: {3})",  # noqa: E501
            imported,
            failed,
            total,
            latest_updated_datetime,
        )

        return latest_updated_datetime

    def _process_indicator(self, indicator: dict) -> bool:
        self._info("Processing indicator {0}...", indicator["id"])

        indicator_bundle = self._create_indicator_bundle(indicator)
        if indicator_bundle is None:
            self._error("Discarding indicator {0} bundle", indicator["id"])
            return False

        # with open(f"indicator_bundle_{indicator_bundle['id']}.json", "w") as f:
        #     f.write(indicator_bundle.serialize(pretty=True))

        self._send_bundle(indicator_bundle)

        return True

    def _get_reports_by_code(self, codes: List[str]) -> List[FetchedReport]:
        return self.report_fetcher.get_by_codes(codes)

    def _create_indicator_bundle(self, indicator: dict) -> Optional[Bundle]:
        try:
            bundle_builder_config = IndicatorBundleBuilderConfig(
                indicator=indicator,
                author=self.author,
                source_name=self._source_name(),
                object_markings=[self.tlp_marking],
                confidence_level=self._confidence_level(),
                create_observables=self.create_observables,
                create_indicators=self.create_indicators,
                default_x_opencti_score=self.default_x_opencti_score,
                indicator_low_score=self.indicator_low_score,
                indicator_low_score_labels=self.indicator_low_score_labels,
                indicator_medium_score=self.indicator_medium_score,
                indicator_medium_score_labels=self.indicator_medium_score_labels,
                indicator_high_score=self.indicator_high_score,
                indicator_high_score_labels=self.indicator_high_score_labels,
                indicator_unwanted_labels=self.indicator_unwanted_labels,
            )

            bundle_builder = IndicatorBundleBuilder(self.helper, bundle_builder_config)
            indicator_bundle_built = bundle_builder.build()
            if indicator_bundle_built:
                return indicator_bundle_built.get("indicator_bundle")
            else:
                self.helper.connector_logger.warning(
                    "[WARNING] The construction of the indicator and all related entities has been skipped.",
                    {
                        "indicator_id": indicator.get("id"),
                        "indicator_type": indicator.get("type"),
                    },
                )
                return None
        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] An unexpected error occurred when creating a bundle indicator.",
                {
                    "error": err,
                    "indicator_id": indicator.get("id"),
                },
            )
            raise
