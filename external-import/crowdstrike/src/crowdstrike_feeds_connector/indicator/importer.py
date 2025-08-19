# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike indicator importer module."""

from typing import Any, Dict, Generator, Iterator, List, NamedTuple, Optional, Set

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
    no_file_trigger_import: bool


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
        self.no_file_trigger_import = config.no_file_trigger_import

        if not (self.create_observables or self.create_indicators):
            msg = "'create_observables' and 'create_indicators' false at the same time"
            raise ValueError(msg)

        self.report_fetcher = ReportFetcher(config.helper, self.no_file_trigger_import)

    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run importer."""
        self._info("Running indicator importer with state: {0}...", state)

        self._clear_report_fetcher_cache()

        fetch_timestamp = state.get(
            self._LATEST_INDICATOR_TIMESTAMP, self.default_latest_timestamp
        )

        new_state = state.copy()

        latest_indicator_updated_timestamp = None

        for indicators_batch in self._fetch_indicators_batched(fetch_timestamp):
            if not indicators_batch:
                break

            latest_indicator_updated_datetime = self._process_indicators(
                indicators_batch
            )

            if latest_indicator_updated_datetime is not None:
                latest_indicator_updated_timestamp = datetime_to_timestamp(
                    latest_indicator_updated_datetime
                )

                new_state[self._LATEST_INDICATOR_TIMESTAMP] = (
                    latest_indicator_updated_timestamp
                )
                self._set_state(new_state)

        latest_indicator_timestamp = (
            latest_indicator_updated_timestamp or fetch_timestamp
        )

        self._info(
            "Indicator importer completed, latest fetch {0}.",
            timestamp_to_datetime(latest_indicator_timestamp),
        )

        return {self._LATEST_INDICATOR_TIMESTAMP: latest_indicator_timestamp}

    def _clear_report_fetcher_cache(self) -> None:
        self.report_fetcher.clear_cache()

    def _fetch_indicators_batched(
        self, fetch_timestamp: int
    ) -> Generator[List[Dict[str, Any]], None, None]:
        """Fetch indicators in batches with pagination support."""
        limit = 1000
        sort = "last_updated|asc"
        fql_filter = f"last_updated:>{fetch_timestamp}"

        if self.exclude_types:
            fql_filter = f"{fql_filter}+type:!{self.exclude_types}"

        current_batch = []
        batch_size = 1000  # Process in batches to match other importers

        for indicator in self._paginated_query_indicators(limit, sort, fql_filter):
            current_batch.append(indicator)

            if len(current_batch) >= batch_size:
                yield current_batch
                current_batch = []

        # Yield any remaining indicators
        if current_batch:
            yield current_batch

    def _paginated_query_indicators(
        self, limit: int, sort: str, fql_filter: str
    ) -> Iterator[Dict[str, Any]]:
        """Generator that yields indicators from all pages."""
        next_page_params = None
        total_fetched = 0

        while True:
            response = self._query_indicators_page(
                limit, sort, fql_filter, next_page_params
            )

            if not response or not response.get("resources"):
                break

            resources = response["resources"]
            batch_size = len(resources)
            total_fetched += batch_size

            # Log progress
            meta = response.get("meta", {})
            pagination = meta.get("pagination", {})
            total_available = pagination.get("total", 0)

            self.helper.connector_logger.info(
                "Fetched indicator batch",
                {
                    "batch_size": batch_size,
                    "total_fetched": total_fetched,
                    "total_available": total_available,
                    "remaining": max(0, total_available - total_fetched),
                },
            )

            # Yield each indicator
            yield from resources

            # Check for next page
            next_page_details = response.get("next_page_details")
            if not next_page_details:
                break

            next_page_params = next_page_details

    def _query_indicators_page(
        self,
        limit: int,
        sort: str,
        fql_filter: str,
        next_page_params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Query a single page of indicators from the CrowdStrike API."""
        next_page = None
        if next_page_params and "next_page" in next_page_params:
            next_page = (
                next_page_params["next_page"][0]
                if isinstance(next_page_params["next_page"], list)
                else next_page_params["next_page"]
            )

        response = self.indicators_api_cs.get_combined_indicator_entities(
            limit=limit,
            sort=sort,
            fql_filter=fql_filter,
            deep_pagination=True,
            next_page=next_page,
        )

        return response

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
            self._warning("Discarding indicator {0} bundle", indicator["id"])
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
        except TypeError as err:
            self.helper.connector_logger.warning(
                "Skipping unsupported indicator type.",
                {
                    "indicator_id": indicator.get("id"),
                    "indicator_type": indicator.get("type"),
                    "indicator_value": indicator.get("indicator"),
                    "error": str(err),
                },
            )
            return None
        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] An unexpected error occurred when creating a bundle indicator.",
                {
                    "error": err,
                    "indicator_id": indicator.get("id"),
                    "indicator_type": indicator.get("type"),
                },
            )
            raise
