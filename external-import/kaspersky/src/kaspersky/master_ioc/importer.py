"""Kaspersky Master IOC importer module."""

import itertools
from datetime import datetime
from typing import Any, List, Mapping, Optional, Set, Tuple

from kaspersky.client import KasperskyClient
from kaspersky.importer import BaseImporter
from kaspersky.master_ioc.builder import IndicatorGroupBundleBuilder
from kaspersky.models import OpenIOCCSV, OpenIOCCSVIndicator
from kaspersky.utils import (convert_openioc_csv_to_openioc_csv_model,
                             datetime_to_timestamp, datetime_utc_now,
                             is_current_weekday_before_datetime,
                             timestamp_to_datetime)
from pycti import OpenCTIConnectorHelper  # type: ignore
from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore
from stix2.exceptions import STIXError  # type: ignore


class MasterIOCImporter(BaseImporter):
    """Kaspersky Master IOC importer."""

    _LATEST_MASTER_IOC_TIMESTAMP = "latest_master_ioc_timestamp"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: KasperskyClient,
        author: Identity,
        tlp_marking: MarkingDefinition,
        create_observables: bool,
        create_indicators: bool,
        update_existing_data: bool,
        master_ioc_fetch_weekday: Optional[int],
        master_ioc_excluded_ioc_indicator_types: Set[str],
        master_ioc_report_type: str,
        master_ioc_report_status: int,
    ) -> None:
        """Initialize Kaspersky Master IOC importer."""
        super().__init__(helper, client, author, tlp_marking, update_existing_data)

        self.create_observables = create_observables
        self.create_indicators = create_indicators

        self.master_ioc_fetch_weekday = master_ioc_fetch_weekday
        self.master_ioc_excluded_ioc_indicator_types = (
            master_ioc_excluded_ioc_indicator_types
        )
        self.master_ioc_report_type = master_ioc_report_type
        self.master_ioc_report_status = master_ioc_report_status

        if not (self.create_observables or self.create_indicators):
            msg = "'create_observables' and 'create_indicators' false at the same time"
            raise ValueError(msg)

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self._info(
            "Running Kaspersky Master IOC importer (update data: {0})...",
            self.update_existing_data,
        )

        latest_master_ioc_timestamp = state.get(self._LATEST_MASTER_IOC_TIMESTAMP)
        if latest_master_ioc_timestamp is None:
            latest_master_ioc_datetime = None
        else:
            latest_master_ioc_datetime = timestamp_to_datetime(
                latest_master_ioc_timestamp
            )

        master_ioc_fetch_weekday = self.master_ioc_fetch_weekday
        if master_ioc_fetch_weekday is not None:
            if not is_current_weekday_before_datetime(
                master_ioc_fetch_weekday, latest_master_ioc_datetime
            ):
                self._info("It is not time to fetch the Master IOC yet.")
                return self._create_state(latest_master_ioc_datetime)

        openioc_csv = self._fetch_master_ioc()

        indicators = openioc_csv.indicators
        indicator_count = len(indicators)

        self._info(
            "Master IOC with {0} indicators...",
            indicator_count,
        )

        indicators = self._filter_indicators(indicators, latest_master_ioc_datetime)
        indicator_count = len(indicators)

        self._info(
            "{0} indicators after filtering...",
            indicator_count,
        )

        grouped_indicators = self._group_indicators_by_publication(indicators)
        group_count = len(grouped_indicators)

        self._info(
            "{0} indicator groups...",
            group_count,
        )

        failed_count = 0

        for indicator_group in grouped_indicators:
            result = self._process_indicator_group(indicator_group)
            if not result:
                failed_count += 1

        success_count = group_count - failed_count

        self._info(
            "Kaspersky Master IOC importer completed (imported: {0}, total: {1})",
            success_count,
            group_count,
        )

        return self._create_state(datetime_utc_now())

    @classmethod
    def _create_state(cls, latest_datetime: Optional[datetime]) -> Mapping[str, Any]:
        if latest_datetime is None:
            return {}

        return {
            cls._LATEST_MASTER_IOC_TIMESTAMP: datetime_to_timestamp(latest_datetime)
        }

    def _fetch_master_ioc(self) -> OpenIOCCSV:
        report_group = "apt"
        master_ioc = self.client.get_master_ioc(report_group)
        return convert_openioc_csv_to_openioc_csv_model(master_ioc)

    def _filter_indicators(
        self,
        indicators: List[OpenIOCCSVIndicator],
        latest_master_ioc_datetime: Optional[datetime],
    ) -> List[OpenIOCCSVIndicator]:
        filtered_indicators = self._filter_already_processed(
            indicators, latest_master_ioc_datetime
        )
        filtered_indicators = self._filter_excluded_indicator_types(filtered_indicators)
        return filtered_indicators

    def _filter_already_processed(
        self,
        indicators: List[OpenIOCCSVIndicator],
        latest_master_ioc_datetime: Optional[datetime],
    ) -> List[OpenIOCCSVIndicator]:
        if latest_master_ioc_datetime is None:
            return indicators

        latest_master_ioc_date = latest_master_ioc_datetime.date()

        def _processed_filter(indicator: OpenIOCCSVIndicator) -> bool:
            detection_date = indicator.detection_date.date()
            if detection_date < latest_master_ioc_date:
                self._info(
                    "Excluding already processed indicator '{0}' ({1}).",
                    indicator.indicator,
                    indicator.id,
                )
                return False
            else:
                return True

        return list(filter(_processed_filter, indicators))

    def _filter_excluded_indicator_types(
        self,
        indicators: List[OpenIOCCSVIndicator],
    ) -> List[OpenIOCCSVIndicator]:
        excluded_types = self.master_ioc_excluded_ioc_indicator_types

        def _exclude_indicator_types_filter(
            indicator: OpenIOCCSVIndicator,
        ) -> bool:
            indicator_type = indicator.indicator_type
            if indicator_type in excluded_types:
                self._info(
                    "Excluding indicator by type '{0}' ({1})",
                    indicator.indicator,
                    indicator_type,
                )
                return False
            else:
                return True

        return list(filter(_exclude_indicator_types_filter, indicators))

    @staticmethod
    def _group_indicators_by_publication(
        indicators: List[OpenIOCCSVIndicator],
    ) -> List[Tuple[str, List[OpenIOCCSVIndicator]]]:
        def _key_func(item: OpenIOCCSVIndicator) -> str:
            return item.publication

        groups = []
        sorted_indicators = sorted(indicators, key=_key_func)
        for key, group in itertools.groupby(sorted_indicators, key=_key_func):
            groups.append((key, list(group)))
        return groups

    def _process_indicator_group(
        self, indicator_group: Tuple[str, List[OpenIOCCSVIndicator]]
    ) -> bool:
        self._info("Processing indicator group {0}...", indicator_group[0])

        indicator_group_bundle = self._create_indicator_group_bundle(indicator_group)
        if indicator_group_bundle is None:
            return False

        # bundle_id = uuid5(indicator_group[0])
        # with open(f"indicator_group_bundle_{bundle_id}.json", "w") as f:
        #     f.write(indicator_group_bundle.serialize(pretty=True))

        self._send_bundle(indicator_group_bundle)

        return True

    def _create_indicator_group_bundle(
        self, indicator_group: Tuple[str, List[OpenIOCCSVIndicator]]
    ) -> Optional[Bundle]:
        author = self.author
        source_name = self._source_name()
        object_markings = [self.tlp_marking]
        create_observables = self.create_observables
        create_indicators = self.create_indicators
        confidence_level = self._confidence_level()
        report_type = self.master_ioc_report_type
        report_status = self.master_ioc_report_status

        bundle_builder = IndicatorGroupBundleBuilder(
            indicator_group[0],
            indicator_group[1],
            author,
            source_name,
            object_markings,
            create_observables,
            create_indicators,
            confidence_level,
            report_type,
            report_status,
        )

        try:
            return bundle_builder.build()
        except STIXError as e:
            self._error(
                "Failed to build indicator group bundle for '{0}': {1}",
                indicator_group[0],
                e,
            )
            return None
