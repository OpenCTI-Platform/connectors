"""OpenCTI Cybersixgill importer module."""

from datetime import datetime
from typing import Any, Dict, NamedTuple, Optional

import stix2
from cybersixgill.builder import IndicatorBundleBuilder, IndicatorBundleBuilderConfig
from cybersixgill.client import CybersixgillClient
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from stix2.exceptions import STIXError


class IndicatorImporterConfig(NamedTuple):
    """Cybersixgill Indicator importer configuration."""

    helper: OpenCTIConnectorHelper
    client: CybersixgillClient
    author: stix2.Identity
    create_observables: bool
    create_indicators: bool
    update_existing_data: bool
    enable_relationships: bool
    fetch_size: int


class IndicatorImporter:
    """Cybersixgill indicator importer."""

    _LATEST_INDICATOR_TIMESTAMP = "latest_pulse_timestamp"

    _STATE_UPDATE_INTERVAL_COUNT = 20

    def __init__(
        self,
        config: IndicatorImporterConfig,
    ) -> None:
        """Initialize Cybersixgill indicator importer."""
        self.helper = config.helper
        self.client = config.client
        self.author = config.author
        self.create_observables = config.create_observables
        self.create_indicators = config.create_indicators
        self.update_existing_data = config.update_existing_data
        self.enable_relationships = config.enable_relationships
        self.limit = config.fetch_size

        self.work_id: Optional[str] = None

    def run(self, state: Dict[str, Any], work_id: str) -> Dict[str, Any]:
        """Run importer."""
        self.work_id = work_id

        self._info("Running indicator importer with state: {0}...", state)

        self._info("Fetching Cybersixgill Darkfeed data...")
        feed_data = self._fetch_darkfeed_data()
        feed_count = len(feed_data)

        failed = 0
        new_state = state.copy()

        global latest_indicator_modified_datetime

        for count, indicator in enumerate(feed_data, start=1):
            result = self._process_indicator(indicator)

            if not result:
                failed += 1
            latest_indicator_modified_datetime = indicator.get("modified")

            if count % self._STATE_UPDATE_INTERVAL_COUNT == 0:  # noqa: S001
                self._info(
                    "Store state: {0}: {1}", count, latest_indicator_modified_datetime
                )
                new_state.update(
                    self._create_pulse_state(latest_indicator_modified_datetime)
                )
                self._set_state(new_state)

        imported = feed_count - failed

        self._info(
            "Indicator importer completed (imported: {0}, failed: {1}, total: {2}), latest fetch {3}",  # noqa: E501
            imported,
            failed,
            feed_count,
            latest_indicator_modified_datetime,
        )

        return self._create_pulse_state(
            datetime.strptime(
                latest_indicator_modified_datetime, "%Y-%m-%dT%H:%M:%S.%fZ"
            )
        )

    def _create_pulse_state(
        self, latest_indicator_timestamp: datetime
    ) -> Dict[str, Any]:
        return {
            self._LATEST_INDICATOR_TIMESTAMP: latest_indicator_timestamp.isoformat()
        }

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

    def _fetch_darkfeed_data(self):
        df_data = self.client.get_darkfeed_data()
        return self._filter_darkfeed_data(df_data)

    def _filter_darkfeed_data(self, df_data):

        for indicator in df_data:
            post_id = (
                f"https://portal.cybersixgill.com/#/search?dateRange=01%2F01%2F1990-now&q=_id:{indicator.get('sixgill_postid', '')}"
                if indicator.get("sixgill_postid")
                else ""
            )
            indicators_list, indicator_type = self.client.get_sixgill_pattern_type(
                indicator
            )

            indicator["final_indicator_type"] = indicator_type

            indicator["indicators"] = indicators_list
            indicator["postid_link"] = post_id
            indicator.pop("object_marking_refs")

        return df_data

    def _process_indicator(self, indicator):
        # self._info(
        #     "Processing indicator of {0} ({1} indicators) ({2})",
        #     indicator.name,
        #     len(indicator.get('indicators')),
        #     indicator.get('id'),
        # )

        indicator_bundle = self._create_indicator_bundle(indicator)
        if indicator_bundle is None:
            return False

        self._send_bundle(indicator_bundle)

        return True

    def _create_indicator_bundle(self, indicator) -> Optional[stix2.Bundle]:
        config = IndicatorBundleBuilderConfig(
            indicator=indicator,
            provider=self.author,
            source_name=self._source_name(),
            create_observables=self.create_observables,
            create_indicators=self.create_indicators,
            confidence_level=self._confidence_level(),
            enable_relationships=self.enable_relationships,
        )

        bundle_builder = IndicatorBundleBuilder(config)

        try:
            return bundle_builder.build()
        except STIXError as e:
            self._error(
                "Failed to build pulse bundle for '{0}' ({1}): {2}",
                indicator.get("name"),
                indicator.get("id"),
                e,
            )
            return None

    def _source_name(self) -> str:
        return self.helper.connect_name

    def _confidence_level(self) -> int:
        return self.helper.connect_confidence_level

    def _set_state(self, state: Dict[str, Any]) -> None:
        self.helper.set_state(state)

    def _send_bundle(self, bundle: stix2.Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle, update=self.update_existing_data, work_id=self.work_id
        )
