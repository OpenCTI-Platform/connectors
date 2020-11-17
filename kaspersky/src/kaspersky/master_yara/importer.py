"""Kaspersky Master YARA importer module."""

from typing import Any, Mapping, Optional

from pycti import OpenCTIConnectorHelper  # type: ignore

from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore
from stix2.exceptions import STIXError  # type: ignore

from kaspersky.client import KasperskyClient
from kaspersky.importer import BaseImporter
from kaspersky.master_yara.builder import YaraRuleBundleBuilder
from kaspersky.models import Yara, YaraRule
from kaspersky.utils import (
    YaraRuleUpdater,
    convert_yara_rules_to_yara_model,
    datetime_to_timestamp,
    datetime_utc_now,
    is_current_weekday_before_datetime,
    timestamp_to_datetime,
)


class MasterYaraImporter(BaseImporter):
    """Kaspersky Master YARA importer."""

    _LATEST_MASTER_YARA_TIMESTAMP = "latest_master_yara_timestamp"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: KasperskyClient,
        author: Identity,
        tlp_marking: MarkingDefinition,
        update_existing_data: bool,
        master_yara_fetch_weekday: Optional[int],
        master_yara_report_type: str,
        master_yara_report_status: int,
    ) -> None:
        """Initialize Kaspersky Master YARA importer."""
        super().__init__(helper, client, author, tlp_marking, update_existing_data)

        self.master_yara_fetch_weekday = master_yara_fetch_weekday
        self.master_yara_report_type = master_yara_report_type
        self.master_yara_report_status = master_yara_report_status

        self.yara_rule_updater = YaraRuleUpdater(self.helper)

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self._info(
            "Running Kaspersky Master YARA importer (update data: {0})...",
            self.update_existing_data,
        )

        latest_master_yara_timestamp = state.get(self._LATEST_MASTER_YARA_TIMESTAMP)
        if latest_master_yara_timestamp is None:
            latest_master_yara_datetime = None
        else:
            latest_master_yara_datetime = timestamp_to_datetime(
                latest_master_yara_timestamp
            )

        master_yara_fetch_weekday = self.master_yara_fetch_weekday
        if master_yara_fetch_weekday is not None:
            if not is_current_weekday_before_datetime(
                master_yara_fetch_weekday, latest_master_yara_datetime
            ):
                self._info("It is not time to fetch the Master YARA yet.")
                return state

        yara = self._fetch_master_yara()

        yara_rules = yara.rules
        yara_rule_count = len(yara_rules)

        self._info(
            "Master YARA with {0} rules...",
            yara_rule_count,
        )

        new_yara_rules = self.yara_rule_updater.update_existing(yara.rules)
        new_yara_rule_count = len(new_yara_rules)

        self._info(
            "{0} new YARA rules...",
            new_yara_rule_count,
        )

        failed_count = 0

        for yara_rule in new_yara_rules:
            result = self._process_yara_rule(yara_rule)
            if not result:
                failed_count += 1

        success_count = new_yara_rule_count - failed_count

        self._info(
            "Kaspersky Master YARA importer completed (imported: {0}, total: {1})",
            success_count,
            new_yara_rule_count,
        )

        return {
            self._LATEST_MASTER_YARA_TIMESTAMP: datetime_to_timestamp(
                datetime_utc_now()
            )
        }

    def _fetch_master_yara(self) -> Yara:
        report_group = "apt"
        master_yara = self.client.get_master_yara(report_group)
        return convert_yara_rules_to_yara_model(master_yara, imports_at_top=True)

    def _process_yara_rule(self, yara_rule: YaraRule) -> bool:
        self._info("Processing YARA rule {0}...", yara_rule.name)

        yara_rule_bundle = self._create_yara_rule_bundle(yara_rule)
        if yara_rule_bundle is None:
            return False

        # bundle_id = uuid5(yara_rule.name)
        # with open(f"yara_rule_bundle_{bundle_id}.json", "w") as f:
        #     f.write(yara_rule_bundle.serialize(pretty=True))

        self._send_bundle(yara_rule_bundle)

        return True

    def _create_yara_rule_bundle(self, yara_rule: YaraRule) -> Optional[Bundle]:
        author = self.author
        object_markings = [self.tlp_marking]
        source_name = self._source_name()
        confidence_level = self._confidence_level()
        report_type = self.master_yara_report_type
        report_status = self.master_yara_report_status

        bundle_builder = YaraRuleBundleBuilder(
            yara_rule,
            author,
            object_markings,
            source_name,
            confidence_level,
            report_type,
            report_status,
        )

        try:
            return bundle_builder.build()
        except STIXError as e:
            self._error(
                "Failed to build YARA rule bundle for '{0}': {1}",
                yara_rule.name,
                e,
            )
            return None
