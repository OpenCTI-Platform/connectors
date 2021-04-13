# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike YARA master importer module."""

import zipfile
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List, Mapping, Optional, Tuple

from crowdstrike_client.api.intel import Reports, Rules
from crowdstrike_client.api.models.download import Download

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper  # type: ignore  # noqa: E501

from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore

from crowdstrike.importer import BaseImporter
from crowdstrike.utils.report_fetcher import FetchedReport, ReportFetcher
from crowdstrike.utils import datetime_to_timestamp, timestamp_to_datetime
from crowdstrike.rule.yara_master_builder import YaraRuleBundleBuilder
from crowdstrike.utils.yara_parser import YaraParser, YaraRule


class YaraMasterImporter(BaseImporter):
    """CrowdStrike YARA master importer."""

    _E_TAG = "yara_master_e_tag"
    _LAST_MODIFIED = "yara_master_last_modified"

    _KEY_ID = "id"
    _KEY_INDICATOR_PATTERN = "pattern"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        rules_api: Rules,
        reports_api: Reports,
        author: Identity,
        tlp_marking: MarkingDefinition,
        update_existing_data: bool,
        report_status: int,
        report_type: str,
    ) -> None:
        """Initialize CrowdStrike YARA master importer."""
        super().__init__(helper, author, tlp_marking, update_existing_data)

        self.rules_api = rules_api
        self.report_status = report_status
        self.report_type = report_type

        self.report_fetcher = ReportFetcher(reports_api)

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self._info("Running YARA master importer with state: {0}...", state)

        # Ignore the Etag, see the comment below.
        # e_tag = state.get(self._E_TAG)

        last_modified = state.get(self._LAST_MODIFIED)
        if last_modified is not None:
            last_modified = timestamp_to_datetime(last_modified)

        # TODO: CrowdStrike Etag and Last-Modified fails with HTTP 500.
        # download = self._download_yara_master(e_tag, last_modified)
        download = self._download_yara_master()

        latest_e_tag = download.e_tag
        latest_last_modified = download.last_modified

        if last_modified is None or (
            last_modified is not None
            and latest_last_modified is not None
            and latest_last_modified > last_modified
        ):
            self._process_content(download.content)
        else:
            self._info("YARA master not modified, skipping...")

        self._info(
            "YARA master importer completed, latest download {0} ({1}).",
            latest_last_modified,
            latest_e_tag,
        )

        self._clear_report_fetcher_cache()

        new_state: Dict[str, Any] = {}

        if latest_e_tag is not None:
            new_state[self._E_TAG] = latest_e_tag

        if latest_last_modified is not None:
            new_state[self._LAST_MODIFIED] = datetime_to_timestamp(latest_last_modified)

        return new_state

    def _clear_report_fetcher_cache(self) -> None:
        self._info("Clearing report fetcher cache...")
        self.report_fetcher.clear_cache()

    def _download_yara_master(
        self, e_tag: Optional[str] = None, last_modified: Optional[datetime] = None
    ) -> Download:
        rule_set_type = "yara-master"
        return self.rules_api.get_latest_file(
            rule_set_type, e_tag=e_tag, last_modified=last_modified
        )

    def _process_content(self, compressed_content: BytesIO) -> None:
        yara_rules = self._unzip_content(compressed_content)
        rules = self._parse_yara_rules(yara_rules)
        self._process_rules(rules)

    @staticmethod
    def _unzip_content(compressed_content: BytesIO) -> str:
        yara_master_filename = "crowdstrike_intel_yara.yara"
        with zipfile.ZipFile(compressed_content) as z:
            with z.open(yara_master_filename) as yara_master:
                return yara_master.read().decode("utf-8")

    @staticmethod
    def _parse_yara_rules(yara_rules: str) -> List[YaraRule]:
        return YaraParser.parse(yara_rules)

    def _process_rules(self, rules: List[YaraRule]) -> None:
        rule_count = len(rules)
        self._info("Processing {0} YARA rules...", rule_count)

        failed = 0
        updated = 0
        not_updated = 0

        for rule in rules:
            rule_name = rule.name

            existing_rule = self._find_rule_by_name(rule_name)
            if existing_rule is not None:
                existing_rule_updated = self._update_if_needed(rule, existing_rule)
                if existing_rule_updated:
                    updated += 1
                else:
                    not_updated += 1
            else:
                result = self._process_rule(rule)
                if not result:
                    failed += 1

        existing = updated + not_updated
        imported = rule_count - failed - existing
        total = existing + imported + failed

        self._info(
            "Processing rules completed (imported: {0}, updated: {1} of {2}, failed: {3}, total: {4})",  # noqa: E501
            imported,
            updated,
            existing,
            failed,
            total,
        )

    def _process_rule(self, rule: YaraRule) -> bool:
        self._info("Processing YARA rule '{0}'...", rule.name)

        reports = self._get_reports_by_code(rule.reports)

        indicator_bundle = self._create_indicator_bundle(rule, reports)

        self._send_bundle(indicator_bundle)

        return True

    def _update_if_needed(
        self, new_rule: YaraRule, existing_rule: Tuple[str, YaraRule]
    ) -> bool:
        new_rule_name = new_rule.name
        indicator_id, current_rule = existing_rule
        if self._needs_updating(current_rule, new_rule):
            updated = self._update_indicator_pattern(indicator_id, new_rule.rule)
            if updated:
                self._info("Rule '{0}' ({1}) updated", new_rule_name, indicator_id)
            else:
                self._error("Rule '{0}' ({1}) not updated", new_rule_name, indicator_id)
            return updated
        else:
            self._info("Not updating rule '{0}' ({1})", new_rule_name, indicator_id)
            return False

    def _find_rule_by_name(self, name: str) -> Optional[Tuple[str, YaraRule]]:
        indicator = self._fetch_indicator_by_name(name)
        if indicator is None:
            return None

        indicator_id = indicator.get(self._KEY_ID)
        if indicator_id is None or not indicator_id:
            self._error("Indicator '{0}' without ID", name)
            return None

        indicator_pattern = indicator.get(self._KEY_INDICATOR_PATTERN)
        if indicator_pattern is None or not indicator_pattern:
            self._error("Indicator '{0}' without pattern", name)
            return None

        rules = YaraParser.parse(indicator_pattern)

        if not rules:
            self._error("Indicator '{0}' pattern without YARA rules", name)
            return None

        if len(rules) > 1:
            self._error(
                "Indicator '{0}' pattern contains more than one YARA rules", name
            )
            return None

        return indicator_id, rules[0]

    def _fetch_indicator_by_name(self, name: str) -> Optional[Mapping[str, Any]]:
        values = [name]
        filters = [{"key": "name", "values": values, "operator": "eq"}]
        return self.helper.api.indicator.read(filters=filters)

    def _needs_updating(self, current_rule: YaraRule, new_rule: YaraRule) -> bool:
        if current_rule.name != new_rule.name:
            self._error(
                "Current ({0}) and new ({1}) YARA rules names do no match",
                current_rule.name,
                new_rule.name,
            )
            return False

        self._info(
            "Current rule last modified '{0}, new rule last modified '{1}''",
            current_rule.last_modified,
            new_rule.last_modified,
        )

        if new_rule.last_modified > current_rule.last_modified:
            return True

        return False

    def _update_indicator_pattern(
        self, indicator_id: str, new_indicator_pattern: str
    ) -> bool:
        updated = self.helper.api.stix_domain_object.update_field(
            id=indicator_id,
            key=self._KEY_INDICATOR_PATTERN,
            value=new_indicator_pattern,
        )
        if updated is None:
            return False
        return updated.get(self._KEY_ID) == indicator_id

    def _get_reports_by_code(self, codes: List[str]) -> List[FetchedReport]:
        return self.report_fetcher.get_by_codes(codes)

    def _create_indicator_bundle(
        self, rule: YaraRule, reports: List[FetchedReport]
    ) -> Bundle:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        confidence_level = self._confidence_level()
        report_status = self.report_status
        report_type = self.report_type

        bundle_builder = YaraRuleBundleBuilder(
            rule,
            author,
            source_name,
            object_marking_refs,
            confidence_level,
            report_status,
            report_type,
            reports,
        )
        return bundle_builder.build()
