# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike rules YARA master importer module."""

import zipfile
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List, Mapping, Optional

from crowdstrike_client.api.intel import Reports, Rules
from crowdstrike_client.api.models.download import Download

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper

from stix2 import Bundle, Identity, MarkingDefinition

from crowdstrike.report_fetcher import FetchedReport, ReportFetcher
from crowdstrike.utils import datetime_to_timestamp, timestamp_to_datetime
from crowdstrike.yara_rule_bundle_builder import YaraRuleBundleBuilder
from crowdstrike.yara_rules_parser import YaraParser, YaraRule


class RulesYaraMasterImporter:
    """CrowdStrike rules YARA master importer."""

    _E_TAG = "yara_master_e_tag"
    _LAST_MODIFIED = "yara_master_last_modified"

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
        """Initialize CrowdStrike rules YARA master importer."""
        self.helper = helper
        self.rules_api = rules_api
        self.report_fetcher = ReportFetcher(reports_api)
        self.author = author
        self.tlp_marking = tlp_marking
        self.update_existing_data = update_existing_data
        self.report_status = report_status
        self.report_type = report_type

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self._info("Running YARA master importer with state: {0}...", state)

        self._clear_report_fetcher_cache()

        e_tag = state.get(self._E_TAG)

        last_modified = state.get(self._LAST_MODIFIED)
        if last_modified is not None:
            last_modified = timestamp_to_datetime(last_modified)

        download = self._download_yara_master(e_tag, last_modified)
        self._process_content(download.content)

        latest_e_tag = download.e_tag
        latest_last_modified = download.last_modified

        self._info(
            "YARA master importer completed, latest download {0} ({1}).",
            latest_last_modified,
            latest_e_tag,
        )

        new_state: Dict[str, Any] = {}

        if latest_e_tag is not None:
            new_state[self._E_TAG] = latest_e_tag

        if latest_last_modified is not None:
            new_state[self._LAST_MODIFIED] = datetime_to_timestamp(latest_last_modified)

        return new_state

    def _clear_report_fetcher_cache(self) -> None:
        self.report_fetcher.clear_cache()

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

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
        yara_master_name = "crowdstrike_intel_yara.yara"
        with zipfile.ZipFile(compressed_content) as z:
            with z.open(yara_master_name) as yara_master:
                return yara_master.read().decode("utf-8")

    @staticmethod
    def _parse_yara_rules(yara_rules: str) -> List[YaraRule]:
        return YaraParser.parse(yara_rules)

    def _process_rules(self, rules: List[YaraRule]) -> None:
        rule_count = len(rules)
        self._info("Processing {0} YARA rules...", rule_count)

        failed = 0
        for rule in rules:
            result = self._process_rule(rule)
            if not result:
                failed += 1

        imported = rule_count - failed
        total = imported + failed

        self._info(
            "Processing rules completed (imported: {0}, failed: {1}, total: {2})",
            imported,
            failed,
            total,
        )

    def _process_rule(self, rule: YaraRule) -> bool:
        self._info("Processing YARA rule '{0}'...", rule.name)

        reports = self._get_reports_by_code(rule.reports)

        indicator_bundle = self._create_indicator_bundle(rule, reports)
        if indicator_bundle is None:
            self._error("Discarding '{0}' YARA indicator bundle", rule.name)
            return False

        self._send_bundle(indicator_bundle)

        return True

    def _get_reports_by_code(self, codes: List[str]) -> List[FetchedReport]:
        return self.report_fetcher.get_by_codes(codes)

    def _create_indicator_bundle(
        self, rule: YaraRule, reports: List[FetchedReport]
    ) -> Optional[Bundle]:
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

    def _source_name(self) -> str:
        return self.helper.connect_name

    def _confidence_level(self) -> int:
        return self.helper.connect_confidence_level

    def _send_bundle(self, bundle: Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle, None, self.update_existing_data, False
        )
