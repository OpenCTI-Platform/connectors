# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike Snort master importer module."""

import itertools
import zipfile
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Tuple

from crowdstrike_feeds_services.client.rules import RulesAPI
from crowdstrike_feeds_services.utils import (
    datetime_to_timestamp,
    timestamp_to_datetime,
)
from crowdstrike_feeds_services.utils.report_fetcher import FetchedReport, ReportFetcher
from crowdstrike_feeds_services.utils.snort_parser import SnortParser, SnortRule
from pycti.connector.opencti_connector_helper import (  # type: ignore  # noqa: E501
    OpenCTIConnectorHelper,
)
from requests import RequestException
from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore
from stix2.exceptions import STIXError  # type: ignore

from ..importer import BaseImporter
from .snort_suricata_master_builder import SnortRuleBundleBuilder


class SnortMaster(NamedTuple):
    """Snort Master."""

    rules: List[SnortRule]
    e_tag: Optional[str]
    last_modified: Optional[datetime]


class SnortMasterImporter(BaseImporter):
    """CrowdStrike Snort master importer."""

    _E_TAG = "snort_master_e_tag"
    _LAST_MODIFIED = "snort_master_last_modified"

    _KEY_ID = "id"
    _KEY_INDICATOR_PATTERN = "pattern"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        tlp_marking: MarkingDefinition,
        update_existing_data: bool,
        report_status: int,
        report_type: str,
    ) -> None:
        """Initialize CrowdStrike Snort master importer."""
        super().__init__(helper, author, tlp_marking, update_existing_data)

        self.rules_api_cs = RulesAPI(helper)
        self.report_status = report_status
        self.report_type = report_type

        self.report_fetcher = ReportFetcher(helper)

    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run importer."""
        self._info("Running Snort master importer with state: {0}...", state)

        # Ignore the Etag, see the comment below.
        # e_tag = state.get(self._E_TAG)

        last_modified = state.get(self._LAST_MODIFIED)
        if last_modified is not None:
            last_modified = timestamp_to_datetime(last_modified)

        # XXX: Using Etag and Last-Modified results in HTTP 500.
        # snort_master = self._fetch_snort_master(e_tag, last_modified)
        snort_master = self._fetch_snort_master()

        latest_e_tag = snort_master.e_tag
        latest_last_modified = snort_master.last_modified

        if (
            last_modified is not None
            and latest_last_modified is not None
            and last_modified >= latest_last_modified
        ):
            self._info("Snort master not modified, skipping...")
            return state

        snort_rules = snort_master.rules
        snort_rule_count = len(snort_rules)

        self._info(
            "Snort master with {0} rules...",
            snort_rule_count,
        )

        new_snort_rules = self._update_existing(snort_rules)
        new_snort_rule_count = len(new_snort_rules)

        self._info(
            "{0} new Snort rules...",
            new_snort_rule_count,
        )

        grouped_snort_rules = self._group_snort_rules_by_report(new_snort_rules)
        group_count = len(grouped_snort_rules)

        self._info(
            "{0} Snort rule groups...",
            group_count,
        )

        for group, rules in grouped_snort_rules:
            self._info("Snort rule group: ({0}) {1}", len(rules), group)

        failed_count = 0

        for snort_rule_group in grouped_snort_rules:
            failed = self._process_snort_rule_group(snort_rule_group)
            failed_count += failed

        success_count = new_snort_rule_count - failed_count

        self._info(
            "Snort master importer completed (imported: {0}, total: {1}, e_tag: {2}, last_modified: {3})",  # noqa: E501
            success_count,
            new_snort_rule_count,
            latest_e_tag,
            latest_last_modified,
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

    def _fetch_snort_master(
        self, e_tag: Optional[str] = None, last_modified: Optional[datetime] = None
    ) -> SnortMaster:
        download = self._fetch_latest_snort_master(
            e_tag=e_tag, last_modified=last_modified
        )
        download_converted = BytesIO(download)
        return SnortMaster(
            rules=self._parse_download(download_converted),
            e_tag=None,
            last_modified=None,
        )

    def _fetch_latest_snort_master(
        self, e_tag: Optional[str] = None, last_modified: Optional[datetime] = None
    ):
        rule_set_type = "snort-suricata-master"
        return self.rules_api_cs.get_latest_rule_file(
            rule_set_type, e_tag=e_tag, last_modified=last_modified
        )

    def _parse_download(self, download) -> List[SnortRule]:
        snort_str = self._unzip_content(download)
        return self._parse_snort_rules(snort_str)

    @staticmethod
    def _unzip_content(compressed_content: BytesIO) -> str:
        snort_master_filename = "crowdstrike_intel_snort.rules"
        with zipfile.ZipFile(compressed_content) as z:
            with z.open(snort_master_filename) as snort_master:
                return snort_master.read().decode("utf-8")

    @staticmethod
    def _parse_snort_rules(snort_rules: str) -> List[SnortRule]:
        return SnortParser.parse(snort_rules)

    def _update_existing(self, snort_rules: List[SnortRule]) -> List[SnortRule]:
        """Update Snort rules if they already exists in the OpenCTI."""
        new_snort_rules = []

        updated = 0
        not_updated = 0

        for snort_rule in snort_rules:
            rule_updated = self._try_updating(snort_rule)
            if rule_updated is None:
                new_snort_rules.append(snort_rule)
            else:
                if rule_updated:
                    updated += 1
                else:
                    not_updated += 1

        existing = updated + not_updated

        self._info("Updated {0} of {1} existing Snort rules", updated, existing)

        return new_snort_rules

    def _try_updating(self, snort_rule: SnortRule) -> Optional[bool]:
        """Try updating Snort rule if it already exists in the OpenCTI."""
        name = snort_rule.name

        existing_rule = self._find_rule_by_name(name)
        if existing_rule is None:
            return None

        return self._update_if_needed(snort_rule, existing_rule)

    @staticmethod
    def _group_snort_rules_by_report(
        snort_rules: List[SnortRule],
    ) -> List[Tuple[str, List[SnortRule]]]:
        def _key_func(item: SnortRule) -> str:
            reports = item.reports
            if reports:
                sorted_reports = sorted(reports)
                return "_".join(sorted_reports)
            return ""

        groups = []
        sorted_snort_rules = sorted(snort_rules, key=_key_func)
        for key, group in itertools.groupby(sorted_snort_rules, key=_key_func):
            groups.append((key, list(group)))
        return groups

    def _process_snort_rule_group(
        self, snort_rule_group: Tuple[str, List[SnortRule]]
    ) -> int:
        group = snort_rule_group[0]
        self._info("Processing Snort rule group '{0}'...", group)

        snort_rules = snort_rule_group[1]
        total_count = len(snort_rules)

        failed_count = 0

        for snort_rule in snort_rules:
            fetched_reports = self._get_reports_by_code(snort_rule.reports)

            snort_rule_bundle = self._create_snort_rule_bundle(
                snort_rule, fetched_reports
            )
            if snort_rule_bundle is None:
                failed_count += 1

            # with open(f"snort_rule_bundle_{snort_rule.name}.json", "w") as f:
            #     f.write(snort_rule_bundle.serialize(pretty=True))

            self._send_bundle(snort_rule_bundle)

        success_count = total_count - failed_count

        self._info(
            "Completed processing Snort rule group '{0}' (imported: {1}, total: {2})",
            group,
            success_count,
            total_count,
        )

        return failed_count

    def _update_if_needed(
        self, new_rule: SnortRule, existing_rule: Tuple[str, SnortRule]
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

    def _find_rule_by_name(self, name: str) -> Optional[Tuple[str, SnortRule]]:
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

        rules = SnortParser.parse(indicator_pattern)

        if not rules:
            self._error("Indicator '{0}' pattern without Snort rules", name)
            return None

        if len(rules) > 1:
            self._error(
                "Indicator '{0}' pattern contains more than one Snort rules", name
            )
            return None

        return indicator_id, rules[0]

    def _fetch_indicator_by_name(self, name: str) -> Optional[Mapping[str, Any]]:
        values = [name]
        filters = {
            "mode": "and",
            "filters": [{"key": "name", "values": values, "operator": "eq"}],
            "filterGroups": [],
        }
        return self.helper.api.indicator.read(filters=filters)

    def _needs_updating(self, current_rule: SnortRule, new_rule: SnortRule) -> bool:
        if current_rule.name != new_rule.name:
            self._error(
                "Current ({0}) and new ({1}) Snort rules names do no match",
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
            input={"key": self._KEY_INDICATOR_PATTERN, "value": new_indicator_pattern},
        )
        if updated is None:
            return False
        return updated.get(self._KEY_ID) == indicator_id

    def _get_reports_by_code(self, codes: List[str]) -> List[FetchedReport]:
        try:
            return self.report_fetcher.get_by_codes(codes)
        except RequestException as e:
            self._error("Failed to fetch reports {0}: {1}", codes, e)
            return []

    def _create_snort_rule_bundle(
        self, rule: SnortRule, reports: List[FetchedReport]
    ) -> Optional[Bundle]:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        confidence_level = self._confidence_level()
        report_status = self.report_status
        report_type = self.report_type

        bundle_builder = SnortRuleBundleBuilder(
            rule,
            author,
            source_name,
            object_marking_refs,
            confidence_level,
            report_status,
            report_type,
            reports,
        )

        try:
            return bundle_builder.build()
        except STIXError as e:
            self._error(
                "Failed to build Snort rule bundle for '{0}': {1}",
                rule.name,
                e,
            )
            return None
