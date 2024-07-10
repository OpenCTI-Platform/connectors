# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike report importer module."""

from datetime import datetime
from typing import Any, Dict, Generator, List, Mapping, Optional

from crowdstrike_feeds_services.client.reports import ReportsAPI
from crowdstrike_feeds_services.utils import (
    create_file_from_download,
    datetime_to_timestamp,
    paginate,
    timestamp_to_datetime,
)
from pycti.connector.opencti_connector_helper import (  # type: ignore  # noqa: E501
    OpenCTIConnectorHelper,
)
from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore

from ..importer import BaseImporter
from .builder import ReportBundleBuilder


class ReportImporter(BaseImporter):
    """CrowdStrike report importer."""

    _LATEST_REPORT_TIMESTAMP = "latest_report_timestamp"

    _GUESS_NOT_A_MALWARE = "GUESS_NOT_A_MALWARE"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        update_existing_data: bool,
        author: Identity,
        default_latest_timestamp: int,
        tlp_marking: MarkingDefinition,
        include_types: List[str],
        report_status: int,
        report_type: str,
        guess_malware: bool,
    ) -> None:
        """Initialize CrowdStrike report importer."""
        super().__init__(helper, author, tlp_marking, update_existing_data)

        self.reports_api_cs = ReportsAPI(helper)
        self.default_latest_timestamp = default_latest_timestamp
        self.include_types = include_types
        self.report_status = report_status
        self.report_type = report_type
        self.guess_malware = guess_malware

        self.malware_guess_cache: Dict[str, str] = {}

    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run importer."""
        self._info(
            "Running report importer (update data: {0}, guess malware: {1}) with state: {2}...",  # noqa: E501
            self.update_existing_data,
            self.guess_malware,
            state,
        )

        self._clear_malware_guess_cache()

        fetch_timestamp = state.get(
            self._LATEST_REPORT_TIMESTAMP, self.default_latest_timestamp
        )

        new_state = state.copy()

        latest_report_created_timestamp = None

        for reports_batch in self._fetch_reports(fetch_timestamp):
            if not reports_batch:
                break

            latest_report_created_datetime = self._process_reports(reports_batch)

            if latest_report_created_datetime is not None:
                latest_report_created_timestamp = datetime_to_timestamp(
                    latest_report_created_datetime
                )

                new_state[self._LATEST_REPORT_TIMESTAMP] = (
                    latest_report_created_timestamp
                )
                self._set_state(new_state)

        latest_report_timestamp = latest_report_created_timestamp or fetch_timestamp

        self._info(
            "Report importer completed, latest fetch {0}.",
            timestamp_to_datetime(latest_report_timestamp),
        )

        return {self._LATEST_REPORT_TIMESTAMP: latest_report_timestamp}

    def _clear_malware_guess_cache(self):
        self.malware_guess_cache.clear()

    def _fetch_reports(self, start_timestamp: int) -> Generator[List, None, None]:
        limit = 30
        sort = "created_date|asc"
        fields = ["__full__"]

        fql_filter = f"created_date:>{start_timestamp}"

        if self.include_types:
            fql_filter = f"{fql_filter}+type:{self.include_types}"

        paginated_query = paginate(self._query_report_entities)

        return paginated_query(
            limit=limit, sort=sort, fql_filter=fql_filter, fields=fields
        )

    def _query_report_entities(
        self,
        limit: int = 10,
        offset: int = 0,
        sort: Optional[str] = None,
        fql_filter: Optional[str] = None,
        fields: Optional[List[str]] = None,
    ) -> dict:
        self._info(
            "Query reports limit: {0}, offset: {1}, sort: {2}, filter: {3}, fields: {4}",  # noqa: E501
            limit,
            offset,
            sort,
            fql_filter,
            fields,
        )
        reports = self.reports_api_cs.get_combined_report_entities(
            limit=limit, offset=offset, sort=sort, fql_filter=fql_filter, fields=fields
        )

        return reports

    def _process_reports(self, reports: List) -> Optional[datetime]:
        report_count = len(reports)
        self._info("Processing {0} reports...", report_count)

        latest_created_datetime = None

        for report in reports:
            self._process_report(report)

            created_date = report["created_date"]
            if created_date is None:
                self._error(
                    "Missing created date for report {0} ({1})",
                    report["name"],
                    report["id"],
                )
                continue

            if (
                latest_created_datetime is None
                or created_date > latest_created_datetime
            ):
                latest_created_datetime = created_date

        self._info(
            "Processing reports completed (imported: {0}, latest: {1})",
            report_count,
            latest_created_datetime,
        )

        return timestamp_to_datetime(latest_created_datetime)

    def _process_report(self, report) -> None:
        self._info("Processing report {0} ({1})...", report["name"], report["id"])

        report_file = self._get_report_pdf(report["id"], report["name"])
        report_bundle = self._create_report_bundle(report, report_file)

        # with open(f"report_bundle_{report.id}.json", "w") as f:
        #     f.write(report_bundle.serialize(pretty=True))
        self._send_bundle(report_bundle)

    def _get_report_pdf(
        self, report_id: int, report_name: str
    ) -> Optional[Mapping[str, str]]:
        self._info("Fetching report PDF for {0}...", report_id)

        download = self.reports_api_cs.get_report_pdf(str(report_id))

        if type(download) is dict:
            self._info("No report PDF for id '%s'", report_id)
            return None
        else:
            return create_file_from_download(download, report_name)

    def _create_report_bundle(
        self, report, report_file: Optional[Mapping[str, str]] = None
    ) -> Bundle:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        report_status = self.report_status
        report_type = self.report_type
        confidence_level = self._confidence_level()
        guessed_malwares: Mapping[str, str] = {}

        tags = report["tags"]
        if tags is not None:
            guessed_malwares = self._guess_malwares_from_tags(tags)

        bundle_builder = ReportBundleBuilder(
            report,
            author,
            source_name,
            object_marking_refs,
            report_status,
            report_type,
            confidence_level,
            guessed_malwares,
            report_file,
        )
        return bundle_builder.build()

    def _guess_malwares_from_tags(self, tags: List) -> Mapping[str, str]:
        if not self.guess_malware:
            return {}

        malwares = {}
        for tag in tags:
            name = tag["value"]
            if name is None or not name:
                continue

            guess = self.malware_guess_cache.get(name)
            if guess is None:
                guess = self._GUESS_NOT_A_MALWARE

                standard_id = self._fetch_malware_standard_id_by_name(name)
                if standard_id is not None:
                    guess = standard_id

                self.malware_guess_cache[name] = guess

            if guess == self._GUESS_NOT_A_MALWARE:
                self._info("Tag '{0}' does not reference malware", name)
            else:
                self._info("Tag '{0}' references malware '{1}'", name, guess)
                malwares[name] = guess
        return malwares

    def _fetch_malware_standard_id_by_name(self, name: str) -> Optional[str]:
        filters_list = [
            self._create_filter("name", name),
            self._create_filter("aliases", name),
        ]
        for _filter in filters_list:
            malwares = self.helper.api.malware.list(filters=_filter)
            if malwares:
                if len(malwares) > 1:
                    self._info("More then one malware for '{0}'", name)
                malware = malwares[0]
                return malware["standard_id"]
        return None

    @staticmethod
    def _create_filter(key: str, value: str):
        return {
            "mode": "and",
            "filters": [{"key": key, "values": [value]}],
            "filterGroups": [],
        }
