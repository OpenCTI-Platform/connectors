# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike report importer module."""

from typing import Any, Dict, Generator, List, Mapping, Optional

from crowdstrike_client.api.intel import Reports
from crowdstrike_client.api.models import Response
from crowdstrike_client.api.models.base import Entity
from crowdstrike_client.api.models.report import Report

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper  # type: ignore  # noqa: E501

from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore

from crowdstrike.report.builder import ReportBundleBuilder
from crowdstrike.utils import (
    create_file_from_download,
    datetime_to_timestamp,
    paginate,
    timestamp_to_datetime,
)


class ReportImporter:
    """CrowdStrike report importer."""

    _LATEST_REPORT_TIMESTAMP = "latest_report_timestamp"

    _GUESS_NOT_A_MALWARE = "GUESS_NOT_A_MALWARE"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        reports_api: Reports,
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
        self.helper = helper
        self.reports_api = reports_api
        self.update_existing_data = update_existing_data
        self.author = author
        self.default_latest_timestamp = default_latest_timestamp
        self.tlp_marking = tlp_marking
        self.include_types = include_types
        self.report_status = report_status
        self.report_type = report_type
        self.guess_malware = guess_malware

        self.malware_guess_cache: Dict[str, str] = {}

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
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

        latest_fetched_report_timestamp = None

        for reports_batch in self._fetch_reports(fetch_timestamp):
            if not reports_batch:
                break

            if latest_fetched_report_timestamp is None:
                first_in_batch = reports_batch[0]

                created_date = first_in_batch.created_date
                if created_date is None:
                    self._error(
                        "Missing created date for report {0} ({1})",
                        first_in_batch.name,
                        first_in_batch.id,
                    )
                    break

                latest_fetched_report_timestamp = datetime_to_timestamp(created_date)

            self._process_reports(reports_batch)

        state_timestamp = latest_fetched_report_timestamp or fetch_timestamp

        self._info(
            "Report importer completed, latest fetch {0}.",
            timestamp_to_datetime(state_timestamp),
        )

        return {self._LATEST_REPORT_TIMESTAMP: state_timestamp}

    def _clear_malware_guess_cache(self):
        self.malware_guess_cache.clear()

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

    def _fetch_reports(
        self, start_timestamp: int
    ) -> Generator[List[Report], None, None]:
        limit = 30
        sort = "created_date|desc"
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
    ) -> Response[Report]:
        self._info(
            "Query reports limit: {0}, offset: {1}, sort: {2}, filter: {3}, fields: {4}",  # noqa: E501
            limit,
            offset,
            sort,
            fql_filter,
            fields,
        )

        return self.reports_api.query_entities(
            limit=limit, offset=offset, sort=sort, fql_filter=fql_filter, fields=fields
        )

    def _process_reports(self, reports: List[Report]) -> None:
        report_count = len(reports)
        self._info("Processing {0} reports...", report_count)

        for report in reports:
            self._process_report(report)

        self._info("Processing reports completed (imported: {0})", report_count)

    def _process_report(self, report: Report) -> None:
        self._info("Processing report {0} ({1})...", report.name, report.id)

        report_file = self._get_report_pdf(report.id)
        report_bundle = self._create_report_bundle(report, report_file)

        # with open(f"report_bundle_{report.id}.json", "w") as f:
        #     f.write(report_bundle.serialize(pretty=True))

        self._send_bundle(report_bundle)

    def _get_report_pdf(self, report_id: int) -> Optional[Mapping[str, str]]:
        self._info("Fetching report PDF for {0}...", report_id)

        download = self.reports_api.get_pdf(str(report_id))
        if download is None:
            self._info("No report PDF for {0}q", report_id)
            return None

        return create_file_from_download(download)

    def _create_report_bundle(
        self, report: Report, report_file: Optional[Mapping[str, str]] = None
    ) -> Bundle:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        report_status = self.report_status
        report_type = self.report_type
        confidence_level = self._confidence_level()
        guessed_malwares: Mapping[str, str] = {}

        tags = report.tags
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

    def _guess_malwares_from_tags(self, tags: List[Entity]) -> Mapping[str, str]:
        if not self.guess_malware:
            return {}

        malwares = {}
        for tag in tags:
            name = tag.value
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
        filters = [
            self._create_filter("name", name),
            self._create_filter("aliases", name),
        ]
        for _filter in filters:
            malwares = self.helper.api.malware.list(filters=_filter)
            if malwares:
                if len(malwares) > 1:
                    self._info("More then one malware for '{0}'", name)
                malware = malwares[0]
                return malware["standard_id"]
        return None

    @staticmethod
    def _create_filter(key: str, value: str) -> List[Mapping[str, Any]]:
        return [{"key": key, "values": [value]}]

    def _source_name(self) -> str:
        return self.helper.connect_name

    def _confidence_level(self) -> int:
        return self.helper.connect_confidence_level

    def _send_bundle(self, bundle: Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle, None, self.update_existing_data, False
        )
