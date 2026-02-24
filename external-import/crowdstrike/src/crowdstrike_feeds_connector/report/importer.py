"""OpenCTI CrowdStrike report importer module."""

from collections.abc import Mapping as ABCMapping
from datetime import datetime
from typing import Any, Generator, List, Mapping, Optional, cast

from crowdstrike_feeds_connector.related_actors.importer import RelatedActorImporter
from crowdstrike_feeds_services.client.indicators import IndicatorsAPI
from crowdstrike_feeds_services.client.reports import ReportsAPI
from crowdstrike_feeds_services.utils import (
    create_file_from_download,
    datetime_to_timestamp,
    paginate,
    timestamp_to_datetime,
)
from pycti.connector.opencti_connector_helper import (  # noqa: E501
    OpenCTIConnectorHelper,
)
from stix2 import Bundle, Identity, MarkingDefinition
from stix2.v21 import _DomainObject

from ..importer import BaseImporter
from ..indicator.builder import IndicatorBundleBuilder
from ..indicator.importer import (
    IndicatorBundleBuilderConfig,  # pyright: ignore[reportPrivateImportUsage]
)
from .builder import ReportBundleBuilder


class ReportImporter(BaseImporter):
    """CrowdStrike report importer."""

    _NAME = "Report"

    _LATEST_REPORT_TIMESTAMP = "latest_report_timestamp"
    _GUESS_NOT_A_MALWARE = "__NOT_A_MALWARE__"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        default_latest_timestamp: int,
        tlp_marking: MarkingDefinition,
        include_types: List[str],
        target_industries: List[str],
        report_status: int,
        report_type: str,
        guess_malware: bool,
        report_guess_relations: bool,
        indicator_config: dict,
        no_file_trigger_import: bool,
        scopes: set[str],
    ) -> None:
        """Initialize CrowdStrike report importer."""
        super().__init__(helper, author, tlp_marking)

        self.reports_api_cs = ReportsAPI(helper)
        self.default_latest_timestamp = default_latest_timestamp
        self.include_types = include_types
        self.target_industries = target_industries
        self.report_status = report_status
        self.report_type = report_type
        self.guess_malware = guess_malware
        self.report_guess_relations = report_guess_relations
        self.indicators_api_cs = IndicatorsAPI(helper)
        self.indicator_config = indicator_config
        self.no_file_trigger_import = no_file_trigger_import
        self.scopes = scopes
        self.malware_guess_cache: dict[str, str] = {}

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        self._info(
            "Running report importer with state: {0}...",  # noqa: E501
            state,
        )

        raw_fetch_ts = state.get(
            self._LATEST_REPORT_TIMESTAMP, self.default_latest_timestamp
        )
        fetch_timestamp = (
            raw_fetch_ts
            if isinstance(raw_fetch_ts, int)
            else int(self.default_latest_timestamp)
        )

        new_state = state.copy()

        latest_report_modified_timestamp = None

        for reports_batch in self._fetch_reports(fetch_timestamp):
            if not reports_batch:
                break

            latest_report_modified_datetime = self._process_reports(reports_batch)

            if latest_report_modified_datetime is not None:
                latest_report_modified_timestamp = datetime_to_timestamp(
                    latest_report_modified_datetime
                )

                new_state[self._LATEST_REPORT_TIMESTAMP] = (
                    latest_report_modified_timestamp
                )
                self._set_state(new_state)

        latest_report_timestamp = latest_report_modified_timestamp or fetch_timestamp

        self._info(
            "Report importer completed, latest fetch {0}.",
            timestamp_to_datetime(latest_report_timestamp),
        )

        return {self._LATEST_REPORT_TIMESTAMP: latest_report_timestamp}

    def _fetch_reports(self, start_timestamp: int) -> Generator[List, None, None]:
        limit = 30
        sort = "last_modified_date|asc"
        fields = ["__full__"]

        fql_filter = f"last_modified_date:>{start_timestamp}"

        if self.include_types:
            fql_filter = f"{fql_filter}+type:{self.include_types}"

        if self.target_industries:
            fql_filter = f"{fql_filter}+target_industries:{self.target_industries}"

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
            limit=limit,
            offset=offset,
            sort=sort or "",
            fql_filter=fql_filter or "",
            fields=fields or ["__full__"],
        )

        return reports

    def _process_reports(self, reports: List) -> Optional[datetime]:
        report_count = len(reports)
        self._info("Processing {0} reports...", report_count)

        # Cache actor entities once per batch to avoid noisy per-report/per-actor updates.
        # RelatedActorImporter expects: Dict[str, Dict[str, Any]]
        batch_actor_cache: dict[str, dict[str, Any]] = {}
        for report in reports:
            for actor in report.get("actors") or []:
                actor_id = actor.get("id")
                actor_name = actor.get("name")
                if actor_id is None or not actor_name:
                    continue
                # Use string keys for consistency with the rest of the connector.
                batch_actor_cache[str(actor_id)] = {"id": actor_id, "name": actor_name}

        if batch_actor_cache:
            RelatedActorImporter._resolved_actor_entity_cache.update(batch_actor_cache)

        latest_modified_timestamp: Optional[int] = None

        for report in reports:
            self._process_report(report)

            last_modified_date = report.get("last_modified_date")
            if last_modified_date is None:
                self._error(
                    "Missing last modified date for report {0} ({1})",
                    report.get("name"),
                    report.get("id"),
                )
                continue

            # CrowdStrike usually returns timestamps here, but tolerate datetime too.
            if isinstance(last_modified_date, datetime):
                last_modified_ts = datetime_to_timestamp(last_modified_date)
            else:
                last_modified_ts = int(last_modified_date)

            if (
                latest_modified_timestamp is None
                or last_modified_ts > latest_modified_timestamp
            ):
                latest_modified_timestamp = last_modified_ts

        latest_modified_datetime = (
            timestamp_to_datetime(latest_modified_timestamp)
            if latest_modified_timestamp is not None
            else None
        )

        self._info(
            "Processing reports completed (imported: {0}, latest: {1})",
            report_count,
            latest_modified_datetime,
        )
        self.helper.connector_logger.debug(
            "Reports batch summary",
            {
                "count": report_count,
                "latest_modified_timestamp": latest_modified_timestamp,
                "cached_actor_ids": len(batch_actor_cache),
            },
        )

        return latest_modified_datetime

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

        # The CS API returns a dict when there is no PDF (or an error payload).
        if isinstance(download, dict):
            self._info("No report PDF for id {0}", report_id)
            return None

        created = create_file_from_download(
            download, report_name, self.no_file_trigger_import
        )

        if not isinstance(created, ABCMapping):
            return None

        return cast(Mapping[str, str], created)

    def _get_related_iocs(self, report_name: str) -> list[_DomainObject]:
        try:
            related_indicators = []
            related_indicators_with_related_entities = []
            _limit = 10000
            _sort = "last_updated|asc"
            _fql_filter = f"reports:['{report_name}']"

            # Getting IOCs linked and based on report name
            response = self.indicators_api_cs.get_combined_indicator_entities(
                limit=_limit, sort=_sort, fql_filter=_fql_filter, deep_pagination=True
            )

            # Check if response has resources or if it's an error response
            if "resources" in response:
                related_indicators.extend(response["resources"])
            elif "errors" in response:
                # API returned an error (e.g., 403 permission denied)
                error_code = response.get("errors", [{}])[0].get("code")
                if error_code == 403:
                    self._warning(
                        "Skipping IOC fetching for report {0} - no indicator scope permission",
                        report_name,
                    )
                    return (
                        related_indicators_with_related_entities  # Return what we have
                    )
                else:
                    # Other errors should be logged
                    self._warning(
                        "Error fetching related IOCs for report {0}: {1}",
                        report_name,
                        str(response),
                    )
                    return related_indicators_with_related_entities
            else:
                # Unexpected response format
                self._warning(
                    "Unexpected response format when fetching indicators for report {0}",
                    report_name,
                )
                return related_indicators_with_related_entities

            if related_indicators is not None:
                for indicator in related_indicators:
                    bundle_builder_config = IndicatorBundleBuilderConfig(
                        indicator=indicator,
                        author=self.author,
                        source_name=self._source_name(),
                        object_markings=[self.tlp_marking],
                        confidence_level=self._confidence_level(),
                        create_observables=self.indicator_config["create_observables"],
                        create_indicators=self.indicator_config["create_indicators"],
                        default_x_opencti_score=self.indicator_config[
                            "default_x_opencti_score"
                        ],
                        indicator_low_score=self.indicator_config[
                            "indicator_low_score"
                        ],
                        indicator_low_score_labels=self.indicator_config[
                            "indicator_low_score_labels"
                        ],
                        indicator_medium_score=self.indicator_config[
                            "indicator_medium_score"
                        ],
                        indicator_medium_score_labels=self.indicator_config[
                            "indicator_medium_score_labels"
                        ],
                        indicator_high_score=self.indicator_config[
                            "indicator_high_score"
                        ],
                        indicator_high_score_labels=self.indicator_config[
                            "indicator_high_score_labels"
                        ],
                        indicator_unwanted_labels=self.indicator_config[
                            "indicator_unwanted_labels"
                        ],
                        scopes=self.scopes,
                    )
                    try:
                        bundle_builder = IndicatorBundleBuilder(
                            self.helper, bundle_builder_config
                        )
                    except TypeError as err:
                        self.helper.connector_logger.warning(
                            "Skipping unsupported indicator type for report.",
                            {
                                "report_name": report_name,
                                "indicator_id": indicator.get("id"),
                                "indicator_type": indicator.get("type"),
                                "indicator_value": indicator.get("indicator"),
                                "error": str(err),
                            },
                        )
                        continue
                    indicator_bundle_built = bundle_builder.build()
                    if indicator_bundle_built:
                        indicator_with_related_entities = indicator_bundle_built[
                            "object_refs"
                        ]
                        related_indicators_with_related_entities.extend(
                            indicator_with_related_entities
                        )
                    else:
                        self.helper.connector_logger.debug(
                            "[DEBUG] The construction of the indicator has been skipped in the report.",
                            {
                                "indicator_id": indicator.get("id"),
                                "indicator_type": indicator.get("type"),
                            },
                        )
                        continue

            return related_indicators_with_related_entities
        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] An unexpected error occurred when retrieving indicators for the report.",
                {
                    "error": str(err),
                    "report_name": report_name,
                },
            )
            raise

    def _create_report_bundle(
        self, report, report_file: Optional[Mapping[str, str]] = None
    ) -> Bundle:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        report_status = self.report_status
        report_type = self.report_type
        confidence_level = self._confidence_level()
        related_indicators_with_related_entities = []

        report_slug = report["slug"]
        if report_slug is not None:
            report_name = report_slug.upper()
            related_indicators_with_related_entities = self._get_related_iocs(
                report_name
            )
        malwares_from_field = report.get("malware", [])

        bundle_builder = ReportBundleBuilder(
            report,
            author,
            source_name,
            object_marking_refs,
            report_status,
            report_type,
            confidence_level,
            report_file,
            related_indicators_with_related_entities,
            self.report_guess_relations,
            malwares_from_field=malwares_from_field,
            scopes=self.scopes,
        )
        return bundle_builder.build()

    # MVP2
    def _guess_malwares_from_tags(self, tags: List) -> dict[str, str]:
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
