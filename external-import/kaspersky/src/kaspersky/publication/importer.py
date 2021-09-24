"""Kaspersky publication importer module."""

from datetime import datetime
from typing import Any, List, Mapping, Optional, Set

from pycti import OpenCTIConnectorHelper  # type: ignore

from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore
from stix2.exceptions import STIXError  # type: ignore

from kaspersky.client import KasperskyClient
from kaspersky.importer import BaseImporter
from kaspersky.models import Publication
from kaspersky.publication.builder import PublicationBundleBuilder
from kaspersky.utils import (
    datetime_to_timestamp,
    timestamp_to_datetime,
)


class PublicationImporter(BaseImporter):
    """Kaspersky publication importer."""

    _LATEST_PUBLICATION_TIMESTAMP = "latest_publication_timestamp"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: KasperskyClient,
        author: Identity,
        tlp_marking: MarkingDefinition,
        create_observables: bool,
        create_indicators: bool,
        update_existing_data: bool,
        publication_start_timestamp: int,
        publication_report_type: str,
        publication_report_status: int,
        publication_report_ignore_prefixes: Set[str],
        publication_excluded_ioc_indicator_types: Set[str],
    ) -> None:
        """Initialize Kaspersky publication importer."""
        super().__init__(helper, client, author, tlp_marking, update_existing_data)

        self.create_observables = create_observables
        self.create_indicators = create_indicators

        self.publication_start_timestamp = publication_start_timestamp
        self.publication_report_type = publication_report_type
        self.publication_report_status = publication_report_status
        self.publication_report_ignore_prefixes = publication_report_ignore_prefixes
        self.publication_excluded_ioc_indicator_types = (
            publication_excluded_ioc_indicator_types
        )

        self.opencti_regions: Set[str] = set()

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self._info(
            "Running Kaspersky publication importer (update data: {0})...",
            self.update_existing_data,
        )

        self._load_opencti_regions()

        latest_publication_timestamp = state.get(self._LATEST_PUBLICATION_TIMESTAMP)
        if latest_publication_timestamp is None:
            latest_publication_timestamp = self.publication_start_timestamp

        latest_publication_datetime = timestamp_to_datetime(
            latest_publication_timestamp
        )

        publications = self._fetch_publications(latest_publication_datetime)
        publication_count = len(publications)

        self._info(
            "Fetched {0} publications...",
            publication_count,
        )

        publications = self._filter_publications(
            publications, latest_publication_datetime
        )
        publication_count = len(publications)

        self._info(
            "{0} publications after filtering...",
            publication_count,
        )

        failed_count = 0

        for publication in publications:
            result = self._process_publication(publication)
            if not result:
                failed_count += 1

            publication_updated = publication.updated
            if publication_updated > latest_publication_datetime:
                latest_publication_datetime = publication_updated

        success_count = publication_count - failed_count

        self._info(
            "Kaspersky publication importer completed (imported: {0}, failed: {1}, total: {2})",  # noqa: E501
            success_count,
            failed_count,
            publication_count,
        )

        return {
            self._LATEST_PUBLICATION_TIMESTAMP: datetime_to_timestamp(
                latest_publication_datetime
            )
        }

    def _fetch_publications(self, date_start: datetime) -> List[Publication]:
        return self.client.get_publications(date_start=date_start)

    def _fetch_publication_details(self, publication_id: str) -> Publication:
        include_info = ["pdf", "yara", "iocs"]
        lang = "en"

        return self.client.get_publication(
            publication_id, include_info=include_info, lang=lang
        )

    def _filter_publications(
        self, publications: List[Publication], latest_publication_datetime: datetime
    ) -> List[Publication]:
        filtered_publications = self._filter_already_processed(
            publications, latest_publication_datetime
        )
        filtered_publications = self._filter_ignored_prefixes(filtered_publications)
        return filtered_publications

    def _filter_already_processed(
        self, publications: List[Publication], latest_publication_datetime: datetime
    ) -> List[Publication]:
        def _updated_filter(publication: Publication) -> bool:
            updated = publication.updated
            if updated <= latest_publication_datetime:
                self._info(
                    "Discarding processed publication '{}' ({}).",
                    publication.name,
                    publication.id,
                )
                return False
            else:
                return True

        return list(filter(_updated_filter, publications))

    def _filter_ignored_prefixes(
        self, publications: List[Publication]
    ) -> List[Publication]:
        ignored_prefixes = tuple(self.publication_report_ignore_prefixes)

        def _ignored_prefix_filter(publication: Publication) -> bool:
            name = publication.name
            if name.startswith(ignored_prefixes):
                self._info(
                    "Discarding publication with ignored prefix '{}' ({}).",
                    publication.name,
                    publication.id,
                )
                return False
            else:
                return True

        return list(filter(_ignored_prefix_filter, publications))

    def _process_publication(self, publication: Publication) -> bool:
        self._info(
            "Processing publication {0} ({1})...", publication.name, publication.id
        )

        publication_details = self._fetch_publication_details(publication.id)

        publication_bundle = self._create_publication_bundle(publication_details)
        if publication_bundle is None:
            return False

        # with open(f"publication_bundle_{publication_details.id}.json", "w") as f:
        #     f.write(publication_bundle.serialize(pretty=True))

        self._send_bundle(publication_bundle)

        return True

    def _create_publication_bundle(self, publication: Publication) -> Optional[Bundle]:
        author = self.author
        source_name = self._source_name()
        object_markings = [self.tlp_marking]
        create_observables = self.create_observables
        create_indicators = self.create_indicators
        confidence_level = self._confidence_level()
        report_type = self.publication_report_type
        report_status = self.publication_report_status
        excluded_ioc_indicator_types = self.publication_excluded_ioc_indicator_types
        opencti_regions = self.opencti_regions

        bundle_builder = PublicationBundleBuilder(
            publication,
            author,
            source_name,
            object_markings,
            create_observables,
            create_indicators,
            confidence_level,
            report_type,
            report_status,
            excluded_ioc_indicator_types,
            opencti_regions,
        )

        try:
            return bundle_builder.build()
        except STIXError as e:
            self.helper.metric_inc("error_count")
            self._error(
                "Failed to build publication bundle for '{0}' ({1}): {2}",
                publication.name,
                publication.id,
                e,
            )
            return None

    def _load_opencti_regions(self) -> None:
        self.opencti_regions.clear()

        regions = self._fetch_opencti_regions()

        self._info("Loaded {0} regions from OpenCTI", len(regions))

        self.opencti_regions.update(regions)

    def _fetch_opencti_regions(self) -> Set[str]:
        regions = set()

        opencti_api_client = self.helper.api

        custom_attributes = """
            id
            name
            x_opencti_aliases
            entity_type
        """

        pagination_key = "pagination"
        has_next_page_key = "hasNextPage"
        end_cursor_key = "endCursor"

        data: Mapping[str, Any] = {
            pagination_key: {has_next_page_key: True, end_cursor_key: None}
        }

        while data[pagination_key][has_next_page_key]:
            after = data[pagination_key][end_cursor_key]

            data = opencti_api_client.location.list(
                types=["Region"],
                first=50,
                after=after,
                customAttributes=custom_attributes,
                withPagination=True,
                orderBy="created_at",
                orderMode="asc",
            )

            entities: List[Mapping[str, Any]] = data["entities"]

            for entity in entities:
                region_name = entity.get("name")
                if region_name is None or not region_name:
                    continue

                regions.add(region_name)

        return regions
