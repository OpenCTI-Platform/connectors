"""Offer tools to ingest Report and related entities from Dragos reports."""

import logging
from typing import TYPE_CHECKING, Any, Generator, Literal, Optional

from dragos.domain.models import octi
from dragos.domain.models.octi.enums import OrganizationType
from dragos.domain.use_cases.common import BaseUseCase, UseCaseError
from dragos.interfaces import Area, City, Country, Position, Region
from markdownify import markdownify

if TYPE_CHECKING:
    from dragos.interfaces import Geocoding, Indicator, Report, Tag

logger = logging.getLogger(__name__)


SUPPORTED_TAG_TYPES = [
    "industry",
    "naics",
    "geographiclocation",
    "hacker group",
    "threatgroup",
    "externalname",
    "government organization",
    "malware",
    "cve",
]


class ReportProcessor(BaseUseCase):
    """Process simply the data from a Dragos report.

    Examples:
        >>> from dragos.adapters.report import Reports
        >>> from dragos.domain.models.octi import TLPMarking
        >>> processor = ReportProcessor(tlp_marking=TLPMarking(level="white"))
        >>> reports = Reports.iter()
        >>> for report in reports:
        ...   entities = processor.run_on(report)

    """

    def __init__(
        self,
        tlp_level: Literal["white", "green", "amber", "amber+strict", "red"],
        geocoding: "Geocoding",
    ) -> None:
        """Initialize the reports ingestion use case."""
        BaseUseCase.__init__(self, tlp_level)
        self.geocoding = geocoding

    def _make_domain_name(self, indicator: "Indicator") -> octi.DomainName:
        """Make an OCTI DomainName from report's indicator."""
        return octi.DomainName(
            value=indicator.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_file(self, indicator: "Indicator") -> octi.File:
        """Make an OCTI File from report's indicator."""
        # Indicators of type "artifact" are mapped to File observables in OCTI
        # as Dragos does not provide any payload for them.
        if indicator.type == "artifact":
            hash_algorithm, hash_value = indicator.value.split(":")
        else:
            hash_algorithm = indicator.type
            hash_value = indicator.value

        return octi.File(
            hashes={hash_algorithm: hash_value},
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_ip_address(
        self, indicator: "Indicator"
    ) -> octi.IPV4Address | octi.IPV6Address:
        """Make an OCTI IP Address (v4 or v6) from report's indicator."""
        if self._is_ipv4(indicator.value):
            return octi.IPV4Address(
                value=indicator.value,
                author=self.author,
                markings=[self.tlp_marking],
            )
        elif self._is_ipv6(indicator.value):
            return octi.IPV6Address(
                value=indicator.value,
                author=self.author,
                markings=[self.tlp_marking],
            )
        else:
            raise UseCaseError(f"Invalid IP Address: {indicator.value}")

    def _make_url(self, indicator: "Indicator") -> octi.Url:
        """Make an OCTI URL from report's indicator."""
        return octi.Url(
            value=indicator.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_intrusion_set(self, tag: "Tag") -> octi.IntrusionSet:
        """Make an OCTI IntrusionSet from report's tag."""
        return octi.IntrusionSet(
            name=tag.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_location(
        self, tag: "Tag"
    ) -> Optional[
        octi.LocationAdministrativeArea
        | octi.LocationCity
        | octi.LocationCountry
        | octi.LocationPosition
        | octi.LocationRegion
    ]:
        """Make an OCTI Location from report's tag."""
        location = self.geocoding.find_from_name(tag.value)
        if not location:
            logger.info(f"Location not found for tag value: {tag.value}")
            return None

        match location:
            case Area():
                return octi.LocationAdministrativeArea(
                    name=location.name,
                    author=self.author,
                    markings=[self.tlp_marking],
                )
            case City():
                return octi.LocationCity(
                    name=location.name,
                    author=self.author,
                    markings=[self.tlp_marking],
                )
            case Country():
                return octi.LocationCountry(
                    name=location.name,
                    author=self.author,
                    markings=[self.tlp_marking],
                )
            case Position():
                return octi.LocationPosition(
                    name=location.name,
                    latitude=location.latitude,
                    longitude=location.longitude,
                    author=self.author,
                    markings=[self.tlp_marking],
                )
            case Region():
                return octi.LocationRegion(
                    name=location.name,
                    author=self.author,
                    markings=[self.tlp_marking],
                )
            case _:
                raise UseCaseError(f"Unsupported location type: {type(location)}")

    def _make_organization(self, tag: "Tag") -> octi.Organization:
        """Make an OCTI Organization from report's tag."""
        return octi.Organization(
            name=tag.value,
            organization_type=OrganizationType.OTHER.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_malware(self, tag: "Tag") -> octi.Malware:
        """Make an OCTI Malware from report's tag."""
        return octi.Malware(
            name=tag.value,
            is_family=False,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_sector(self, tag: "Tag") -> octi.Sector:
        """Make an OCTI Sector from report's tag."""
        return octi.Sector(
            name=tag.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_vulnerability(self, tag: "Tag") -> octi.Vulnerability:
        """Make an OCTI Vulnerability from report's tag."""
        return octi.Vulnerability(
            name=tag.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def make_domain_objects(
        self, report: "Report"
    ) -> Generator["octi.DomainObject", Any, Any]:
        """Make OCTI domain objects generator from Dragos report related tags."""
        for related_tag in report.related_tags:
            tag_type = related_tag.type.lower()
            match tag_type:
                case "industry" | "naics":
                    yield self._make_sector(related_tag)
                case "geographiclocation":
                    location = self._make_location(related_tag)
                    if location:
                        yield location
                case "hacker group" | "threatgroup" | "externalname":
                    yield self._make_intrusion_set(related_tag)
                case "government organization":
                    yield self._make_organization(related_tag)
                case "malware":
                    yield self._make_malware(related_tag)
                case "cve":
                    yield self._make_vulnerability(related_tag)
                case _:
                    logger.info(f"Unsupported tag type {tag_type}")

    def make_observables_and_indicators(
        self, report: "Report"
    ) -> Generator[tuple["octi.Observable", "octi.Indicator"], Any, Any]:
        """Make an OCTI Observable and Indicator generator from Dragos report related indicators."""

        def make_observable(
            _related_indicator: "Indicator",  # shadow name (same variable name bellow)
        ) -> Optional["octi.Observable"]:
            """Make an OCTI observable from a Dragos report related indicator."""
            dragos_indicator_type = _related_indicator.type.lower()
            match dragos_indicator_type:
                case "domain":
                    return self._make_domain_name(_related_indicator)
                case "ip":
                    return self._make_ip_address(_related_indicator)
                case "artifact" | "md5" | "sha1" | "sha256":
                    return self._make_file(_related_indicator)
                case "url":
                    return self._make_url(_related_indicator)
                case _:
                    logger.info(f"Unsupported indicator type {dragos_indicator_type}")
            return None

        for related_indicator in report.related_indicators:
            indicator = None
            observable = make_observable(related_indicator)
            if observable:
                # Dragos reports contains indicators with first_seen and last_seen that can be
                # the same. We do not stipulate a validity time range.
                indicator = observable.to_indicator()
            if observable and indicator:
                yield (observable, indicator)

    def make_indicator_based_on_observable_relationship(
        self, indicator: "octi.Indicator", observable: "octi.Observable"
    ) -> octi.IndicatorBasedOnObservable:
        """Make an OCTI IndicatorBasedOnObservable relationship from Indicator and Observable."""
        return octi.IndicatorBasedOnObservable(
            author=self.author,
            source=indicator,
            target=observable,
            markings=[self.tlp_marking],
            # unused
            description=None,
            start_time=None,
            stop_time=None,
            external_references=None,
        )

    def make_report(
        self, report: "Report", related_objects: list["octi.BaseEntity"]
    ) -> octi.Report:
        """Make an OCTI Report from a Dragos report and the related entities."""
        markdown_description = markdownify(report.summary)

        labels = []
        for related_tag in report.related_tags:
            tag_type = related_tag.type.lower()
            if tag_type not in SUPPORTED_TAG_TYPES:
                # Supported tags are converted into OCTI entities,
                # but unsupported tags are stored as report's labels as fallback
                labels.append(related_tag.value)

        uploaded_file = None
        if report.pdf:
            uploaded_file = octi.UploadedFile(
                name=f"{report.serial}.pdf",
                content=report.pdf,
                mime_type="application/pdf",
            )

        return octi.Report(
            name=report.title,
            publication_date=report.created_at,
            description=markdown_description,
            labels=labels,
            objects=related_objects,
            files=[uploaded_file] if uploaded_file else None,
            author=self.author,
            markings=[self.tlp_marking],
            # unused
            reliability=None,
            report_types=None,
            external_references=None,
        )

    def run_on(self, report: "Report") -> list["octi.BaseEntity"]:
        """Run the process of entities creation thanks to a Report."""
        entities: list["octi.BaseEntity"] = []

        observables_and_indicators = self.make_observables_and_indicators(report)
        for observable, indicator in observables_and_indicators:
            entities.append(observable)
            entities.append(indicator)

            based_on_relationship = (
                self.make_indicator_based_on_observable_relationship(
                    indicator=indicator,
                    observable=observable,
                )
            )
            entities.append(based_on_relationship)
        entities.extend(self.make_domain_objects(report))
        entities.append(self.make_report(report, entities))
        entities.append(self.author)
        entities.append(self.tlp_marking)

        return entities
