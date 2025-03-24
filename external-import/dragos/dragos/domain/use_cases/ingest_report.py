"""Offer tools to ingest Report and related entities from Dragos reports."""

import logging
from typing import TYPE_CHECKING, Any, Generator

from dragos.domain.models import octi
from dragos.domain.models.octi.enums import OrganizationType
from dragos.domain.use_cases.common import BaseUseCase

if TYPE_CHECKING:
    from dragos.interfaces import Indicator, Report, Tag

logger = logging.getLogger(__name__)


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

    def _make_artifact(self, indicator: "Indicator") -> octi.Artifact:
        """Make an OCTI Artifact from report's indicator."""
        hash_algorithm, hash_value = indicator.value.split(":")

        return octi.Artifact(
            hashes={hash_algorithm: hash_value},
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_domain_name(self, indicator: "Indicator") -> octi.DomainName:
        """Make an OCTI DomainName from report's indicator."""
        return octi.DomainName(
            value=indicator.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_file(self, indicator: "Indicator") -> octi.File:
        """Make an OCTI File from report's indicator."""
        return octi.File(
            hashes={indicator.type: indicator.value},
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_ipv4_address(self, indicator: "Indicator") -> octi.IPV4Address:
        """Make an OCTI IPV4Address from report's indicator."""
        return octi.IPV4Address(
            value=indicator.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_ipv6_address(self, indicator: "Indicator") -> octi.IPV6Address:
        """Make an OCTI IPV6Address from report's indicator."""
        return octi.IPV6Address(
            value=indicator.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

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
                    yield None  # Location
                case "hacker group" | "threatgroup" | "externalname":
                    yield self._make_intrusion_set(related_tag)
                case "government organization":
                    yield self._make_organization(related_tag)
                case "malware":
                    yield self._make_malware(related_tag)
                case "cve":
                    yield self._make_vulnerability(related_tag)
                case _:
                    logger.warning(f"Unsupported tag type {tag_type}")

    def make_observables_and_indicators(
        self, report: "Report"
    ) -> Generator[tuple["octi.Observable", "octi.Indicator"], Any, Any]:
        """Make an OCTI Observable and Indicator generator from Dragos report related indicators."""

        def make_observable(related_indicator: "Indicator") -> "octi.Observable":
            """Make an OCTI observable from a Dragos report related indicator."""
            dragos_indicator_type = related_indicator.type.lower()
            match dragos_indicator_type:
                case "artifact":
                    return self._make_artifact(related_indicator)
                case "domain":
                    return self._make_domain_name(related_indicator)
                case "ip":
                    if self._is_ipv4(related_indicator.value):
                        return self._make_ipv4_address(related_indicator)
                    if self._is_ipv6(related_indicator.value):
                        return self._make_ipv6_address(related_indicator)
                case "md5" | "sha1" | "sha256":
                    return self._make_file(related_indicator)
                case "url":
                    return self._make_url(related_indicator)
                case _:
                    logger.warning(
                        f"Unsupported indicator type {dragos_indicator_type}"
                    )
            return None

        for related_indicator in report.related_indicators:
            indicator = None
            observable = make_observable(related_indicator)
            if observable:
                indicator = observable.to_indicator(
                    valid_from=related_indicator.first_seen,
                    valid_until=related_indicator.last_seen,
                )
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
        self, report: "Report", related_objetcs: list["octi.BaseEntity"]
    ) -> octi.Report:
        """Make an OCTI Report from a Dragos report and the related entities."""
        return octi.Report(
            name=report.title,
            publication_date=report.created_at,
            description=report.summary,
            # labels=report.related_tags,
            objects=related_objetcs,
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

        # Only append Report, Author and TLP if at least one entity is present
        # to prevent sending unconsistent bundle in application layer
        if entities:
            entities.append(self.make_report(report, entities))
            entities.append(self.author)
            entities.append(self.tlp_marking)

        return entities
