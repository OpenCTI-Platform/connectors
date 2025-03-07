"""Offer tools to ingest Report and related entities from Dragos reports."""

import ipaddress
from typing import TYPE_CHECKING, Any, Generator

from dragos.domain.models.octi import (
    Artifact,
    DomainName,
    File,
    Indicator,
    IndicatorBasedOnObservable,
    IPV4Address,
    IPV6Address,
    OrganizationAuthor,
    Report,
    TLPMarking,
    Url,
)

if TYPE_CHECKING:
    from dragos.domain.models.octi import BaseEntity, Observable
    from dragos.domain.models.octi.enum import TLPLevel
    from dragos.interfaces import Indicator as IndicatorInterface
    from dragos.interfaces import Report as ReportInterface


class BaseUseCase:
    """Base use case class."""

    def __init__(self, tlp_level: "TLPLevel"):
        """Initialize the use case."""
        self.tlp_marking = TLPMarking(level=tlp_level)
        self.author = OrganizationAuthor(
            name="Dragos",
            description="Dragos WorldView provides actionable information and recommendations on threats to operations technology (OT) environments.",
            contact_information="https://www.dragos.com/us/contact",
            organization_type="vendor",
            reliability=None,
            aliases=None,
            author=None,
            markings=None,
            external_references=None,
        )

    def _is_ipv4(self, value: str) -> bool:
        """Check if value is a valid IPv4 address."""
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False

    def _is_ipv6(self, value: str) -> bool:
        """Check if value is a valid IPv6 address."""
        try:
            ipaddress.IPv6Address(value)
            return True
        except ValueError:
            return False


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

    def _make_artifact(self, dragos_indicator: "IndicatorInterface") -> Artifact:
        hash_algorithm, hash_value = dragos_indicator.value.split(":")

        return Artifact(
            hashes={hash_algorithm: hash_value},
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_domain_name(self, dragos_indicator: "IndicatorInterface") -> DomainName:
        return DomainName(
            value=dragos_indicator.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_file(self, dragos_indicator: "IndicatorInterface") -> File:
        return File(
            hashes={dragos_indicator.type: dragos_indicator.value},
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_ipv4_address(self, dragos_indicator: "IndicatorInterface") -> IPV4Address:
        return IPV4Address(
            value=dragos_indicator.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_ipv6_address(self, dragos_indicator: "IndicatorInterface") -> IPV6Address:
        return IPV6Address(
            value=dragos_indicator.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _make_url(self, dragos_indicator: "IndicatorInterface") -> Url:
        return Url(
            value=dragos_indicator.value,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def make_observables_and_indicators(
        self, report: "ReportInterface"
    ) -> Generator[tuple["Observable", "Indicator"], Any, Any]:
        """Make an OCTI Observable and Indicator generator from a Dragos report."""
        for related_indicator in report.related_indicators:
            match related_indicator.type:
                case "artifact":
                    observable = self._make_artifact(related_indicator)
                case "domain":
                    observable = self._make_domain_name(related_indicator)
                case "ip":
                    if self._is_ipv4(related_indicator.value):
                        observable = self._make_ipv4_address(related_indicator)
                    if self._is_ipv6(related_indicator.value):
                        observable = self._make_ipv6_address(related_indicator)
                case "md5" | "sha1" | "sha256":
                    observable = self._make_file(related_indicator)
                case "url":
                    observable = self._make_url(related_indicator)
            if observable:
                indicator = observable.to_indicator(
                    valid_from=related_indicator.first_seen,
                    valid_until=related_indicator.last_seen,
                )
            if observable and indicator:
                yield (observable, indicator)

    def make_indicator_based_on_observable_relationship(
        self, indicator: "Indicator", observable: "Observable"
    ) -> IndicatorBasedOnObservable:
        """Make an OCTI IndicatorBasedOnObservable relationship from Indicator and Observable."""
        return IndicatorBasedOnObservable(
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
        self, dragos_report: "ReportInterface", related_objetcs: list["BaseEntity"]
    ) -> Report:
        """Make an OCTI Report from a Dragos report and the related entities."""
        return Report(
            name=dragos_report.title,
            publication_date=dragos_report.created_at,
            description=dragos_report.summary,
            # labels=dragos_report.related_tags,
            objects=related_objetcs,
            author=self.author,
            markings=[self.tlp_marking],
            # unused
            reliability=None,
            report_types=None,
            external_references=None,
        )

    def run_on(self, dragos_report: "ReportInterface") -> list["BaseEntity"]:
        """Run the process of entities creation thanks to a Report."""
        entities: list["BaseEntity"] = []

        observables_and_indicators = self.make_observables_and_indicators(dragos_report)
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

        # Only append Report, Author and TLP if at least one entity is present
        # to prevent sending unconsistent bundle in application layer
        if entities:
            entities.append(self.make_report(dragos_report, entities))
            entities.append(self.author)
            entities.append(self.tlp_marking)

        return entities
