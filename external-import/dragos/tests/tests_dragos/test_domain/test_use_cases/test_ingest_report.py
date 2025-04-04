"""Offer tests for the ingest_report module."""

from typing import Generator, Optional

import dragos.domain.models.octi as octi
from dragos.domain.models.octi.enums import TLPLevel
from dragos.domain.use_cases.ingest_report import ReportProcessor
from dragos.interfaces import Geocoding, Indicator, Report, Tag
from dragos.interfaces.geocoding import Country


class StubGeocoding(Geocoding):
    """Stub implementation of _Geocoding for testing purposes."""

    def find_from_name(self, name: str) -> Country:
        """Return a Country."""
        return Country(name=name)


class StubReport(Report):
    """Stub Report implementation for testing purposes."""

    @property
    def related_tags(self) -> Generator[Tag, None, None]:
        yield from [stub_valid_tag()]

    @property
    def related_indicators(self) -> Generator[Indicator, None, None]:
        yield from [stub_valid_indicator()] * 3

    @property
    def pdf(self) -> Optional[bytes]:
        return None


def stub_valid_tag() -> Tag:
    """Return a stub valid tag."""
    return Tag(type="Geolocation", value="my_place")


def stub_valid_indicator() -> Indicator:
    """Return a stub valid indicator."""
    return Indicator(
        value="192.0.0.1",
        type="ip",
        first_seen="1970-01-01T00:00:00Z",
        last_seen="1970-01-02T00:00:00Z",
    )


def stub_valid_report() -> StubReport:
    """Return a stub valid report."""
    return StubReport(
        serial="12345",
        title="Sample Report",
        created_at="1970-01-01T00:00:00Z",
        updated_at="1970-01-01T00:00:00Z",
        summary="This is a sample report summary.",
    )


def test_report_processor_should_process_a_valid_report():
    """Test that ReportProcessor can process a valid report."""
    # Given: A ReportProcessor and a valid report
    report_processor = ReportProcessor(
        tlp_level=TLPLevel.AMBER.value,
        geocoding=StubGeocoding(),
    )
    stub_report = stub_valid_report()

    # When: Processing it
    octi_entities = report_processor.run_on(stub_report)

    # Then: ReportProcessor returns a list of OCTI entities
    assert (  # noqa: S101
        isinstance(octi_entities, list)
        and any(isinstance(entity, octi.Report) for entity in octi_entities)
        and any(isinstance(entity, octi.Observable) for entity in octi_entities)
        and any(isinstance(entity, octi.Indicator) for entity in octi_entities)
        and any(
            isinstance(entity, octi.IndicatorBasedOnObservable)
            for entity in octi_entities
        )
        and any(isinstance(entity, octi.OrganizationAuthor) for entity in octi_entities)
        and any(isinstance(entity, octi.TLPMarking) for entity in octi_entities)
    )
