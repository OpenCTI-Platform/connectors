from typing import Generator, Optional

import dragos.domain.models.octi as octi
from dragos.domain.models.octi.enums import TLPLevel
from dragos.domain.use_cases.ingest_report import ReportProcessor
from dragos.interfaces import Indicator, Report, Tag


class StubTag(Tag):
    """Stub Tag implementation for testing purposes."""

    @property
    def _type(self) -> str:
        """Return the Stub Tag type."""
        return "Geolocation"

    @property
    def _value(self) -> str:
        """Return the Stub Tag value."""
        return "my_place"


class StubIndicator(Indicator):
    """Stub Indicator implementation for testing purposes."""

    @property
    def _value(self):
        return "192.0.0.1"

    @property
    def _type(self):
        return "ip"

    @property
    def _first_seen(self) -> str:
        return "1970-01-01T00:00:00Z"

    @property
    def _last_seen(self) -> str:
        return "1970-01-02T00:00:00Z"


class StubReport(Report):
    """Stub Report implementation for testing purposes."""

    @property
    def _serial(self) -> str:
        return "12345"

    @property
    def _title(self) -> str:
        return "Sample Report"

    @property
    def _created_at(self) -> str:
        return "1970-01-01T00:00:00Z"

    @property
    def _updated_at(self) -> str:
        return "1970-01-01T00:00:00Z"

    @property
    def _summary(self) -> str:
        return "This is a sample report summary."

    @property
    def _related_tags(self) -> Generator[Tag, None, None]:
        yield from [StubTag()]

    @property
    def _related_indicators(self) -> Generator[Indicator, None, None]:
        yield from [StubIndicator()] * 3

    @property
    def _pdf(self) -> Optional[bytes]:
        return None


def test_report_processor_should_process_a_valid_report():
    # Given: A ReportProcessor and a valid report
    report_processor = ReportProcessor(tlp_level=TLPLevel.AMBER.value)
    stub_report = StubReport()

    # When: Processing it
    octi_entities = report_processor.run_on(stub_report)

    # Then: ReportProcessor returns a list of OCTI entities
    assert isinstance(octi_entities, list) is True
    assert any(isinstance(entity, octi.Report) for entity in octi_entities)
    assert any(isinstance(entity, octi.Observable) for entity in octi_entities)
    assert any(isinstance(entity, octi.Indicator) for entity in octi_entities)
    assert any(
        isinstance(entity, octi.IndicatorBasedOnObservable) for entity in octi_entities
    )
    assert any(isinstance(entity, octi.OrganizationAuthor) for entity in octi_entities)
    assert any(isinstance(entity, octi.TLPMarking) for entity in octi_entities)
