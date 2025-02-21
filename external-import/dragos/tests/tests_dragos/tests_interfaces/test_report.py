"""Provide tests for dragos.interfaces.report module."""

import datetime
import inspect
import typing

import pytest
from dragos.interfaces.report import Indicator, Report, Reports, Tag
from pydantic import ValidationError


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
    def _first_seen(self):
        return datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

    @property
    def _last_seen(self):
        return datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)


class StubReport(Report):
    """Stub Report implementation for testing purposes."""

    @property
    def _serial(self) -> str:
        return "12345"

    @property
    def _title(self) -> str:
        return "Sample Report"

    @property
    def _created_at(self) -> datetime.datetime:
        return datetime.datetime(2023, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

    @property
    def _updated_at(self) -> datetime.datetime:
        return datetime.datetime(2023, 1, 2, 0, 0, 0, tzinfo=datetime.timezone.utc)

    @property
    def _summary(self) -> str:
        return "This is a sample report summary."

    @property
    def _related_tags(self) -> list[Tag]:
        return [StubTag()]

    @property
    def _related_indicators(
        self,
    ) -> typing.Generator[Indicator, typing.Any, typing.Any]:
        for indicator in [StubIndicator()] * 3:
            yield indicator


class StubReports(Reports):
    """Stub Reports implementation for testing purposes."""

    def list(self, since) -> typing.Generator[Report, typing.Any, typing.Any]:
        """List the reports."""
        _ = since
        return iter([StubReport()])


@pytest.mark.parametrize(
    "interface",
    [
        pytest.param(Tag, id="Tag"),
        pytest.param(Indicator, id="Indicator"),
        pytest.param(Report, id="Report"),
        pytest.param(Reports, id="Reports"),
    ],
)
def test_interfaces_are_abstract(interface):
    """Test that the interfaces are abstract."""
    # Given an interface
    # When checking if it is abstract
    # Then result is true
    assert inspect.isabstract(interface)  # noqa: S101 we indeed call assert in test


def test_tag_should_have_the_correct_attribute():
    """Test that the Tag has the correct attributes."""
    # Given a StubTag definition respecting interface
    # When instantiating the StubTag
    tag = StubTag()
    # Then the tag should have the correct attributes
    assert (  # noqa: S101 we indeed call assert in test
        tag.type == "Geolocation" and tag.value == "my_place"
    )
    # in fact we just check there is no error due to breaking changes


def test_tag_should_raise_validation_error_with_incorrect_attribute():
    """Test that the Tag raises a validation error with incorrect attributes."""

    # Given a StubTag implementation not respecting interface types
    class IncorrectStubTag(StubTag):
        """Incorrect Stub Tag implementation for testing purposes."""

        @property
        def _value(self) -> tuple[float, float]:
            """Return the Stub Tag value."""
            return (44.5, 5.2)

    # When instantiating the IncorrectStubTag
    with pytest.raises(ValidationError):
        _ = IncorrectStubTag()


def test_indicator_should_have_the_correct_attribute():
    """Test that the Indicator has the correct attributes."""
    # Given a StubIndicator definition respecting interface types
    # When instantiating the StubIndicator
    indicator = StubIndicator()
    # Then the indicator should have the correct attributes
    assert indicator.value == "192.0.0.1"  # noqa: S101 we indeed call assert in test
    # in fact we just check there is no error due to breaking changes


def test_indicator_should_raise_validation_error_with_incorrect_attribute():
    """Test that the Indicator raises a validation error with incorrect attributes."""

    # Given a StubIndicator implementation not respecting interface types
    class IncorrectStubIndicator(StubIndicator):
        """Incorrect Stub Indicator implementation for testing purposes."""

        @property
        def _value(self):
            return 1234

    # When instantiating the IncorrectStubIndicator
    # Then a validation error should be raised
    with pytest.raises(ValidationError):
        _ = IncorrectStubIndicator()


def test_report_should_have_the_correct_attributes():
    """Test that the Report has the correct attributes."""
    # Given a StubReport definition respecting interface types
    # When instantiating the StubReport
    report = StubReport()
    # Then the report should have the correct attributes
    assert report.serial == "12345"  # noqa: S101 we indeed call assert in test
    # in fact we just check there is no error due to breaking changes


def test_report_should_raise_validation_error_with_incorrect_attribute():
    """Test that the Report raises a validation error with incorrect attributes."""

    # Given a StubReport implementation not respecting interface types
    class IncorrectStubReport(StubReport):
        """Incorrect Stub Report implementation for testing purposes."""

        @property
        def _serial(self) -> str:
            return 12345  # should be str

    # When instantiating the IncorrectStubReport
    # Then a validation error should be raised
    with pytest.raises(ValidationError):
        _ = IncorrectStubReport()


def test_reports_list_reports():
    """Test that the Reports list reports."""
    # Given a StubReports instance
    reports = StubReports()
    # When listing the reports
    reports_list = list(
        reports.list(
            since=datetime.datetime(2023, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
        )
    )
    # Then the reports list should not be empty
    assert len(reports_list) == 1  # noqa: S101 we indeed call assert in test
    # in fact we just check there is no error due to breaking changes
