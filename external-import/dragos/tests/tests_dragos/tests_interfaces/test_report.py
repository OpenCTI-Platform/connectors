"""Provide tests for dragos.interfaces.report module."""

import datetime
import inspect
import typing

import pytest
from pydantic import ValidationError

from dragos.interfaces.report import Indicator, Report, Reports, Tag


class DummyTag(Tag):
    """Dummy Tag implementation for testing purposes."""

    @property
    def _type(self) -> str:
        """Return the Dummy Tag type."""
        return "Geolocation"

    @property
    def _value(self) -> str:
        """Return the Dummy Tag value."""
        return "my_place"


class DummyIndicator(Indicator):
    """Dummy Indicator implementation for testing purposes."""

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


class DummyReport(Report):
    """Dummy Report implementation for testing purposes."""

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
        return [DummyTag()]

    @property
    def _related_indicators(
        self,
    ) -> typing.Generator[Indicator, typing.Any, typing.Any]:
        for indicator in [DummyIndicator()] * 3:
            yield indicator


class DummyReports(Reports):
    """Dummy Reports implementation for testing purposes."""

    def list(self, since) -> typing.Generator[Report, typing.Any, typing.Any]:
        """List the reports."""
        _ = since
        return iter([DummyReport()])


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
    # Given a DummyTag definition respecting interface
    # When instantiating the DummyTag
    tag = DummyTag()
    # Then the tag should have the correct attributes
    assert (  # noqa: S101 we indeed call assert in test
        tag.type == "Geolocation" and tag.value == "my_place"
    )
    # in fact we just check there is no error due to breaking changes


def test_tag_should_raise_validation_error_with_incorrect_attribute():
    """Test that the Tag raises a validation error with incorrect attributes."""

    # Given a DummyTag implementation not respecting interface types
    class IncorrectDummyTag(DummyTag):
        """Incorrect Dummy Tag implementation for testing purposes."""

        @property
        def _value(self) -> tuple[float, float]:
            """Return the Dummy Tag value."""
            return (44.5, 5.2)

    # When instantiating the IncorrectDummyTag
    with pytest.raises(ValidationError):
        _ = IncorrectDummyTag()


def test_indicator_should_have_the_correct_attribute():
    """Test that the Indicator has the correct attributes."""
    # Given a DummyIndicator definition respecting interface types
    # When instantiating the DummyIndicator
    indicator = DummyIndicator()
    # Then the indicator should have the correct attributes
    assert indicator.value == "192.0.0.1"  # noqa: S101 we indeed call assert in test
    # in fact we just check there is no error due to breaking changes


def test_indicator_should_raise_validation_error_with_incorrect_attribute():
    """Test that the Indicator raises a validation error with incorrect attributes."""

    # Given a DummyIndicator implementation not respecting interface types
    class IncorrectDummyIndicator(DummyIndicator):
        """Incorrect Dummy Indicator implementation for testing purposes."""

        @property
        def _value(self):
            return 1234

    # When instantiating the IncorrectDummyIndicator
    # Then a validation error should be raised
    with pytest.raises(ValidationError):
        _ = IncorrectDummyIndicator()


def test_report_should_have_the_correct_attributes():
    """Test that the Report has the correct attributes."""
    # Given a DummyReport definition respecting interface types
    # When instantiating the DummyReport
    report = DummyReport()
    # Then the report should have the correct attributes
    assert report.serial == "12345"  # noqa: S101 we indeed call assert in test
    # in fact we just check there is no error due to breaking changes


def test_report_should_raise_validation_error_with_incorrect_attribute():
    """Test that the Report raises a validation error with incorrect attributes."""

    # Given a DummyReport implementation not respecting interface types
    class IncorrectDummyReport(DummyReport):
        """Incorrect Dummy Report implementation for testing purposes."""

        @property
        def _serial(self) -> str:
            return 12345  # should be str

    # When instantiating the IncorrectDummyReport
    # Then a validation error should be raised
    with pytest.raises(ValidationError):
        _ = IncorrectDummyReport()


def test_reports_list_reports():
    """Test that the Reports list reports."""
    # Given a DummyReports instance
    reports = DummyReports()
    # When listing the reports
    reports_list = list(reports.list(since=datetime.datetime(2023, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)))
    # Then the reports list should not be empty
    assert len(reports_list) == 1  # noqa: S101 we indeed call assert in test
    # in fact we just check there is no error due to breaking changes
