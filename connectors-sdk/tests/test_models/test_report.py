import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import Reliability
from connectors_sdk.models.report import Report
from pydantic import ValidationError
from stix2.v21 import Report as Stix2Report


def test_report_is_a_base_identified_entity():
    """Test that Report is a BaseIdentifiedEntity."""
    # Given the Report class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Report, BaseIdentifiedEntity)


def test_report_class_should_not_accept_invalid_input():
    """Test that Report class should not accept invalid input."""
    # Given: An invalid input data for Report
    input_data = {
        "name": "Test report",
        "invalid_key": "invalid_value",
    }
    # When validating the report
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Report.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_report_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Report to_stix2_object method returns a valid STIX2.1 Report."""
    # Given: A valid Report instance
    report = Report(
        name="Test report",
        publication_date="2025-01-01T12:00:00Z",
        description="Test description",
        report_types=["Test report type"],
        reliability=Reliability.A,
        objects=[fake_valid_organization_author],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = report.to_stix2_object()
    # Then: A valid STIX2.1 Report is returned
    assert isinstance(stix2_obj, Stix2Report)
    assert isinstance(stix2_obj, Stix2Report)
