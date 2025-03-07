from datetime import datetime, timezone

import pytest
import stix2
from dragos.domain.models.octi import (
    ExternalReference,
    Indicator,
    KillChainPhase,
    Organization,
    OrganizationAuthor,
    Report,
    TLPMarking,
)
from dragos.domain.models.octi.enum import (
    IndicatorType,
    ObservableType,
    OrganizationType,
    PatternType,
    Platform,
    Reliability,
    ReportType,
    TLPLevel,
)
from pydantic import ValidationError


def fake_valid_organization_author():
    return OrganizationAuthor(name="Valid Author")


def fake_valid_tlp_marking():
    return TLPMarking(level=TLPLevel.RED.value)


def fake_external_reference():
    return ExternalReference(
        source_name="Test Source",
        description="Test Description",
        url="http://example.com",
        external_id="test_id",
    )


def fake_valid_indicator():
    return Indicator(
        name="Test Indicator",
        pattern="[url:value='http://example.com']",
        pattern_type=PatternType.STIX.value,
        observable_type=ObservableType.URL.value,
        author=fake_valid_organization_author(),
        markings=[fake_valid_tlp_marking()],
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Indicator",
                "description": "Test Indicator description",
                "pattern": "[url:value='http://example.com']",
                "pattern_type": PatternType.STIX.value,
                "indicator_types": [
                    indicator_type.value for indicator_type in IndicatorType
                ],
                "kill_chain_phases": [
                    KillChainPhase(
                        chain_name="Test Chain",
                        phase_name="Test Phase",
                    )
                ],
                "valid_from": datetime(1970, 1, 1, tzinfo=timezone.utc),
                "valid_until": datetime.now(tz=timezone.utc),
                "score": 50,
                "observable_type": ObservableType.URL.value,
                "platforms": [platform.value for platform in Platform],
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Indicator",
                "pattern": "[url:value='http://example.com']",
                "pattern_type": PatternType.STIX.value,
                "observable_type": ObservableType.URL.value,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_indicator_class_should_accept_valid_input(input_data):
    # Given: Valid indicator input data
    # When: Creating an indicator object
    indicator = Indicator.model_validate(input_data)

    # Then: The indicator object should be valid
    assert indicator.id is not None
    assert indicator.name == input_data.get("name")
    assert indicator.description == input_data.get("description")
    assert indicator.pattern == input_data.get("pattern")
    assert indicator.pattern_type == input_data.get("pattern_type")
    assert indicator.observable_type == input_data.get("observable_type")
    assert indicator.indicator_types == input_data.get("indicator_types")
    assert indicator.platforms == input_data.get("platforms")
    assert indicator.kill_chain_phases == input_data.get("kill_chain_phases")
    assert indicator.valid_from == input_data.get("valid_from")
    assert indicator.valid_until == input_data.get("valid_until")
    assert indicator.score == input_data.get("score")
    assert indicator.author == input_data.get("author")
    assert indicator.external_references == input_data.get("external_references")
    assert indicator.markings == input_data.get("markings")


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "name": "Test Indicator",
                "pattern_type": "random pattern type",
                "observable_type": ObservableType.URL.value,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "pattern",
            id="missing_pattern",
        ),
        pytest.param(
            {
                "name": "Test Indicator",
                "pattern": "[url:value='http://example.com']",
                "pattern_type": "random pattern type",
                "observable_type": ObservableType.URL.value,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "pattern_type",
            id="invalid_pattern_type",
        ),
        # pytest.param(
        #     {
        #         "name": "Test Indicator",
        #         "pattern": "[url:value='http://example.com']",
        #         "pattern_type": PatternType.STIX.value,
        #         "observable_type": ObservableType.URL.value,
        #         "markings": [fake_valid_tlp_marking()],
        #     },
        #     "author",
        #     id="missing_author",
        # ),
    ],
)
def test_indicator_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input data for the Indicator class
    # When: Trying to create a Indicator instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        Indicator.model_validate(input_data)
    assert str(error_field) in str(err)


def test_indicator_to_stix2_object_returns_valid_stix_object():
    # Given: A valid indicator
    input_data = {
        "name": "Test Indicator",
        "description": "Test Indicator description",
        "pattern": "[url:value='http://example.com']",
        "pattern_type": PatternType.STIX.value,
        "indicator_types": [indicator_type.value for indicator_type in IndicatorType],
        "kill_chain_phases": [
            KillChainPhase(
                chain_name="Test Chain",
                phase_name="Test Phase",
            )
        ],
        "valid_from": datetime(1970, 1, 1, tzinfo=timezone.utc),
        "valid_until": datetime.now(tz=timezone.utc),
        "score": 50,
        "platforms": [platform.value for platform in Platform],
        "observable_type": ObservableType.URL.value,
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    indicator = Indicator.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = indicator.to_stix2_object()

    # Then: A valid STIX2.1 Indicator is returned
    assert isinstance(stix2_obj, stix2.Indicator) is True
    assert stix2_obj.id is not None
    assert stix2_obj.name == input_data.get("name")
    assert stix2_obj.description == input_data.get("description")
    assert stix2_obj.pattern == input_data.get("pattern")
    assert stix2_obj.pattern_type == input_data.get("pattern_type")
    assert stix2_obj.indicator_types == input_data.get("indicator_types")
    assert stix2_obj.valid_from == input_data.get("valid_from")
    assert stix2_obj.valid_until == input_data.get("valid_until")
    assert stix2_obj.x_opencti_score == 50
    assert stix2_obj.x_mitre_platforms == input_data.get("platforms")
    assert stix2_obj.x_opencti_main_observable_type == input_data.get("observable_type")


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Organization",
                "description": "Test Organization description",
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
                "contact_information": "contact@example.com",
                "organization_type": OrganizationType.VENDOR.value,
                "reliability": Reliability.A.value,
                "aliases": ["Alias1", "Alias2"],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Organization",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_organization_class_should_accept_valid_input(input_data):
    # Given: Valid organization input data
    # When: Creating an organization object
    organization = Organization.model_validate(input_data)

    # Then: The organization object should be valid
    assert organization.id is not None
    assert organization.name == input_data.get("name")
    assert organization.description == input_data.get("description")
    assert organization.author == input_data.get("author")
    assert organization.external_references == input_data.get("external_references")
    assert organization.markings == input_data.get("markings")
    assert organization.contact_information == input_data.get("contact_information")
    assert organization.organization_type == input_data.get("organization_type")
    assert organization.reliability == input_data.get("reliability")
    assert organization.aliases == input_data.get("aliases")


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Organization description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
    ],
)
def test_organization_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input data for the Organization class
    # When: Trying to create an Organization instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        Organization.model_validate(input_data)
    assert str(error_field) in str(err)


def test_organization_to_stix2_object_returns_valid_stix_object():
    # Given: A valid organization
    input_data = {
        "name": "Test Organization",
        "description": "Test Organization description",
        "contact_information": "contact@example.com",
        "organization_type": OrganizationType.VENDOR.value,
        "reliability": Reliability.A.value,
        "aliases": ["Alias1", "Alias2"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    organization = Organization.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = organization.to_stix2_object()

    # Then: A valid STIX2.1 Identity is returned
    assert isinstance(stix2_obj, stix2.Identity) is True
    assert stix2_obj.id is not None
    assert stix2_obj.name == input_data.get("name")
    assert stix2_obj.description == input_data.get("description")
    assert stix2_obj.contact_information == input_data.get("contact_information")
    assert stix2_obj.x_opencti_organization_type == input_data.get("organization_type")
    assert stix2_obj.x_opencti_reliability == input_data.get("reliability")
    assert stix2_obj.x_opencti_aliases == input_data.get("aliases")


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Report",
                "description": "Test Report description",
                "publication_date": datetime.now(tz=timezone.utc),
                "report_types": [report_type.value for report_type in ReportType],
                "reliability": Reliability.A.value,
                "objects": [fake_valid_indicator()],
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Report",
                "publication_date": datetime.now(tz=timezone.utc),
                "objects": [fake_valid_indicator()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_report_class_should_accept_valid_input(input_data):
    # Given: Valid report input data
    # When: Creating a report object
    report = Report.model_validate(input_data)

    # Then: The report object should be valid
    assert report.id is not None
    assert report.name == input_data.get("name")
    assert report.publication_date == input_data.get("publication_date")
    assert report.report_types == input_data.get("report_types")
    assert report.reliability == input_data.get("reliability")
    assert report.description == input_data.get("description")
    assert report.author == input_data.get("author")
    assert report.external_references == input_data.get("external_references")
    assert report.markings == input_data.get("markings")
    assert report.objects == input_data.get("objects")


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "publication_date": datetime.now(tz=timezone.utc),
                "objects": [fake_valid_organization_author()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Report",
                "objects": [fake_valid_organization_author()],
            },
            "publication_date",
            id="missing_publication_date",
        ),
    ],
)
def test_report_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input data for the Report class
    # When: Trying to create a Report instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        Report.model_validate(input_data)
    assert str(error_field) in str(err)


def test_report_to_stix2_object_returns_valid_stix_object():
    # Given: A valid report
    input_data = {
        "name": "Test Report",
        "publication_date": datetime.now(tz=timezone.utc),
        "report_types": [report_type.value for report_type in ReportType],
        "reliability": Reliability.A.value,
        "description": "Test Report description",
        "objects": [fake_valid_organization_author()],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    report = Report.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = report.to_stix2_object()

    # Then: A valid STIX2.1 Report is returned
    assert isinstance(stix2_obj, stix2.Report) is True
    assert stix2_obj.id is not None
    assert stix2_obj.name == input_data.get("name")
    assert stix2_obj.description == input_data.get("description")
    assert stix2_obj.published == input_data.get("publication_date")
    assert stix2_obj.report_types == input_data.get("report_types")
    assert stix2_obj.x_opencti_reliability == input_data.get("reliability")
    assert stix2_obj.object_refs == [obj.id for obj in input_data.get("objects")]
