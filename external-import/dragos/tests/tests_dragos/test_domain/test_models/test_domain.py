from datetime import datetime, timezone

import pytest
import stix2
import dragos.domain.models.octi as octi
import dragos.domain.models.octi.enum as octi_enums
from pydantic import ValidationError


def fake_valid_organization_author():
    return octi.OrganizationAuthor(name="Valid Author")


def fake_valid_tlp_marking():
    return octi.TLPMarking(level=octi_enums.TLPLevel.RED.value)


def fake_external_reference():
    return octi.ExternalReference(
        source_name="Test Source",
        description="Test Description",
        url="http://example.com",
        external_id="test_id",
    )


def fake_valid_indicator():
    return octi.Indicator(
        name="Test Indicator",
        pattern="[url:value='http://example.com']",
        pattern_type=octi_enums.PatternType.STIX.value,
        observable_type=octi_enums.ObservableType.URL.value,
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
                "pattern_type": octi_enums.PatternType.STIX.value,
                "indicator_types": [
                    indicator_type.value for indicator_type in octi_enums.IndicatorType
                ],
                "kill_chain_phases": [
                    octi.KillChainPhase(
                        chain_name="Test Chain",
                        phase_name="Test Phase",
                    )
                ],
                "valid_from": datetime(1970, 1, 1, tzinfo=timezone.utc),
                "valid_until": datetime.now(tz=timezone.utc),
                "score": 50,
                "observable_type": octi_enums.ObservableType.URL.value,
                "platforms": [platform.value for platform in octi_enums.Platform],
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
                "pattern_type": octi_enums.PatternType.STIX.value,
                "observable_type": octi_enums.ObservableType.URL.value,
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
    indicator = octi.Indicator.model_validate(input_data)

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
                "pattern_type": octi_enums.PatternType.STIX.value,
                "observable_type": octi_enums.ObservableType.URL.value,
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
                "pattern_type": octi_enums.PatternType.STIX.value,
                "observable_type": "random observable",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "observable_type",
            id="invalid_observable_type",
        ),
        # pytest.param(
        #     {
        #         "name": "Test Indicator",
        #         "pattern": "[url:value='http://example.com']",
        #         "pattern_type": octi_enums.PatternType.STIX.value,
        #         "observable_type": octi_enums.ObservableType.URL.value,
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
        octi.Indicator.model_validate(input_data)
    assert str(error_field) in str(err)


def test_indicator_to_stix2_object_returns_valid_stix_object():
    # Given: A valid indicator
    input_data = {
        "name": "Test Indicator",
        "description": "Test Indicator description",
        "pattern": "[url:value='http://example.com']",
        "pattern_type": octi_enums.PatternType.STIX.value,
        "indicator_types": [
            indicator_type.value for indicator_type in octi_enums.IndicatorType
        ],
        "kill_chain_phases": [
            octi.KillChainPhase(
                chain_name="Test Chain",
                phase_name="Test Phase",
            )
        ],
        "valid_from": datetime(1970, 1, 1, tzinfo=timezone.utc),
        "valid_until": datetime.now(tz=timezone.utc),
        "score": 50,
        "platforms": [platform.value for platform in octi_enums.Platform],
        "observable_type": octi_enums.ObservableType.URL.value,
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    indicator = octi.Indicator.model_validate(input_data)

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
                "name": "Test Intrusion Set",
                "description": "Test Intrusion Set description",
                "aliases": ["alias1", "alias2"],
                "first_seen": datetime(1970, 1, 1, tzinfo=timezone.utc),
                "last_seen": datetime.now(tz=timezone.utc),
                "goals": ["goal1", "goal2"],
                "resource_level": octi_enums.AttackResourceLevel.CLUB.value,
                "primary_motivation": octi_enums.AttackMotivation.ACCIDENTAL.value,
                "secondary_motivations": [
                    attack_motivation.value
                    for attack_motivation in octi_enums.AttackMotivation
                ],
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Intrusion Set",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_intrusion_set_class_should_accept_valid_input(input_data):
    # Given: Valid intrusion set input data
    # When: Creating an intrusion set object
    intrusion_set = octi.IntrusionSet.model_validate(input_data)

    # Then: The intrusion set object should be valid
    assert intrusion_set.id is not None
    assert intrusion_set.name == input_data.get("name")
    assert intrusion_set.description == input_data.get("description")
    assert intrusion_set.aliases == input_data.get("aliases")
    assert intrusion_set.first_seen == input_data.get("first_seen")
    assert intrusion_set.last_seen == input_data.get("last_seen")
    assert intrusion_set.goals == input_data.get("goals")
    assert intrusion_set.resource_level == input_data.get("resource_level")
    assert intrusion_set.primary_motivation == input_data.get("primary_motivation")
    assert intrusion_set.secondary_motivations == input_data.get(
        "secondary_motivations"
    )
    assert intrusion_set.author == input_data.get("author")
    assert intrusion_set.external_references == input_data.get("external_references")
    assert intrusion_set.markings == input_data.get("markings")


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Intrusion Set description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Intrusion Set",
                "aliases": "alias",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "aliases",
            id="invalid_aliases_type",
        ),
        # pytest.param(
        #     {
        #         "name": "Test IntrusionSet",
        #         "pattern": "[url:value='http://example.com']",
        #         "pattern_type": octi_enums.PatternType.STIX.value,
        #         "observable_type": octi_enums.ObservableType.URL.value,
        #         "markings": [fake_valid_tlp_marking()],
        #     },
        #     "author",
        #     id="missing_author",
        # ),
    ],
)
def test_intrusion_set_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input data for the IntrusionSet class
    # When: Trying to create a IntrusionSet instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.IntrusionSet.model_validate(input_data)
    assert str(error_field) in str(err)


def test_intrusion_set_to_stix2_object_returns_valid_stix_object():
    # Given: A valid intrusion set
    input_data = {
        "name": "Test Intrusion Set",
        "description": "Test Intrusion Set description",
        "aliases": ["alias1", "alias2"],
        "first_seen": datetime(1970, 1, 1, tzinfo=timezone.utc),
        "last_seen": datetime.now(tz=timezone.utc),
        "goals": ["goal1", "goal2"],
        "resource_level": octi_enums.AttackResourceLevel.CLUB.value,
        "primary_motivation": octi_enums.AttackMotivation.ACCIDENTAL.value,
        "secondary_motivations": [
            attack_motivation.value for attack_motivation in octi_enums.AttackMotivation
        ],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    intrusion_set = octi.IntrusionSet.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = intrusion_set.to_stix2_object()

    # Then: A valid STIX2.1 IntrusionSet is returned
    assert isinstance(stix2_obj, stix2.IntrusionSet) is True
    assert stix2_obj.id is not None
    assert stix2_obj.name == input_data.get("name")
    assert stix2_obj.description == input_data.get("description")
    assert stix2_obj.aliases == input_data.get("aliases")
    assert stix2_obj.first_seen == input_data.get("first_seen")
    assert stix2_obj.last_seen == input_data.get("last_seen")
    assert stix2_obj.goals == input_data.get("goals")
    assert stix2_obj.resource_level == input_data.get("resource_level")
    assert stix2_obj.primary_motivation == input_data.get("primary_motivation")
    assert stix2_obj.secondary_motivations == input_data.get("secondary_motivations")


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Malware",
                "is_family": False,
                "description": "Test Malware description",
                "aliases": ["alias1", "alias2"],
                "types": [
                    malware_type.value for malware_type in octi_enums.MalwareType
                ],
                "first_seen": datetime(1970, 1, 1, tzinfo=timezone.utc),
                "last_seen": datetime.now(tz=timezone.utc),
                "architecture_execution_envs": [
                    processor_architecture.value
                    for processor_architecture in octi_enums.ProcessorArchitecture
                ],
                "implementation_languages": [
                    implementation_language.value
                    for implementation_language in octi_enums.ImplementationLanguage
                ],
                "kill_chain_phases": [
                    octi.KillChainPhase(
                        chain_name="Test Chain",
                        phase_name="Test Phase",
                    )
                ],
                "capabilities": [
                    capability.value for capability in octi_enums.MalwareCapability
                ],
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Malware",
                "is_family": False,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_malware_class_should_accept_valid_input(input_data):
    # Given: Valid malware input data
    # When: Creating an malware object
    malware = octi.Malware.model_validate(input_data)

    # Then: The malware object should be valid
    assert malware.id is not None
    assert malware.name == input_data.get("name")
    assert malware.is_family == input_data.get("is_family")
    assert malware.description == input_data.get("description")
    assert malware.aliases == input_data.get("aliases")
    assert malware.types == input_data.get("types")
    assert malware.first_seen == input_data.get("first_seen")
    assert malware.last_seen == input_data.get("last_seen")
    assert malware.architecture_execution_envs == input_data.get(
        "architecture_execution_envs"
    )
    assert malware.implementation_languages == input_data.get(
        "implementation_languages"
    )
    assert malware.kill_chain_phases == input_data.get("kill_chain_phases")
    assert malware.capabilities == input_data.get("capabilities")
    assert malware.author == input_data.get("author")
    assert malware.external_references == input_data.get("external_references")
    assert malware.markings == input_data.get("markings")


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "is_family": False,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Malware",
                "is_family": 42,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "is_family",
            id="invalid_is_family_type",
        ),
        # pytest.param(
        #     {
        #         "name": "Test Malware",
        #         "is_family": False,
        #         "markings": [fake_valid_tlp_marking()],
        #     },
        #     "author",
        #     id="missing_author",
        # ),
    ],
)
def test_malware_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input data for the Malware class
    # When: Trying to create a Malware instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.Malware.model_validate(input_data)
    assert str(error_field) in str(err)


def test_malware_to_stix2_object_returns_valid_stix_object():
    # Given: A valid malware
    input_data = {
        "name": "Test Malware",
        "is_family": False,
        "description": "Test Malware description",
        "aliases": ["alias1", "alias2"],
        "types": [malware_type.value for malware_type in octi_enums.MalwareType],
        "first_seen": datetime(1970, 1, 1, tzinfo=timezone.utc),
        "last_seen": datetime.now(tz=timezone.utc),
        "architecture_execution_envs": [
            processor_architecture.value
            for processor_architecture in octi_enums.ProcessorArchitecture
        ],
        "implementation_languages": [
            implementation_language.value
            for implementation_language in octi_enums.ImplementationLanguage
        ],
        "kill_chain_phases": [
            octi.KillChainPhase(
                chain_name="Test Chain",
                phase_name="Test Phase",
            )
        ],
        "capabilities": [
            capability.value for capability in octi_enums.MalwareCapability
        ],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    malware = octi.Malware.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = malware.to_stix2_object()

    # Then: A valid STIX2.1 Malware is returned
    assert isinstance(stix2_obj, stix2.Malware) is True
    assert stix2_obj.id is not None
    assert stix2_obj.name == input_data.get("name")
    assert stix2_obj.is_family == input_data.get("is_family")
    assert stix2_obj.description == input_data.get("description")
    assert stix2_obj.aliases == input_data.get("aliases")
    assert stix2_obj.malware_types == input_data.get("types")
    assert stix2_obj.first_seen == input_data.get("first_seen")
    assert stix2_obj.last_seen == input_data.get("last_seen")
    assert stix2_obj.architecture_execution_envs == input_data.get(
        "architecture_execution_envs"
    )
    assert stix2_obj.implementation_languages == input_data.get(
        "implementation_languages"
    )
    assert stix2_obj.kill_chain_phases == [
        kill_chain_phase.to_stix2_object()
        for kill_chain_phase in input_data.get("kill_chain_phases")
    ]
    assert stix2_obj.capabilities == input_data.get("capabilities")


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
                "organization_type": octi_enums.OrganizationType.VENDOR.value,
                "reliability": octi_enums.Reliability.A.value,
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
    organization = octi.Organization.model_validate(input_data)

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
        octi.Organization.model_validate(input_data)
    assert str(error_field) in str(err)


def test_organization_to_stix2_object_returns_valid_stix_object():
    # Given: A valid organization
    input_data = {
        "name": "Test Organization",
        "description": "Test Organization description",
        "contact_information": "contact@example.com",
        "organization_type": octi_enums.OrganizationType.VENDOR.value,
        "reliability": octi_enums.Reliability.A.value,
        "aliases": ["Alias1", "Alias2"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    organization = octi.Organization.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = organization.to_stix2_object()

    # Then: A valid STIX2.1 Identity is returned
    assert isinstance(stix2_obj, stix2.Identity) is True
    assert stix2_obj.id is not None
    assert stix2_obj.identity_class == octi_enums.IdentityClass.ORGANIZATION.value
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
                "report_types": [
                    report_type.value for report_type in octi_enums.ReportType
                ],
                "reliability": octi_enums.Reliability.A.value,
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
    report = octi.Report.model_validate(input_data)

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
        octi.Report.model_validate(input_data)
    assert str(error_field) in str(err)


def test_report_to_stix2_object_returns_valid_stix_object():
    # Given: A valid report
    input_data = {
        "name": "Test Report",
        "publication_date": datetime.now(tz=timezone.utc),
        "report_types": [report_type.value for report_type in octi_enums.ReportType],
        "reliability": octi_enums.Reliability.A.value,
        "description": "Test Report description",
        "objects": [fake_valid_organization_author()],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    report = octi.Report.model_validate(input_data)

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


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Sector",
                "description": "Test Sector description",
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
                "sectors": [
                    industry_sector.value
                    for industry_sector in octi_enums.IndustrySector
                ],
                "reliability": octi_enums.Reliability.A.value,
                "aliases": ["Alias1", "Alias2"],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Sector",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_sector_class_should_accept_valid_input(input_data):
    # Given: Valid sector input data
    # When: Creating an sector object
    sector = octi.Sector.model_validate(input_data)

    # Then: The sector object should be valid
    assert sector.id is not None
    assert sector.name == input_data.get("name")
    assert sector.description == input_data.get("description")
    assert sector.author == input_data.get("author")
    assert sector.external_references == input_data.get("external_references")
    assert sector.markings == input_data.get("markings")
    assert sector.sectors == input_data.get("sectors")
    assert sector.reliability == input_data.get("reliability")
    assert sector.aliases == input_data.get("aliases")


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Sector description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
    ],
)
def test_sector_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input data for the Sector class
    # When: Trying to create an Sector instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.Sector.model_validate(input_data)
    assert str(error_field) in str(err)


def test_sector_to_stix2_object_returns_valid_stix_object():
    # Given: A valid sector
    input_data = {
        "name": "Test Sector",
        "description": "Test Sector description",
        "sectors": [
            industry_sector.value for industry_sector in octi_enums.IndustrySector
        ],
        "reliability": octi_enums.Reliability.A.value,
        "aliases": ["Alias1", "Alias2"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    sector = octi.Sector.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = sector.to_stix2_object()

    # Then: A valid STIX2.1 Identity is returned
    assert isinstance(stix2_obj, stix2.Identity) is True
    assert stix2_obj.id is not None
    assert stix2_obj.identity_class == octi_enums.IdentityClass.CLASS.value
    assert stix2_obj.name == input_data.get("name")
    assert stix2_obj.description == input_data.get("description")
    assert stix2_obj.sectors == input_data.get("sectors")
    assert stix2_obj.x_opencti_reliability == input_data.get("reliability")
    assert stix2_obj.x_opencti_aliases == input_data.get("aliases")


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Vulnerability",
                "description": "Test Vulnerability description",
                "aliases": ["alias1", "alias2"],
                "cvss_score": 0,
                "cvss_severity": octi_enums.CvssSeverity.CRITICAL.value,
                "cvss_attack_vector": "attack_vector",
                "cvss_integrity_impact": "integrity impact",
                "cvss_availability_impact": "availability impact",
                "cvss_confidentiality_impact": "confidentiality impact",
                "is_cisa_kev": False,
                "epss_score": 0,
                "epss_percentile": 0,
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Vulnerability",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_vulnerability_class_should_accept_valid_input(input_data):
    # Given: Valid vulnerability input data
    # When: Creating an vulnerability object
    vulnerability = octi.Vulnerability.model_validate(input_data)

    # Then: The vulnerability object should be valid
    assert vulnerability.id is not None
    assert vulnerability.name == input_data.get("name")
    assert vulnerability.description == input_data.get("description")
    assert vulnerability.aliases == input_data.get("aliases")
    assert vulnerability.cvss_score == input_data.get("cvss_score")
    assert vulnerability.cvss_severity == input_data.get("cvss_severity")
    assert vulnerability.cvss_attack_vector == input_data.get("cvss_attack_vector")
    assert vulnerability.cvss_integrity_impact == input_data.get(
        "cvss_integrity_impact"
    )
    assert vulnerability.cvss_availability_impact == input_data.get(
        "cvss_availability_impact"
    )
    assert vulnerability.cvss_confidentiality_impact == input_data.get(
        "cvss_confidentiality_impact"
    )
    assert vulnerability.is_cisa_kev == input_data.get("is_cisa_kev")
    assert vulnerability.epss_score == input_data.get("epss_score")
    assert vulnerability.epss_percentile == input_data.get("epss_percentile")


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Vulnerability description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
    ],
)
def test_vulnerability_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input data for the Vulnerability class
    # When: Trying to create an Vulnerability instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.Vulnerability.model_validate(input_data)
    assert str(error_field) in str(err)


def test_vulnerability_to_stix2_object_returns_valid_stix_object():
    # Given: A valid vulnerability
    input_data = {
        "name": "Test Vulnerability",
        "description": "Test Vulnerability description",
        "aliases": ["alias1", "alias2"],
        "cvss_score": 0,
        "cvss_severity": octi_enums.CvssSeverity.CRITICAL.value,
        "cvss_attack_vector": "attack_vector",
        "cvss_integrity_impact": "integrity impact",
        "cvss_availability_impact": "availability impact",
        "cvss_confidentiality_impact": "confidentiality impact",
        "is_cisa_kev": False,
        "epss_score": 0,
        "epss_percentile": 0,
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    vulnerability = octi.Vulnerability.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = vulnerability.to_stix2_object()

    # Then: A valid STIX2.1 Identity is returned
    assert isinstance(stix2_obj, stix2.Vulnerability) is True
    assert stix2_obj.id is not None
    assert stix2_obj.name == input_data.get("name")
    assert stix2_obj.description == input_data.get("description")
    assert stix2_obj.x_opencti_aliases == input_data.get("aliases")
    assert stix2_obj.x_opencti_cvss_base_score == input_data.get("cvss_score")
    assert stix2_obj.x_opencti_cvss_base_severity == input_data.get("cvss_severity")
    assert stix2_obj.x_opencti_cvss_attack_vector == input_data.get(
        "cvss_attack_vector"
    )
    assert stix2_obj.x_opencti_cvss_integrity_impact == input_data.get(
        "cvss_integrity_impact"
    )
    assert stix2_obj.x_opencti_cvss_availability_impact == input_data.get(
        "cvss_availability_impact"
    )
    assert stix2_obj.x_opencti_cvss_confidentiality_impact == input_data.get(
        "cvss_confidentiality_impact"
    )
    assert stix2_obj.x_opencti_cisa_kev == input_data.get("is_cisa_kev")
    assert stix2_obj.x_opencti_epss_score == input_data.get("epss_score")
    assert stix2_obj.x_opencti_epss_percentile == input_data.get("epss_percentile")
