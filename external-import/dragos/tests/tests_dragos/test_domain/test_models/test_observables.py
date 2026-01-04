"""Offer tests for the OCTI observable classes."""

from datetime import datetime, timezone

import pytest
import stix2
from dragos.domain.models import octi
from dragos.domain.models.octi.enums import (
    ObservableType,
    PatternType,
    TLPLevel,
)
from pydantic import ValidationError


def fake_valid_organization_author():
    """Return a valid Organization Author."""
    return octi.OrganizationAuthor(name="Valid Author")


def fake_valid_tlp_marking():
    """Return a valid TLP Marking."""
    return octi.TLPMarking(level=TLPLevel.RED.value)


def fake_valid_external_reference():
    """Return a valid External Reference."""
    return octi.ExternalReference(
        source_name="Test Source",
        description="Test Description",
        url="http://example.com",
        external_id="test_id",
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "example.com",
                "score": 50,
                "description": "Example description",
                "labels": ["example_label"],
                "author": fake_valid_organization_author(),
                "external_references": [fake_valid_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "value": "example.com",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_domain_name_class_should_accept_valid_input(input_data):
    """Test that DomainName class should accept valid input data."""
    domain_name = octi.DomainName.model_validate(input_data)
    assert (  # noqa S101
        domain_name.id is not None and domain_name.value == input_data.get("value")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "value",
            id="missing_value",
        ),
    ],
)
def test_domain_name_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that DomainName class should not accept invalid input."""
    with pytest.raises(ValidationError) as err:
        octi.DomainName.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa S101


def test_domain_name_to_stix2_object_returns_valid_stix_object():
    """Test that DomainName to_stix2_object method returns a valid STIX2.1 DomainName."""
    # Given: A valid domain name
    input_data = {
        "value": "example.com",
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    domain_name = octi.DomainName.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = domain_name.to_stix2_object()

    # Then: A valid STIX2.1 DomainName is returned
    assert (  # noqa S101
        isinstance(stix2_obj, stix2.DomainName) is True
        and stix2_obj.id is not None
        and stix2_obj.value == input_data.get("value")
        and stix2_obj.object_marking_refs
        == [marking.id for marking in input_data.get("markings")]
        and stix2_obj.x_opencti_score == input_data.get("score")
        and stix2_obj.x_opencti_description == input_data.get("description")
        and stix2_obj.x_opencti_labels == input_data.get("labels")
        and stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
        and stix2_obj.x_opencti_external_references
        == [
            external_reference.to_stix2_object()
            for external_reference in input_data.get("external_references")
        ]
    )


def test_domain_name_to_indicator_returns_valid_octi_indicator():
    """Test that DomainName to_indicator method returns a valid OCTI Indicator."""
    # Given: A valid domain name
    input_data = {
        "value": "example.com",
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    domain_name = octi.DomainName.model_validate(input_data)

    # When: calling to_indicator method
    valid_from = datetime(1970, 1, 1, tzinfo=timezone.utc)
    valid_until = datetime.now(tz=timezone.utc)
    indicator = domain_name.to_indicator(valid_from, valid_until)

    # Then: A valid OCTI Indicator is returned
    assert (  # noqa S101
        isinstance(indicator, octi.Indicator) is True
        and indicator.id is not None
        and indicator.name == input_data.get("value")
        and indicator.pattern == f"[domain-name:value='{input_data.get('value')}']"
        and indicator.pattern_type == PatternType.STIX.value
        and indicator.observable_type == ObservableType.DOMAIN_NAME.value
        and indicator.description == input_data.get("description")
        and indicator.valid_from == valid_from
        and indicator.valid_until == valid_until
        and indicator.score == input_data.get("score")
        and indicator.author == input_data.get("author")
        and indicator.markings == input_data.get("markings")
        and indicator.external_references == input_data.get("external_references")
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "hashes": {"MD5": "44d88612fea8a8f36de82e1278abb02f"},
                "size": 1024,
                "name": "example.txt",
                "score": 50,
                "description": "Example description",
                "labels": ["example_label"],
                "author": fake_valid_organization_author(),
                "external_references": [fake_valid_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "hashes": {"MD5": "44d88612fea8a8f36de82e1278abb02f"},
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_file_class_should_accept_valid_input(input_data):
    """Test that File class should accept valid input data."""
    file = octi.File.model_validate(input_data)
    assert (  # noqa S101
        file.id is not None
        and file.hashes == input_data.get("hashes")
        and file.size == input_data.get("size")
        and file.name == input_data.get("name")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "size": 1024,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "hashes",
            id="missing_name_and_hashes",
        ),
    ],
)
def test_file_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that File class should not accept invalid input."""
    with pytest.raises(ValidationError) as err:
        octi.File.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa S101


def test_file_to_stix2_object_returns_valid_stix_object():
    """Test that File to_stix2_object method returns a valid STIX2.1 File."""
    # Given: A valid file
    input_data = {
        "hashes": {"MD5": "44d88612fea8a8f36de82e1278abb02f"},
        "size": 1024,
        "name": "example.txt",
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    file = octi.File.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = file.to_stix2_object()

    # Then: A valid STIX2.1 File is returned
    assert (  # noqa S101
        isinstance(stix2_obj, stix2.File) is True
        and stix2_obj.id is not None
        and stix2_obj.hashes == input_data.get("hashes")
        and stix2_obj.size == input_data.get("size")
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.object_marking_refs
        == [marking.id for marking in input_data.get("markings")]
        and stix2_obj.x_opencti_score == input_data.get("score")
        and stix2_obj.x_opencti_description == input_data.get("description")
        and stix2_obj.x_opencti_labels == input_data.get("labels")
        and stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
        and stix2_obj.x_opencti_external_references
        == [
            external_reference.to_stix2_object()
            for external_reference in input_data.get("external_references")
        ]
    )


def test_file_to_indicator_returns_valid_octi_indicator():
    """Test that File to_indicator method returns a valid OCTI Indicator."""
    # Given: A valid file
    input_data = {
        "hashes": {"MD5": "44d88612fea8a8f36de82e1278abb02f"},
        "size": 1024,
        "name": "example.txt",
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    file = octi.File.model_validate(input_data)

    # When: calling to_indicator method
    valid_from = datetime(1970, 1, 1, tzinfo=timezone.utc)
    valid_until = datetime.now(tz=timezone.utc)
    indicator = file.to_indicator(valid_from, valid_until)

    # Then: A valid OCTI Indicator is returned
    assert (  # noqa S101
        isinstance(indicator, octi.Indicator) is True
        and indicator.id is not None
        and indicator.name == input_data.get("name")
        and indicator.pattern
        == f"[file:name='{input_data.get('name')}' AND file:hashes.'MD5'='{input_data.get('hashes')['MD5']}']"
        and indicator.pattern_type == PatternType.STIX.value
        and indicator.observable_type == ObservableType.FILE.value
        and indicator.description == input_data.get("description")
        and indicator.valid_from == valid_from
        and indicator.valid_until == valid_until
        and indicator.score == input_data.get("score")
        and indicator.author == input_data.get("author")
        and indicator.markings == input_data.get("markings")
        and indicator.external_references == input_data.get("external_references")
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "165.3.228.230",
                "score": 50,
                "description": "Example description",
                "labels": ["example_label"],
                "author": fake_valid_organization_author(),
                "external_references": [fake_valid_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "value": "165.3.228.230",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_ip_v4_class_should_accept_valid_input(input_data):
    """Test that IPV4Address class should accept valid input data."""
    ip_v4 = octi.IPV4Address.model_validate(input_data)
    assert (  # noqa S101
        ip_v4.id is not None
        and ip_v4.value == input_data.get("value")
        and ip_v4.score == input_data.get("score")
        and ip_v4.description == input_data.get("description")
        and ip_v4.labels == input_data.get("labels")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "value": "any string",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "value",
            id="invalid_value",
        ),
    ],
)
def test_ip_v4_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that IPV4Address class should not accept invalid input."""
    with pytest.raises(ValidationError) as err:
        octi.IPV4Address.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa S101


def test_ip_v4_address_to_stix2_object_returns_valid_stix_object():
    """Test that IPV4Address to_stix2_object method returns a valid STIX2.1 IPV4Address."""
    # Given: A valid IP v4 address
    input_data = {
        "value": "165.3.228.230",
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    ip_v4_address = octi.IPV4Address.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = ip_v4_address.to_stix2_object()

    # Then: A valid STIX2.1 IPV4Address is returned
    assert (  # noqa S101
        isinstance(stix2_obj, stix2.IPv4Address) is True
        and stix2_obj.id is not None
        and stix2_obj.value == input_data.get("value")
        and stix2_obj.object_marking_refs
        == [marking.id for marking in input_data.get("markings")]
        and stix2_obj.x_opencti_score == input_data.get("score")
        and stix2_obj.x_opencti_description == input_data.get("description")
        and stix2_obj.x_opencti_labels == input_data.get("labels")
        and stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
        and stix2_obj.x_opencti_external_references
        == [
            external_reference.to_stix2_object()
            for external_reference in input_data.get("external_references")
        ]
    )


def test_ip_v4_to_indicator_returns_valid_octi_indicator():
    """Test that IPV4Address to_indicator method returns a valid OCTI Indicator."""
    # Given: A valid IP v4 address
    input_data = {
        "value": "165.3.228.230",
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    ip_v4_address = octi.IPV4Address.model_validate(input_data)

    # When: calling to_indicator method
    valid_from = datetime(1970, 1, 1, tzinfo=timezone.utc)
    valid_until = datetime.now(tz=timezone.utc)
    indicator = ip_v4_address.to_indicator(valid_from, valid_until)

    # Then: A valid OCTI Indicator is returned
    assert (  # noqa S101
        isinstance(indicator, octi.Indicator) is True
        and indicator.id is not None
        and indicator.name == input_data.get("value")
        and indicator.pattern == f"[ipv4-addr:value='{input_data.get('value')}']"
        and indicator.pattern_type == PatternType.STIX.value
        and indicator.observable_type == ObservableType.IPV4_ADDR.value
        and indicator.description == input_data.get("description")
        and indicator.valid_from == valid_from
        and indicator.valid_until == valid_until
        and indicator.score == input_data.get("score")
        and indicator.author == input_data.get("author")
        and indicator.markings == input_data.get("markings")
        and indicator.external_references == input_data.get("external_references")
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "9042:6eb5:1b3b:ef30:92f0:375c:a227:b4be",
                "score": 50,
                "description": "Example description",
                "labels": ["example_label"],
                "author": fake_valid_organization_author(),
                "external_references": [fake_valid_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "value": "9042:6eb5:1b3b:ef30:92f0:375c:a227:b4be",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_ip_v6_class_should_accept_valid_input(input_data):
    """Test that IPV6Address class should accept valid input data."""
    ip_v6 = octi.IPV6Address.model_validate(input_data)
    assert (  # noqa S101
        ip_v6.id is not None
        and ip_v6.value == input_data.get("value")
        and ip_v6.score == input_data.get("score")
        and ip_v6.description == input_data.get("description")
        and ip_v6.labels == input_data.get("labels")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "value": "any string",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "value",
            id="invalid_value",
        ),
    ],
)
def test_ip_v6_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that IPV6Address class should not accept invalid input."""
    with pytest.raises(ValidationError) as err:
        octi.IPV6Address.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa S101


def test_ip_v6_address_to_stix2_object_returns_valid_stix_object():
    """Test that IPV6Address to_stix2_object method returns a valid STIX2.1 IPV6Address."""
    # Given: A valid IP v6 address
    input_data = {
        "value": "9042:6eb5:1b3b:ef30:92f0:375c:a227:b4be",
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    ip_v6_address = octi.IPV6Address.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = ip_v6_address.to_stix2_object()

    # Then: A valid STIX2.1 IPV6Address is returned
    assert (  # noqa S101
        isinstance(stix2_obj, stix2.IPv6Address) is True
        and stix2_obj.id is not None
        and stix2_obj.value == input_data.get("value")
        and stix2_obj.object_marking_refs
        == [marking.id for marking in input_data.get("markings")]
        and stix2_obj.x_opencti_score == input_data.get("score")
        and stix2_obj.x_opencti_description == input_data.get("description")
        and stix2_obj.x_opencti_labels == input_data.get("labels")
        and stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
        and stix2_obj.x_opencti_external_references
        == [
            external_reference.to_stix2_object()
            for external_reference in input_data.get("external_references")
        ]
    )


def test_ip_v6_to_indicator_returns_valid_octi_indicator():
    """Test that IPV6Address to_indicator method returns a valid OCTI Indicator."""
    # Given: A valid IP v6 address
    input_data = {
        "value": "9042:6eb5:1b3b:ef30:92f0:375c:a227:b4be",
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    ip_v6_address = octi.IPV6Address.model_validate(input_data)

    # When: calling to_indicator method
    valid_from = datetime(1970, 1, 1, tzinfo=timezone.utc)
    valid_until = datetime.now(tz=timezone.utc)
    indicator = ip_v6_address.to_indicator(valid_from, valid_until)

    # Then: A valid OCTI Indicator is returned
    assert (  # noqa S101
        isinstance(indicator, octi.Indicator) is True
        and indicator.id is not None
        and indicator.name == input_data.get("value")
        and indicator.pattern == f"[ipv6-addr:value='{input_data.get('value')}']"
        and indicator.pattern_type == PatternType.STIX.value
        and indicator.observable_type == ObservableType.IPV6_ADDR.value
        and indicator.description == input_data.get("description")
        and indicator.valid_from == valid_from
        and indicator.valid_until == valid_until
        and indicator.score == input_data.get("score")
        and indicator.author == input_data.get("author")
        and indicator.markings == input_data.get("markings")
        and indicator.external_references == input_data.get("external_references")
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "example.com",
                "score": 50,
                "description": "Example description",
                "labels": ["example_label"],
                "author": fake_valid_organization_author(),
                "external_references": [fake_valid_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "value": "example.com",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_url_class_should_accept_valid_input(input_data):
    """Test that URL class should accept valid input."""
    url = octi.Url.model_validate(input_data)
    assert url.id is not None and url.value == input_data.get("value")  # noqa S101


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "value",
            id="missing_value",
        ),
    ],
)
def test_url_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that URL class should not accept invalid input."""
    with pytest.raises(ValidationError) as err:
        octi.Url.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa S101


def test_url_to_stix2_object_returns_valid_stix_object():
    """Test that URL to_stix2_object method returns a valid STIX2.1 URL."""
    # Given: A valid url
    input_data = {
        "value": "example.com",
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    url = octi.Url.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = url.to_stix2_object()

    # Then: A valid STIX2.1 URL is returned
    assert (  # noqa S101
        isinstance(stix2_obj, stix2.URL) is True
        and stix2_obj.id is not None
        and stix2_obj.value == input_data.get("value")
        and stix2_obj.object_marking_refs
        == [marking.id for marking in input_data.get("markings")]
        and stix2_obj.x_opencti_score == input_data.get("score")
        and stix2_obj.x_opencti_description == input_data.get("description")
        and stix2_obj.x_opencti_labels == input_data.get("labels")
        and stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
        and stix2_obj.x_opencti_external_references
        == [
            external_reference.to_stix2_object()
            for external_reference in input_data.get("external_references")
        ]
    )


def test_url_to_indicator_returns_valid_octi_indicator():
    """Test that URL to_indicator method returns a valid OCTI Indicator."""
    # Given: A valid url
    input_data = {
        "value": "example.com",
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    url = octi.Url.model_validate(input_data)

    # When: calling to_indicator method
    valid_from = datetime(1970, 1, 1, tzinfo=timezone.utc)
    valid_until = datetime.now(tz=timezone.utc)
    indicator = url.to_indicator(valid_from, valid_until)

    # Then: A valid OCTI Indicator is returned
    assert (  # noqa S101
        isinstance(indicator, octi.Indicator) is True
        and indicator.id is not None
        and indicator.name == input_data.get("value")
        and indicator.pattern == f"[url:value='{input_data.get('value')}']"
        and indicator.pattern_type == PatternType.STIX.value
        and indicator.observable_type == ObservableType.URL.value
        and indicator.description == input_data.get("description")
        and indicator.valid_from == valid_from
        and indicator.valid_until == valid_until
        and indicator.score == input_data.get("score")
        and indicator.author == input_data.get("author")
        and indicator.markings == input_data.get("markings")
        and indicator.external_references == input_data.get("external_references")
    )
