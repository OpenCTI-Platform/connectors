import pytest
import stix2
from dragos.domain.models.octi import (
    Artifact,
    DomainName,
    ExternalReference,
    File,
    IPV4Address,
    IPV6Address,
    OrganizationAuthor,
    TLPMarking,
    Url,
)
from dragos.domain.models.octi.enums import EncryptionAlgorithm, TLPLevel
from pydantic import ValidationError


def fake_valid_organization_author():
    return OrganizationAuthor(name="Valid Author")


def fake_valid_tlp_marking():
    return TLPMarking(level=TLPLevel.RED.value)


def fake_valid_external_reference():
    return ExternalReference(
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
                "mime_type": "application/octet-stream",
                "url": "http://example.com",
                "hashes": {"MD5": "44d88612fea8a8f36de82e1278abb02f"},
                "encryption_algorithm": EncryptionAlgorithm.AES_256_GCM.value,
                "decryption_key": "example_key",
                "additional_names": ["example_name"],
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
                "url": "http://example.com",
                "hashes": {"MD5": "44d88612fea8a8f36de82e1278abb02f"},
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data_with_url",
        ),
        pytest.param(
            {
                "payload_bin": bytes("SGVsbG8gd29ybGQ=", encoding="utf-8"),
            },
            id="minimal_valid_data_with_payload_bin",
        ),
    ],
)
def test_artifact_class_should_accept_valid_input(input_data):
    # Given: Valid artifact input data
    # When: Creating an artifact object
    artifact = Artifact.model_validate(input_data)

    # Then: The artifact object should be valid
    assert artifact.id is not None
    assert artifact.mime_type == input_data.get("mime_type")
    assert artifact.payload_bin == input_data.get("payload_bin")
    assert artifact.url == input_data.get("url")
    assert artifact.hashes == input_data.get("hashes")
    assert artifact.encryption_algorithm == input_data.get("encryption_algorithm")
    assert artifact.decryption_key == input_data.get("decryption_key")
    assert artifact.additional_names == input_data.get("additional_names")
    assert artifact.score == input_data.get("score")
    assert artifact.description == input_data.get("description")
    assert artifact.labels == input_data.get("labels")
    assert artifact.author == input_data.get("author")
    assert artifact.external_references == input_data.get("external_references")
    assert artifact.markings == input_data.get("markings")


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "payload_bin",
            id="missing_payload_bin_and_url",
        ),
        pytest.param(
            {
                # payload_bin and url are mutually exclusive
                "payload_bin": bytes("SGVsbG8gd29ybGQ=", encoding="utf-8"),
                "url": "http://example.com",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "payload_bin",
            id="extra_payload_bin_or_url",
        ),
        pytest.param(
            {
                "url": "http://example.com",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "hashes",
            id="missing_hashes",
        ),
    ],
)
def test_artifact_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input data for the Artifact class
    # When: we try to create a Artifact instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        Artifact.model_validate(input_data)
    assert str(error_field) in str(err)


def test_artifact_to_stix2_object_returns_valid_stix_object():
    # Given: A valid artifact
    input_data = {
        "mime_type": "application/octet-stream",
        "url": "http://example.com",
        "hashes": {"MD5": "44d88612fea8a8f36de82e1278abb02f"},
        "encryption_algorithm": EncryptionAlgorithm.AES_256_GCM.value,
        "decryption_key": "example_key",
        "additional_names": ["example_name"],
        "score": 50,
        "description": "Example description",
        "labels": ["example_label"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_valid_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    artifact = Artifact.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = artifact.to_stix2_object()

    # Then: A valid STIX2.1 Artifact is returned
    assert isinstance(stix2_obj, stix2.Artifact) is True
    assert stix2_obj.id is not None
    assert stix2_obj.mime_type == input_data.get("mime_type")
    assert stix2_obj.url == input_data.get("url")
    assert stix2_obj.hashes == input_data.get("hashes")
    assert stix2_obj.encryption_algorithm == input_data.get("encryption_algorithm")
    assert stix2_obj.decryption_key == input_data.get("decryption_key")
    assert stix2_obj.object_marking_refs == [
        marking.id for marking in input_data.get("markings")
    ]
    assert stix2_obj.x_opencti_additional_names == input_data.get("additional_names")
    assert stix2_obj.x_opencti_score == input_data.get("score")
    assert stix2_obj.x_opencti_description == input_data.get("description")
    assert stix2_obj.x_opencti_labels == input_data.get("labels")
    assert stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
    assert stix2_obj.x_opencti_external_references == [
        external_reference.to_stix2_object()
        for external_reference in input_data.get("external_references")
    ]


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
    domain_name = DomainName.model_validate(input_data)
    assert domain_name.id is not None
    assert domain_name.value == input_data.get("value")


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
    with pytest.raises(ValidationError) as err:
        DomainName.model_validate(input_data)
    assert str(error_field) in str(err)


def test_domain_name_to_stix2_object_returns_valid_stix_object():
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
    domain_name = DomainName.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = domain_name.to_stix2_object()

    # Then: A valid STIX2.1 DomainName is returned
    assert isinstance(stix2_obj, stix2.DomainName) is True
    assert stix2_obj.id is not None
    assert stix2_obj.value == input_data.get("value")
    assert stix2_obj.object_marking_refs == [
        marking.id for marking in input_data.get("markings")
    ]
    assert stix2_obj.x_opencti_score == input_data.get("score")
    assert stix2_obj.x_opencti_description == input_data.get("description")
    assert stix2_obj.x_opencti_labels == input_data.get("labels")
    assert stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
    assert stix2_obj.x_opencti_external_references == [
        external_reference.to_stix2_object()
        for external_reference in input_data.get("external_references")
    ]


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
    file = File.model_validate(input_data)
    assert file.id is not None
    assert file.hashes == input_data.get("hashes")
    assert file.size == input_data.get("size")
    assert file.name == input_data.get("name")


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
    with pytest.raises(ValidationError) as err:
        File.model_validate(input_data)
    assert str(error_field) in str(err)


def test_file_to_stix2_object_returns_valid_stix_object():
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
    file = File.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = file.to_stix2_object()

    # Then: A valid STIX2.1 File is returned
    assert isinstance(stix2_obj, stix2.File) is True
    assert stix2_obj.id is not None
    assert stix2_obj.hashes == input_data.get("hashes")
    assert stix2_obj.size == input_data.get("size")
    assert stix2_obj.name == input_data.get("name")
    assert stix2_obj.object_marking_refs == [
        marking.id for marking in input_data.get("markings")
    ]
    assert stix2_obj.x_opencti_score == input_data.get("score")
    assert stix2_obj.x_opencti_description == input_data.get("description")
    assert stix2_obj.x_opencti_labels == input_data.get("labels")
    assert stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
    assert stix2_obj.x_opencti_external_references == [
        external_reference.to_stix2_object()
        for external_reference in input_data.get("external_references")
    ]


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
    ip_v4 = IPV4Address.model_validate(input_data)
    assert ip_v4.id is not None
    assert ip_v4.value == input_data.get("value")
    assert ip_v4.score == input_data.get("score")
    assert ip_v4.description == input_data.get("description")
    assert ip_v4.labels == input_data.get("labels")


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
    with pytest.raises(ValidationError) as err:
        IPV4Address.model_validate(input_data)
    assert str(error_field) in str(err)


def test_ip_v4_address_to_stix2_object_returns_valid_stix_object():
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
    ip_v4_address = IPV4Address.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = ip_v4_address.to_stix2_object()

    # Then: A valid STIX2.1 IPV4Address is returned
    assert isinstance(stix2_obj, stix2.IPv4Address) is True
    assert stix2_obj.id is not None
    assert stix2_obj.value == input_data.get("value")
    assert stix2_obj.object_marking_refs == [
        marking.id for marking in input_data.get("markings")
    ]
    assert stix2_obj.x_opencti_score == input_data.get("score")
    assert stix2_obj.x_opencti_description == input_data.get("description")
    assert stix2_obj.x_opencti_labels == input_data.get("labels")
    assert stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
    assert stix2_obj.x_opencti_external_references == [
        external_reference.to_stix2_object()
        for external_reference in input_data.get("external_references")
    ]


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
    ip_v6 = IPV6Address.model_validate(input_data)
    assert ip_v6.id is not None
    assert ip_v6.value == input_data.get("value")
    assert ip_v6.score == input_data.get("score")
    assert ip_v6.description == input_data.get("description")
    assert ip_v6.labels == input_data.get("labels")


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
    with pytest.raises(ValidationError) as err:
        IPV6Address.model_validate(input_data)
    assert str(error_field) in str(err)


def test_ip_v6_address_to_stix2_object_returns_valid_stix_object():
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
    ip_v6_address = IPV6Address.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = ip_v6_address.to_stix2_object()

    # Then: A valid STIX2.1 IPV6Address is returned
    assert isinstance(stix2_obj, stix2.IPv6Address) is True
    assert stix2_obj.id is not None
    assert stix2_obj.value == input_data.get("value")
    assert stix2_obj.object_marking_refs == [
        marking.id for marking in input_data.get("markings")
    ]
    assert stix2_obj.x_opencti_score == input_data.get("score")
    assert stix2_obj.x_opencti_description == input_data.get("description")
    assert stix2_obj.x_opencti_labels == input_data.get("labels")
    assert stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
    assert stix2_obj.x_opencti_external_references == [
        external_reference.to_stix2_object()
        for external_reference in input_data.get("external_references")
    ]


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
    url = Url.model_validate(input_data)
    assert url.id is not None
    assert url.value == input_data.get("value")


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
    with pytest.raises(ValidationError) as err:
        Url.model_validate(input_data)
    assert str(error_field) in str(err)


def test_url_to_stix2_object_returns_valid_stix_object():
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
    url = Url.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = url.to_stix2_object()

    # Then: A valid STIX2.1 URL is returned
    assert isinstance(stix2_obj, stix2.URL) is True
    assert stix2_obj.id is not None
    assert stix2_obj.value == input_data.get("value")
    assert stix2_obj.object_marking_refs == [
        marking.id for marking in input_data.get("markings")
    ]
    assert stix2_obj.x_opencti_score == input_data.get("score")
    assert stix2_obj.x_opencti_description == input_data.get("description")
    assert stix2_obj.x_opencti_labels == input_data.get("labels")
    assert stix2_obj.x_opencti_created_by_ref == input_data.get("author").id
    assert stix2_obj.x_opencti_external_references == [
        external_reference.to_stix2_object()
        for external_reference in input_data.get("external_references")
    ]
