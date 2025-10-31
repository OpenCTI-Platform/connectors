import datetime

import pytest
import stix2
from connectors_sdk.models import (
    AssociatedFile,
    ExternalReference,
    OrganizationAuthor,
    TLPMarking,
)
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.x509_certificate import X509Certificate
from pydantic import ValidationError


def test_x509_certificate_is_a_base_identified_entity():
    """Test that X509Certificate is a BaseIdentifiedEntity."""
    # Given the X509Certificate class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(X509Certificate, BaseIdentifiedEntity)


def test_x509_certificate_class_should_not_accept_invalid_input():
    """Test that X509Certificate class should not accept invalid input."""
    # Given: An invalid input data for X509Certificate
    input_data = {
        "name": "Test x509_certificate",
        "invalid_key": "invalid_value",
    }
    # When validating the x509_certificate
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        X509Certificate.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_x509_certificate_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that X509Certificate to_stix2_object method returns a valid STIX2.1 X509Certificate."""
    # Given: A valid X509Certificate instance
    x509_certificate = X509Certificate(
        # BaseIdentifiedEntity properties
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
        # Observable properties
        hashes={"MD5": "d41d8cd98f00b204e9800998ecf8427f"},
    )
    # When: calling to_stix2_object method
    stix2_obj = x509_certificate.to_stix2_object()
    # Then: A valid STIX2.1 Location is returned
    assert isinstance(stix2_obj, stix2.X509Certificate)


def test_x509_certificate_to_stix2_object(
    fake_valid_organization_author: OrganizationAuthor,
    fake_valid_tlp_markings: list[TLPMarking],
    fake_valid_external_references: list[ExternalReference],
) -> None:
    """Test that X509Certificate to_stix2_object method returns correct STIX2.1 Location."""
    # Given: A valid X509Certificate instance
    x509_certificate = X509Certificate(
        # BaseIdentifiedEntity properties
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
        # Observable properties
        score=85,
        description="Test description",
        labels=["test", "x509_certificate"],
        associated_files=[
            AssociatedFile(
                name="test_file.pem",
                content=b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                mime_type="application/x-pem-file",
            )
        ],
        create_indicator=True,
        # X509 certificate properties
        hashes={"MD5": "938c2cc0dcc05f2b68c4287040cfcf71"},
        is_self_signed=False,
        serial_number="123456789",
        signature_algorithm="sha256WithRSAEncryption",
        issuer="CN=Test Issuer,O=Test Org,C=US",
        subject="CN=Test Subject,O=Test Org,C=US",
        subject_public_key_algorithm="rsaEncryption",
        subject_public_key_modulus="00af...",
        subject_public_key_exponent=65537,
        validity_not_before="2023-01-01T00:00:00Z",
        validity_not_after="2024-01-01T00:00:00Z",
        # X509 certificate extensions properties
        basic_constraints="CA:FALSE",
        name_constraints="permitted;DNS:.example.com",
        policy_constraints="requireExplicitPolicy:0",
        key_usage="digitalSignature, keyEncipherment",
        extended_key_usage="serverAuth, clientAuth",
        subject_key_identifier="AB:CD:EF:12:34:56:78:90",
        authority_key_identifier="12:34:56:78:90:AB:CD:EF",
        subject_alternative_name="DNS:example.com, DNS:www.example.com",
        issuer_alternative_name="DNS:issuer.example.com",
        subject_directory_attributes="Some directory attributes",
        crl_distribution_points="http://crl.example.com/crl.pem",
        inhibit_any_policy="0",
        private_key_usage_period_not_before="2023-01-01T00:00:00Z",
        private_key_usage_period_not_after="2024-01-01T00:00:00Z",
        certificate_policies="",
        policy_mappings="",
    ).to_stix2_object()

    assert x509_certificate == stix2.X509Certificate(
        allow_custom=True,
        # BaseIdentifiedEntity properties
        object_marking_refs=[
            marking.to_stix2_object().id for marking in fake_valid_tlp_markings
        ],
        x_opencti_external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
        x_opencti_created_by_ref=fake_valid_organization_author.to_stix2_object().id,
        # Observable properties
        x_opencti_score=85,
        x_opencti_description="Test description",
        x_opencti_labels=["test", "x509_certificate"],
        x_opencti_files=[
            file.to_stix2_object()
            for file in [
                AssociatedFile(
                    name="test_file.pem",
                    content=b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                    mime_type="application/x-pem-file",
                )
            ]
        ],
        x_opencti_create_indicator=True,
        # X509 certificate properties
        hashes={"MD5": "938c2cc0dcc05f2b68c4287040cfcf71"},
        is_self_signed=False,
        serial_number="123456789",
        signature_algorithm="sha256WithRSAEncryption",
        issuer="CN=Test Issuer,O=Test Org,C=US",
        subject="CN=Test Subject,O=Test Org,C=US",
        subject_public_key_algorithm="rsaEncryption",
        subject_public_key_modulus="00af...",
        subject_public_key_exponent=65537,
        validity_not_before=datetime.datetime(
            2023, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
        ),
        validity_not_after=datetime.datetime(
            2024, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
        ),
        # X509 certificate extensions properties
        basic_constraints="CA:FALSE",
        name_constraints="permitted;DNS:.example.com",
        policy_constraints="requireExplicitPolicy:0",
        key_usage="digitalSignature, keyEncipherment",
        extended_key_usage="serverAuth, clientAuth",
        subject_key_identifier="AB:CD:EF:12:34:56:78:90",
        authority_key_identifier="12:34:56:78:90:AB:CD:EF",
        subject_alternative_name="DNS:example.com, DNS:www.example.com",
        issuer_alternative_name="DNS:issuer.example.com",
        subject_directory_attributes="Some directory attributes",
        crl_distribution_points="http://crl.example.com/crl.pem",
        inhibit_any_policy="0",
        private_key_usage_period_not_before=datetime.datetime(
            2023, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
        ),
        private_key_usage_period_not_after=datetime.datetime(
            2024, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
        ),
        certificate_policies="",
        policy_mappings="",
    )
