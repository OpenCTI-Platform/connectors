"""X509Certificate."""

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.enums import HashAlgorithm
from pydantic import AwareDatetime, Field
from stix2 import X509Certificate as Stix2X509Certificate


class X509Certificate(BaseObservableEntity):
    """Define a X509Certificate observable on OpenCTI.

    Examples:
        >>> x509_certificate = X509Certificate(
        ...     hashes={"MD5": "d41d8cd98f00b204e9800998ecf8427f"},
        ...     create_indicator=True,
        ...     )
        >>> entity = x509_certificate.to_stix2_object()
    """

    hashes: dict[HashAlgorithm, str] | None = Field(
        default=None,
        description="A dictionary of hashes for the file.",
        min_length=1,
    )
    is_self_signed: bool = Field(
        default=False,
        description="Indicates if the certificate is self-signed.",
    )
    serial_number: str | None = Field(
        default=None,
        description="The serial number of the certificate.",
    )
    signature_algorithm: str | None = Field(
        default=None,
        description="The signature algorithm used in the certificate.",
    )
    issuer: str | None = Field(
        default=None,
        description="The issuer of the certificate.",
    )
    subject: str | None = Field(
        default=None,
        description="The subject of the certificate.",
    )
    subject_public_key_algorithm: str | None = Field(
        default=None,
        description="The public key algorithm used in the certificate.",
    )
    subject_public_key_modulus: str | None = Field(
        default=None,
        description="The public key modulus of the certificate.",
    )
    subject_public_key_exponent: int | None = Field(
        default=None,
        description="The public key exponent of the certificate.",
    )
    validity_not_before: AwareDatetime | None = Field(
        default=None,
        description="The start date and time of the certificate's validity period.",
    )
    validity_not_after: AwareDatetime | None = Field(
        default=None,
        description="The end date and time of the certificate's validity period.",
    )

    # X509V3Extensions
    basic_constraints: str | None = Field(
        default=None,
        description="The basic constraints extension of the certificate.",
    )
    name_constraints: str | None = Field(
        default=None,
        description="The name constraints extension of the certificate.",
    )
    policy_constraints: str | None = Field(
        default=None,
        description="The policy constraints extension of the certificate.",
    )
    key_usage: str | None = Field(
        default=None,
        description="The key usage extension of the certificate.",
    )
    extended_key_usage: str | None = Field(
        default=None,
        description="The extended key usage extension of the certificate.",
    )
    subject_key_identifier: str | None = Field(
        default=None,
        description="The subject key identifier extension of the certificate.",
    )
    authority_key_identifier: str | None = Field(
        default=None,
        description="The authority key identifier extension of the certificate.",
    )
    subject_alternative_name: str | None = Field(
        default=None,
        description="The subject alternative name extension of the certificate.",
    )
    issuer_alternative_name: str | None = Field(
        default=None,
        description="The issuer alternative name extension of the certificate.",
    )
    subject_directory_attributes: str | None = Field(
        default=None,
        description="The subject directory attributes extension of the certificate.",
    )
    crl_distribution_points: str | None = Field(
        default=None,
        description="The CRL distribution points extension of the certificate.",
    )
    inhibit_any_policy: str | None = Field(
        default=None,
        description="The inhibit any policy extension of the certificate.",
    )
    private_key_usage_period_not_before: AwareDatetime | None = Field(
        default=None,
        description="The start date and time of the private key usage period.",
    )
    private_key_usage_period_not_after: AwareDatetime | None = Field(
        default=None,
        description="The end date and time of the private key usage period.",
    )
    certificate_policies: str | None = Field(
        default=None,
        description="The certificate policies extension of the certificate.",
    )
    policy_mappings: str | None = Field(
        default=None,
        description="The policy mappings extension of the certificate.",
    )

    def to_stix2_object(self) -> Stix2X509Certificate:
        """Make stix object."""
        return Stix2X509Certificate(
            is_self_signed=self.is_self_signed,
            hashes={k.value: v for k, v in (self.hashes or {}).items()},
            serial_number=self.serial_number,
            signature_algorithm=self.signature_algorithm,
            issuer=self.issuer,
            validity_not_before=self.validity_not_before,
            validity_not_after=self.validity_not_after,
            subject=self.subject,
            subject_public_key_algorithm=self.subject_public_key_algorithm,
            subject_public_key_modulus=self.subject_public_key_modulus,
            subject_public_key_exponent=self.subject_public_key_exponent,
            basic_constraints=self.basic_constraints,
            name_constraints=self.name_constraints,
            policy_constraints=self.policy_constraints,
            key_usage=self.key_usage,
            extended_key_usage=self.extended_key_usage,
            subject_key_identifier=self.subject_key_identifier,
            authority_key_identifier=self.authority_key_identifier,
            subject_alternative_name=self.subject_alternative_name,
            issuer_alternative_name=self.issuer_alternative_name,
            subject_directory_attributes=self.subject_directory_attributes,
            crl_distribution_points=self.crl_distribution_points,
            inhibit_any_policy=self.inhibit_any_policy,
            private_key_usage_period_not_before=self.private_key_usage_period_not_before,
            private_key_usage_period_not_after=self.private_key_usage_period_not_after,
            certificate_policies=self.certificate_policies,
            policy_mappings=self.policy_mappings,
            **self._common_stix2_properties(),
        )
