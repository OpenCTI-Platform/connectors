"""The module defines the X509CertificateModel class, which represents a STIX 2.1 X.509 Certificate object."""

from datetime import datetime
from typing import Dict, Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import BaseModel, Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    X509Certificate,
    _STIXBase21,
)


class X509V3ExtensionsTypeModel(BaseModel):
    """Model representing X.509 v3 extensions."""

    basic_constraints: Optional[str] = Field(
        default=None,
        description="Specifies if the certificate is a CA (e.g., CA:TRUE, pathlen:0). OID: 2.5.29.19",
    )
    name_constraints: Optional[str] = Field(
        default=None,
        description="Namespace for subject names in cert path. OID: 2.5.29.30",
    )
    policy_constraints: Optional[str] = Field(
        default=None,
        description="Constraints on path validation for CA certs. OID: 2.5.29.36",
    )
    key_usage: Optional[str] = Field(
        default=None, description="Permitted key usages. OID: 2.5.29.15"
    )
    extended_key_usage: Optional[str] = Field(
        default=None,
        description="Purposes for which the public key may be used. OID: 2.5.29.37",
    )
    subject_key_identifier: Optional[str] = Field(
        default=None,
        description="Identifier for the subject public key. OID: 2.5.29.14",
    )
    authority_key_identifier: Optional[str] = Field(
        default=None,
        description="Identifier for the signing authority public key. OID: 2.5.29.35",
    )
    subject_alternative_name: Optional[str] = Field(
        default=None,
        description="Additional subject identities. OID: 2.5.29.17",
    )
    issuer_alternative_name: Optional[str] = Field(
        default=None,
        description="Additional issuer identities. OID: 2.5.29.18",
    )
    subject_directory_attributes: Optional[str] = Field(
        default=None,
        description="Identification attributes of the subject. OID: 2.5.29.9",
    )
    crl_distribution_points: Optional[str] = Field(
        default=None, description="How CRL info is obtained. OID: 2.5.29.31"
    )
    inhibit_any_policy: Optional[str] = Field(
        default=None,
        description="Max certs before 'anyPolicy' is blocked. OID: 2.5.29.54",
    )
    private_key_usage_period_not_before: Optional[datetime] = Field(
        default=None,
        description="Start of private key usage period, if different from cert validity.",
    )
    private_key_usage_period_not_after: Optional[datetime] = Field(
        default=None,
        description="End of private key usage period, if different from cert validity.",
    )
    certificate_policies: Optional[str] = Field(
        default=None,
        description="One or more policy OIDs and optional qualifiers. OID: 2.5.29.32",
    )
    policy_mappings: Optional[str] = Field(
        default=None,
        description="Pairs of issuer/subject policy OIDs. OID: 2.5.29.33",
    )


class X509CertificateModel(BaseSCOModel):
    """Model representing an X.509 Certificate in STIX 2.1 format."""

    is_self_signed: Optional[bool] = Field(
        default=None, description="True if the certificate is self-signed."
    )
    hashes: Optional[Dict[str, str]] = Field(
        default=None,
        description="Hashes for the full certificate content. Keys MUST follow hash-algorithm-ov.",
    )

    version: Optional[str] = Field(
        default=None, description="Version of the encoded certificate."
    )
    serial_number: Optional[str] = Field(
        default=None,
        description="Unique identifier for the cert as issued by the CA.",
    )
    signature_algorithm: Optional[str] = Field(
        default=None, description="Algorithm used to sign the certificate."
    )

    issuer: Optional[str] = Field(
        default=None,
        description="Name of the Certificate Authority that issued this certificate.",
    )
    validity_not_before: Optional[datetime] = Field(
        default=None, description="Start of certificate validity period."
    )
    validity_not_after: Optional[datetime] = Field(
        default=None, description="End of certificate validity period."
    )

    subject: Optional[str] = Field(
        default=None,
        description="Subject name—the entity the certificate is issued to.",
    )
    subject_public_key_algorithm: Optional[str] = Field(
        default=None,
        description="Algorithm for encrypting data to the subject.",
    )
    subject_public_key_modulus: Optional[str] = Field(
        default=None,
        description="RSA modulus portion of the subject's public key.",
    )
    subject_public_key_exponent: Optional[int] = Field(
        default=None,
        description="RSA exponent portion of the subject's public key.",
    )

    x509_v3_extensions: Optional[X509V3ExtensionsTypeModel] = Field(
        default=None,
        description="Standard X.509 v3 extensions as key-value pairs (e.g., BasicConstraints, SubjectAltName).",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return X509Certificate(**self.model_dump(exclude_none=True))
