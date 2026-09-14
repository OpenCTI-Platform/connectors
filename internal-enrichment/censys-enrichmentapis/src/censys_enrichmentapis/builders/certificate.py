from censys_enrichmentapis.builders.base import AreaStixBuilder
from censys_platform import Certificate
from connectors_sdk.models import Reference, X509Certificate
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType


class CertificateStixBuilder(AreaStixBuilder):
    def _add_parsed_fields(
        self, certificate: X509Certificate, cert: Certificate
    ) -> None:
        certificate.serial_number = cert.parsed.serial_number
        certificate.issuer = cert.parsed.issuer_dn
        certificate.subject = cert.parsed.subject_dn
        if cert.parsed.signature:
            certificate.signature_algorithm = (
                cert.parsed.signature.signature_algorithm.name
            )
        if cert.parsed.validity_period:
            certificate.validity_not_before = cert.parsed.validity_period.not_before
            certificate.validity_not_after = cert.parsed.validity_period.not_after
        if cert.parsed.subject_key_info:
            certificate.subject_public_key_algorithm = (
                cert.parsed.subject_key_info.key_algorithm.name
            )
            if cert.parsed.subject_key_info.rsa:
                certificate.subject_public_key_modulus = (
                    cert.parsed.subject_key_info.rsa.modulus
                )
                certificate.subject_public_key_exponent = (
                    cert.parsed.subject_key_info.rsa.exponent
                )

    def _add_extensions(
        self, certificate: X509Certificate, cert: Certificate
    ) -> None:
        if cert.parsed.extensions.key_usage:
            certificate.key_usage = cert.parsed.extensions.key_usage.model_dump_json()
        if cert.parsed.extensions.basic_constraints:
            certificate.basic_constraints = (
                cert.parsed.extensions.basic_constraints.model_dump_json()
            )
        certificate.crl_distribution_points = str(
            cert.parsed.extensions.crl_distribution_points
        )
        certificate.authority_key_identifier = cert.parsed.extensions.authority_key_id
        if cert.parsed.extensions.extended_key_usage:
            certificate.extended_key_usage = (
                cert.parsed.extensions.extended_key_usage.model_dump_json()
            )
        certificate.certificate_policies = str(
            cert.parsed.extensions.certificate_policies
        )

    def add_certificate(
        self,
        cert: Certificate | None,
        *,
        related_observable: Reference | None = None,
    ) -> X509Certificate | None:
        if not cert or not (
            cert.fingerprint_sha256 or cert.fingerprint_sha1 or cert.fingerprint_md5
        ):
            return None

        hashes = {
            algorithm: fingerprint
            for algorithm, fingerprint in (
                (HashAlgorithm.SHA1, cert.fingerprint_sha1),
                (HashAlgorithm.SHA256, cert.fingerprint_sha256),
                (HashAlgorithm.MD5, cert.fingerprint_md5),
            )
            if fingerprint
        }
        certificate = X509Certificate(hashes=hashes or None, **self.common_props)
        if cert.parsed:
            self._add_parsed_fields(certificate=certificate, cert=cert)
            if cert.parsed.extensions:
                self._add_extensions(certificate=certificate, cert=cert)
        self.bundle.append(certificate)
        if related_observable:
            self.add_relationship(
                certificate, related_observable, RelationshipType.RELATED_TO
            )
        return certificate
