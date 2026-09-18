from censys_enrichmentapis.builders.base import AreaStixBuilder
from censys_platform import Certificate
from connectors_sdk.models import Reference, X509Certificate
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType


class CertificateStixBuilder(AreaStixBuilder):
    def _parsed_field_kwargs(self, cert: Certificate) -> dict[str, object]:
        # ``serial_number``, ``issuer``, ``subject``, and the subject public
        # key fields are STIX id-contributing properties. Returning them as
        # constructor kwargs (rather than assigning them onto an
        # already-built ``X509Certificate``) means the object's id is
        # computed once, from its final field values — assigning them
        # afterward would recompute (and change) the id on every field
        # already read/used it.
        parsed = cert.parsed
        kwargs: dict[str, object] = {
            "serial_number": parsed.serial_number,
            "issuer": parsed.issuer_dn,
            "subject": parsed.subject_dn,
        }
        if parsed.signature:
            kwargs["signature_algorithm"] = parsed.signature.signature_algorithm.name
        if parsed.validity_period:
            kwargs["validity_not_before"] = parsed.validity_period.not_before
            kwargs["validity_not_after"] = parsed.validity_period.not_after
        if parsed.subject_key_info:
            kwargs["subject_public_key_algorithm"] = (
                parsed.subject_key_info.key_algorithm.name
            )
            if parsed.subject_key_info.rsa:
                kwargs["subject_public_key_modulus"] = (
                    parsed.subject_key_info.rsa.modulus
                )
                kwargs["subject_public_key_exponent"] = (
                    parsed.subject_key_info.rsa.exponent
                )
        if parsed.extensions:
            kwargs.update(self._extension_kwargs(parsed.extensions))
        return kwargs

    def _extension_kwargs(self, extensions: object) -> dict[str, object]:
        kwargs: dict[str, object] = {
            "crl_distribution_points": str(extensions.crl_distribution_points),
            "authority_key_identifier": extensions.authority_key_id,
            "certificate_policies": str(extensions.certificate_policies),
        }
        if extensions.key_usage:
            kwargs["key_usage"] = extensions.key_usage.model_dump_json()
        if extensions.basic_constraints:
            kwargs["basic_constraints"] = extensions.basic_constraints.model_dump_json()
        if extensions.extended_key_usage:
            kwargs["extended_key_usage"] = (
                extensions.extended_key_usage.model_dump_json()
            )
        return kwargs

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
        parsed_kwargs = self._parsed_field_kwargs(cert) if cert.parsed else {}
        certificate = X509Certificate(
            hashes=hashes or None, **parsed_kwargs, **self.common_props
        )
        self.bundle.append(certificate)
        if related_observable:
            self.add_relationship(
                certificate, related_observable, RelationshipType.RELATED_TO
            )
        return certificate
