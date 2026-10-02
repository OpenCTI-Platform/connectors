from censys_enrichmentapis.builders.base import AreaStixBuilder
from censys_platform import Certificate, CertificateExtensions
from connectors_sdk.models import Reference, X509Certificate
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType

# ``KeyUsage`` / ``ExtendedKeyUsage`` fields that are not usage flags.
_NON_FLAG_USAGE_FIELDS = frozenset({"value", "unknown"})

# ``GeneralNames`` fields holding plain strings (the structured ones such as
# ``directory_names`` or ``other_names`` have no compact textual form).
_GENERAL_NAME_STRING_FIELDS = (
    "dns_names",
    "ip_addresses",
    "email_addresses",
    "uniform_resource_identifiers",
    "registered_ids",
)


class CertificateStixBuilder(AreaStixBuilder):
    @staticmethod
    def _join(values: object) -> str | None:
        """Render a list of scalars as a comma-separated string, or ``None``."""
        if not isinstance(values, list):
            return None
        rendered = [str(value) for value in values if value not in (None, "")]
        return ", ".join(rendered) or None

    @staticmethod
    def _enabled_flags(usage: object) -> str | None:
        """Render the usage flags set to ``True`` on a Censys usage model."""
        if usage is None:
            return None
        flags = [
            name
            for name, enabled in usage.model_dump(exclude_unset=True).items()
            if name not in _NON_FLAG_USAGE_FIELDS and enabled is True
        ]
        unknown = getattr(usage, "unknown", None)
        if isinstance(unknown, list):
            flags.extend(str(item) for item in unknown if item)
        return ", ".join(flags) or None

    @classmethod
    def _general_names(cls, names: object) -> str | None:
        if names is None:
            return None
        values: list[str] = []
        for field in _GENERAL_NAME_STRING_FIELDS:
            field_values = getattr(names, field, None)
            if isinstance(field_values, list):
                values.extend(str(value) for value in field_values if value)
        return ", ".join(dict.fromkeys(values)) or None

    def _extension_kwargs(self, extensions: CertificateExtensions) -> dict[str, str]:
        kwargs: dict[str, str] = {}
        if crl := self._join(extensions.crl_distribution_points):
            kwargs["crl_distribution_points"] = crl
        if isinstance(extensions.authority_key_id, str) and extensions.authority_key_id:
            kwargs["authority_key_identifier"] = extensions.authority_key_id
        if isinstance(extensions.subject_key_id, str) and extensions.subject_key_id:
            kwargs["subject_key_identifier"] = extensions.subject_key_id
        if isinstance(extensions.certificate_policies, list):
            policies = self._join(
                [
                    getattr(policy, "id", None)
                    for policy in extensions.certificate_policies
                ]
            )
            if policies:
                kwargs["certificate_policies"] = policies
        if key_usage := self._enabled_flags(extensions.key_usage):
            kwargs["key_usage"] = key_usage
        if extended_key_usage := self._enabled_flags(extensions.extended_key_usage):
            kwargs["extended_key_usage"] = extended_key_usage
        if extensions.basic_constraints:
            constraints = [
                f"CA:{str(bool(extensions.basic_constraints.is_ca)).upper()}"
            ]
            if extensions.basic_constraints.max_path_len is not None:
                constraints.append(
                    f"pathlen:{extensions.basic_constraints.max_path_len}"
                )
            kwargs["basic_constraints"] = ", ".join(constraints)
        if subject_alt_name := self._general_names(extensions.subject_alt_name):
            kwargs["subject_alternative_name"] = subject_alt_name
        if issuer_alt_name := self._general_names(extensions.issuer_alt_name):
            kwargs["issuer_alternative_name"] = issuer_alt_name
        return kwargs

    def _parsed_field_kwargs(self, cert: Certificate) -> dict[str, object]:
        # ``serial_number``, ``issuer``, ``subject``, and the subject public
        # key fields are STIX id-contributing properties. Returning them as
        # constructor kwargs (rather than assigning them onto an
        # already-built ``X509Certificate``) means the object's id is
        # computed once, from its final field values -- assigning them
        # afterward would recompute (and change) the id on every field
        # already read/used it.
        #
        # Every nested censys-platform field is optional, so each level is
        # checked before it is dereferenced.
        parsed = cert.parsed
        kwargs: dict[str, object] = {
            "serial_number": parsed.serial_number,
            "issuer": parsed.issuer_dn,
            "subject": parsed.subject_dn,
        }
        signature = parsed.signature
        if signature:
            if signature.signature_algorithm and signature.signature_algorithm.name:
                kwargs["signature_algorithm"] = signature.signature_algorithm.name
            if signature.self_signed is not None:
                kwargs["is_self_signed"] = signature.self_signed
        if parsed.validity_period:
            kwargs["validity_not_before"] = parsed.validity_period.not_before
            kwargs["validity_not_after"] = parsed.validity_period.not_after
        key_info = parsed.subject_key_info
        if key_info:
            if key_info.key_algorithm and key_info.key_algorithm.name:
                kwargs["subject_public_key_algorithm"] = key_info.key_algorithm.name
            if key_info.rsa:
                kwargs["subject_public_key_modulus"] = key_info.rsa.modulus
                kwargs["subject_public_key_exponent"] = key_info.rsa.exponent
        if parsed.extensions:
            kwargs.update(self._extension_kwargs(parsed.extensions))
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
