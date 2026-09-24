import datetime

import pytest
from censys_enrichmentapis.builder import CensysStixBuilder
from censys_platform import (
    BasicConstraints,
    Certificate,
    CertificateExtensions,
    CertificateParsed,
    CertificatePolicy,
    ExtendedKeyUsage,
    GeneralNames,
    KeyUsage,
    Signature,
    SubjectKeyInfo,
)
from censys_platform.types import UNSET
from connectors_sdk.models import (
    AttackPattern,
    City,
    Malware,
    OrganizationAuthor,
    Reference,
    Relationship,
    Software,
    Vulnerability,
)
from connectors_sdk.models.enums import HashAlgorithm

from .factories import CertificateFactory

SHA256 = "73b8ed5becf1ba6493d2e2215a42dfdc7877e91e311ff5e59fb43d094871e699"
OBSERVABLE = Reference(id="ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc")


def test_area_builders_share_context_and_reset_replaces_bundle() -> None:
    builder = CensysStixBuilder()
    builder.add_author_and_marking()
    original_bundle = builder.bundle

    builder.reset()

    assert len(original_bundle) == 2
    assert builder.bundle == []
    assert builder.bundle is not original_bundle


def test_builder_uses_source_marking_refs() -> None:
    marking_id = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    builder = CensysStixBuilder()
    builder.reset(marking_refs=[marking_id])

    builder.add_author_and_marking()
    builder.geography.add_city(observable=OBSERVABLE, name="Paris")

    assert isinstance(builder.bundle[0], OrganizationAuthor)
    assert isinstance(builder.bundle[1], City)
    assert isinstance(builder.bundle[2], Relationship)
    for generated_object in builder.bundle[1:]:
        assert generated_object.to_stix2_object().object_marking_refs == [marking_id]


def test_geography_builder_adds_to_shared_bundle() -> None:
    builder = CensysStixBuilder()

    builder.geography.add_city(observable=OBSERVABLE, name="Paris")

    assert isinstance(builder.bundle[0], City)
    assert builder.bundle[0].name == "Paris"
    assert len(builder.bundle) == 2


def test_service_builder_deduplicates_software_and_relationships() -> None:
    # The same software reported on two services of a host must yield one
    # Software object and one related-to relationship, not one per service.
    builder = CensysStixBuilder()

    first = builder.services.add_software(
        observable=OBSERVABLE,
        name="nginx",
        vendor="nginx",
        cpe="cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*",
    )
    second = builder.services.add_software(
        observable=OBSERVABLE,
        name="nginx",
        vendor="nginx",
        cpe="cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*",
    )

    assert first is second
    assert len([obj for obj in builder.bundle if isinstance(obj, Software)]) == 1
    assert len([obj for obj in builder.bundle if isinstance(obj, Relationship)]) == 1


def test_service_builder_deduplicates_malware_and_attack_patterns() -> None:
    # Two threats sharing the same malware family and tactic must not
    # duplicate the Malware / Attack-Pattern objects or their relationships.
    builder = CensysStixBuilder()
    threats = [
        {
            "id": "THREAT-1",
            "name": "Cobalt Strike Beacon",
            "type": ["backdoor"],
            "tactic": ["command_and_control"],
            "malware": {"primary_name": "Cobalt Strike", "all_names": ["CS"]},
        },
        {
            "id": "THREAT-2",
            "name": "Cobalt Strike Team Server",
            "type": ["backdoor"],
            "tactic": ["command_and_control", "Command_And_Control"],
            "malware": {"primary_name": "Cobalt Strike"},
        },
    ]

    builder.services._add_threats(
        observable=OBSERVABLE,
        observable_value="192.0.2.1",
        threats=threats,
        port=443,
        protocol="HTTPS",
    )

    malware = [obj for obj in builder.bundle if isinstance(obj, Malware)]
    attack_patterns = [obj for obj in builder.bundle if isinstance(obj, AttackPattern)]
    relationships = [obj for obj in builder.bundle if isinstance(obj, Relationship)]
    assert len(malware) == 1
    assert malware[0].description == "THREAT-1: Cobalt Strike Beacon"
    assert len(attack_patterns) == 1
    assert attack_patterns[0].name == "COMMAND AND CONTROL"
    # One relationship to the malware, one to the attack pattern.
    assert len(relationships) == 2


def test_service_builder_extracts_cwe_entries() -> None:
    # Censys returns CWEs as ``{"entry": "CWE-79"}`` objects; the ids must be
    # extracted rather than dropped by a plain string filter.
    builder = CensysStixBuilder()
    software = builder.services.add_software(
        observable=OBSERVABLE, name="openssh", vendor="openbsd", cpe=None
    )
    assert software is not None

    vulnerability = builder.services.add_vulnerability(
        software,
        {
            "id": "CVE-2026-12345",
            "cwes": [{"entry": "CWE-787"}, "CWE-20", {"entry": "CWE-787"}, {}],
            "kev": [{"date_added": "2026-01-01"}],
        },
    )

    assert vulnerability is not None
    assert vulnerability.cwe_ids == ["CWE-787", "CWE-20"]
    assert vulnerability.is_cisa_kev is True


def test_service_builder_skips_invalid_vulnerability() -> None:
    builder = CensysStixBuilder()
    software = builder.services.add_software(
        observable=OBSERVABLE,
        name="nginx",
        vendor="nginx",
        cpe="cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*",
    )
    assert software is not None
    bundle_size = len(builder.bundle)

    vulnerability = builder.services.add_vulnerability(software, {"id": "not-a-cve"})

    assert vulnerability is None
    assert len(builder.bundle) == bundle_size


def test_builder_reset_clears_vulnerability_cache() -> None:
    builder = CensysStixBuilder()
    software = builder.services.add_software(
        observable=OBSERVABLE,
        name="nginx",
        vendor="nginx",
        cpe="cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*",
    )
    assert software is not None
    first_vulnerability = builder.services.add_vulnerability(
        software, {"id": "CVE-2026-12345"}
    )

    builder.reset()
    software = builder.services.add_software(
        observable=OBSERVABLE,
        name="nginx",
        vendor="nginx",
        cpe="cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*",
    )
    assert software is not None
    second_vulnerability = builder.services.add_vulnerability(
        software, {"id": "CVE-2026-12345"}
    )

    assert second_vulnerability is not first_vulnerability
    assert len([obj for obj in builder.bundle if isinstance(obj, Vulnerability)]) == 1


def test_add_certificate_filters_missing_fingerprints() -> None:
    # A certificate that only carries a SHA-256 fingerprint must not leak
    # ``None`` values into ``hashes`` (the SDK model rejects them); only the
    # present fingerprint is kept and the object must serialize cleanly.
    builder = CensysStixBuilder()

    certificate = builder.certificates.add_certificate(
        cert=Certificate(fingerprint_sha256=SHA256)
    )

    assert certificate is not None
    assert certificate.hashes == {HashAlgorithm.SHA256: SHA256}
    # Would raise before the fix (None hash values fail validation).
    certificate.to_stix2_object()


def test_add_certificate_without_fingerprints_is_skipped() -> None:
    # A certificate with parsed metadata but no fingerprint cannot be
    # serialized (empty hashes are rejected by stix2), so it is skipped.
    builder = CensysStixBuilder()

    certificate = builder.certificates.add_certificate(
        cert=Certificate(
            parsed=CertificateParsed(
                serial_number="123456789",
                issuer_dn="C=US, O=Example",
                subject_dn="CN=example.com",
            ),
        )
    )

    assert certificate is None
    assert builder.bundle == []


def test_add_certificate_returns_none_for_empty_certificate() -> None:
    builder = CensysStixBuilder()

    assert builder.certificates.add_certificate(cert=Certificate()) is None
    assert builder.certificates.add_certificate(cert=None) is None


def test_add_certificate_maps_parsed_fields_and_extensions() -> None:
    # ``CertificateFactory`` builds a fingerprinted certificate with a full
    # ``parsed`` payload (signature, validity, key info, extensions) — the
    # part of ``add_certificate`` no other test exercises.
    builder = CensysStixBuilder()
    cert = CertificateFactory()
    parsed = cert.parsed

    certificate = builder.certificates.add_certificate(cert=cert)

    assert certificate is not None
    assert certificate.serial_number == parsed.serial_number
    assert certificate.issuer == parsed.issuer_dn
    assert certificate.subject == parsed.subject_dn
    assert certificate.signature_algorithm == parsed.signature.signature_algorithm.name
    assert certificate.validity_not_before == datetime.datetime.fromisoformat(
        parsed.validity_period.not_before
    )
    assert certificate.validity_not_after == datetime.datetime.fromisoformat(
        parsed.validity_period.not_after
    )
    assert (
        certificate.subject_public_key_algorithm
        == parsed.subject_key_info.key_algorithm.name
    )
    assert certificate.authority_key_identifier == parsed.extensions.authority_key_id
    assert certificate.crl_distribution_points == ", ".join(
        parsed.extensions.crl_distribution_points
    )
    assert certificate.certificate_policies == ", ".join(
        policy.id for policy in parsed.extensions.certificate_policies
    )
    # The factory sets no usage flag, so the flag-only renderings stay unset.
    assert certificate.key_usage is None
    assert certificate.extended_key_usage is None
    # Would raise if a mapped field held a value stix2 rejects.
    certificate.to_stix2_object()


def test_add_certificate_renders_extensions_human_readable() -> None:
    # Extension values must be rendered as readable text, never as Python
    # reprs (``"['a', 'b']"``, ``"[CertificatePolicy(...)]"``) or JSON dumps.
    builder = CensysStixBuilder()
    cert = Certificate(
        fingerprint_sha256=SHA256,
        parsed=CertificateParsed(
            signature=Signature(self_signed=True),
            extensions=CertificateExtensions(
                key_usage=KeyUsage(
                    digital_signature=True, key_encipherment=True, crl_sign=False
                ),
                extended_key_usage=ExtendedKeyUsage(
                    server_auth=True, client_auth=True, unknown=["1.2.3.4"]
                ),
                basic_constraints=BasicConstraints(is_ca=True, max_path_len=0),
                certificate_policies=[
                    CertificatePolicy(id="2.23.140.1.2.1", cps=["http://cps"]),
                    CertificatePolicy(cps=["http://no-id"]),
                ],
                crl_distribution_points=["http://crl.example.com/a.crl"],
                subject_key_id="ab:cd",
                subject_alt_name=GeneralNames(
                    dns_names=["example.com", "www.example.com"],
                    ip_addresses=["192.0.2.1"],
                ),
            ),
        ),
    )

    certificate = builder.certificates.add_certificate(cert=cert)

    assert certificate is not None
    assert certificate.is_self_signed is True
    assert certificate.key_usage == "digital_signature, key_encipherment"
    assert certificate.extended_key_usage == "client_auth, server_auth, 1.2.3.4"
    assert certificate.basic_constraints == "CA:TRUE, pathlen:0"
    assert certificate.certificate_policies == "2.23.140.1.2.1"
    assert certificate.crl_distribution_points == "http://crl.example.com/a.crl"
    assert certificate.subject_key_identifier == "ab:cd"
    assert (
        certificate.subject_alternative_name
        == "example.com, www.example.com, 192.0.2.1"
    )
    certificate.to_stix2_object()


def test_add_certificate_tolerates_partial_nested_models() -> None:
    # Every nested censys-platform field is optional: a signature without an
    # algorithm or key info without an algorithm must not raise.
    builder = CensysStixBuilder()
    cert = Certificate(
        fingerprint_sha256=SHA256,
        parsed=CertificateParsed(
            signature=Signature(valid=True),
            subject_key_info=SubjectKeyInfo(fingerprint_sha256=SHA256),
        ),
    )

    certificate = builder.certificates.add_certificate(cert=cert)

    assert certificate is not None
    assert certificate.signature_algorithm is None
    assert certificate.subject_public_key_algorithm is None
    assert certificate.is_self_signed is False
    certificate.to_stix2_object()


@pytest.mark.parametrize("missing_value", [None, UNSET, []])
def test_add_certificate_omits_missing_list_extensions(missing_value: object) -> None:
    builder = CensysStixBuilder()
    cert = Certificate(
        fingerprint_sha256=SHA256,
        parsed=CertificateParsed(
            extensions=CertificateExtensions(
                crl_distribution_points=missing_value,
                certificate_policies=missing_value,
            )
        ),
    )

    certificate = builder.certificates.add_certificate(cert=cert)

    assert certificate is not None
    assert certificate.crl_distribution_points is None
    assert certificate.certificate_policies is None
    stix_certificate = certificate.to_stix2_object()
    assert "crl_distribution_points" not in stix_certificate
    assert "certificate_policies" not in stix_certificate
