import datetime

from censys_enrichmentapis.builder import CensysStixBuilder
from censys_platform import Certificate, CertificateParsed
from connectors_sdk.models import (
    City,
    IPV4Address,
    IPV6Address,
    Reference,
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


def test_geography_builder_adds_to_shared_bundle() -> None:
    builder = CensysStixBuilder()

    builder.geography.add_city(observable=OBSERVABLE, name="Paris")

    assert isinstance(builder.bundle[0], City)
    assert builder.bundle[0].name == "Paris"
    assert len(builder.bundle) == 2


def test_network_builder_selects_ip_version() -> None:
    builder = CensysStixBuilder()

    ipv4 = builder.network.add_ip(OBSERVABLE, "192.0.2.1")
    ipv6 = builder.network.add_ip(OBSERVABLE, "2001:db8::1")

    assert isinstance(ipv4, IPV4Address)
    assert isinstance(ipv6, IPV6Address)


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
    assert certificate.crl_distribution_points == str(
        parsed.extensions.crl_distribution_points
    )
    assert certificate.certificate_policies == str(
        parsed.extensions.certificate_policies
    )
    assert certificate.key_usage == parsed.extensions.key_usage.model_dump_json()
    assert (
        certificate.extended_key_usage
        == parsed.extensions.extended_key_usage.model_dump_json()
    )
    # Would raise if a mapped field held a value stix2 rejects.
    certificate.to_stix2_object()
