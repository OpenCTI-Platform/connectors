from censys_enrichment.builder import CensysStixBuilder
from censys_platform import Certificate, CertificateParsed
from connectors_sdk.models.enums import HashAlgorithm

SHA256 = "73b8ed5becf1ba6493d2e2215a42dfdc7877e91e311ff5e59fb43d094871e699"


def test_add_certificate_filters_missing_fingerprints() -> None:
    # A certificate that only carries a SHA-256 fingerprint must not leak
    # ``None`` values into ``hashes`` (the SDK model rejects them); only the
    # present fingerprint is kept and the object must serialize cleanly.
    builder = CensysStixBuilder()

    certificate = builder.add_certificate(cert=Certificate(fingerprint_sha256=SHA256))

    assert certificate is not None
    assert certificate.hashes == {HashAlgorithm.SHA256: SHA256}
    # Would raise before the fix (None hash values fail validation).
    certificate.to_stix2_object()


def test_add_certificate_without_fingerprints_is_skipped() -> None:
    # A certificate with parsed metadata but no fingerprint cannot be
    # serialized (empty hashes are rejected by stix2), so it is skipped.
    builder = CensysStixBuilder()

    certificate = builder.add_certificate(
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

    assert builder.add_certificate(cert=Certificate()) is None
    assert builder.add_certificate(cert=None) is None
