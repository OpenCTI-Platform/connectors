from typing import List, Union

from stix2 import (
    URL,
    AutonomousSystem,
    Infrastructure,
    IPv4Address,
    Relationship,
    X509Certificate,
)
from zerofox.domain.phishing import Phishing


def phishing_to_infrastructure(now: str, entry: Phishing) -> List[
    Union[
        Infrastructure,
        Relationship,
        X509Certificate,
        URL,
        IPv4Address,
        AutonomousSystem,
    ]
]:
    phishing = Infrastructure(
        name=f"{entry.domain}",
        created=now,
        infrastructure_types=["phishing"],
        first_seen=entry.scanned,
        external_references=[],
    )
    certificate_objects = build_certificate_objects(entry, phishing)

    url = URL(
        value=entry.url,
    )

    url_relationship = Relationship(
        source_ref=phishing.id,
        target_ref=url.id,
        relationship_type="consists-of",
        start_time=entry.scanned,
    )

    ip = IPv4Address(
        value=entry.host.ip,
    )

    ip_relationship = Relationship(
        source_ref=phishing.id,
        target_ref=ip.id,
        relationship_type="consists-of",
        start_time=entry.scanned,
    )

    asn = AutonomousSystem(
        number=entry.host.asn,
    )

    asn_relationship = Relationship(
        source_ref=phishing.id,
        target_ref=asn.id,
        relationship_type="consists-of",
        start_time=entry.scanned,
    )

    return [
        phishing,
        url,
        url_relationship,
        ip,
        ip_relationship,
        asn,
        asn_relationship,
    ] + certificate_objects


def build_certificate_objects(entry: Phishing, stix_phishing):
    if not entry.cert or not entry.cert.authority:
        return []
    certificate = X509Certificate(
        issuer=entry.cert.authority,
        hashes={"SHA-1": entry.cert.fingerprint} if entry.cert.fingerprint else None,
    )
    certificate_relationship = Relationship(
        source_ref=stix_phishing.id,
        target_ref=certificate.id,
        relationship_type="consists-of",
        start_time=entry.scanned,
    )

    return [certificate, certificate_relationship]
