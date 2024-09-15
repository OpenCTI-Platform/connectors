from typing import List, Union

from open_cti import domain_object, observable
from stix2 import (
    URL,
    AutonomousSystem,
    Infrastructure,
    IPv4Address,
    Relationship,
    X509Certificate,
)
from zerofox.domain.phishing import Phishing


def phishing_to_infrastructure(created_by, now: str, entry: Phishing) -> List[
    Union[
        Infrastructure,
        Relationship,
        X509Certificate,
        URL,
        IPv4Address,
        AutonomousSystem,
    ]
]:
    """
    Creates a STIX Infrastructure/phishing object from a ZeroFOX Phishing object, along with :
        - a URL object for the phishing URL
        - an IPv4Address object for the phishing host
        - an AutonomousSystem object for the phishing host ASN
        - a X509Certificate object for the certificate authority and fingerprint, if present.

    """
    phishing = domain_object(
        created_by=created_by,
        cls=Infrastructure,
        name=f"{entry.domain}",
        created=now,
        infrastructure_types=["phishing"],
        first_seen=entry.scanned,
        external_references=[],
    )
    certificate_objects = build_certificate_objects(created_by, entry, phishing)

    url = observable(
        created_by=created_by,
        cls=URL,
        value=entry.url,
    )

    url_relationship = Relationship(
        source_ref=phishing.id,
        target_ref=url.id,
        relationship_type="consists-of",
        start_time=entry.scanned,
    )

    ip = observable(
        created_by=created_by,
        cls=IPv4Address,
        value=entry.host.ip,
    )

    ip_relationship = Relationship(
        source_ref=phishing.id,
        target_ref=ip.id,
        relationship_type="consists-of",
        start_time=entry.scanned,
    )

    asn = observable(
        created_by=created_by,
        cls=AutonomousSystem,
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


def build_certificate_objects(created_by, entry: Phishing, stix_phishing):
    if not entry.cert or not entry.cert.authority:
        return []
    certificate = observable(
        created_by=created_by,
        cls=X509Certificate,
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
