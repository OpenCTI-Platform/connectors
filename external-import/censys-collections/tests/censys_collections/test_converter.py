"""Tests for censys_collections.converter."""

from __future__ import annotations

from datetime import datetime, timezone

from censys_platform import (
    Certificate,
    CertificateParsed,
    Collection,
    CollectionStatus,
    Host,
    Reputation,
    SearchQueryHit,
    Service,
    Threat,
    ThreatActor,
    ThreatMalware,
    ValidityPeriod,
    Vuln,
    Webproperty,
)
from censys_platform.models import CertificateAsset, HostAssetWithMatchedServices, WebpropertyAsset
from censys_collections.converter import Converter, _parse_rfc3339
from connectors_sdk.models import (
    DomainName,
    IPV4Address,
    IPV6Address,
    Malware,
    Relationship,
    ThreatActorGroup,
    Vulnerability,
    X509Certificate,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_collection(
    name: str = "Test Collection",
    uid: str = "test-collection-id",
) -> Collection:
    return Collection(
        id=uid,
        name=name,
        query="ip:1.2.3.4",
        description="A test collection",
        status=CollectionStatus.ACTIVE,
        status_reason=None,
        total_assets=1,
        added_assets_24_hours=0,
        removed_assets_24_hours=0,
        create_time=datetime.now(tz=timezone.utc),
    )


def _make_converter(
    auto_indicator_by_score: bool = False,
    indicator_score_threshold: int = 50,
) -> Converter:
    return Converter(
        tlp_level="TLP:AMBER",
        score=50,
        auto_indicator_by_score=auto_indicator_by_score,
        indicator_score_threshold=indicator_score_threshold,
    )


# ---------------------------------------------------------------------------
# _parse_rfc3339
# ---------------------------------------------------------------------------


def test_parse_rfc3339_returns_none_for_empty() -> None:
    assert _parse_rfc3339(None) is None
    assert _parse_rfc3339("") is None


def test_parse_rfc3339_parses_z_suffix() -> None:
    dt = _parse_rfc3339("2024-01-01T00:00:00Z")
    assert dt is not None
    assert dt.tzinfo is not None


def test_parse_rfc3339_parses_offset() -> None:
    dt = _parse_rfc3339("2024-06-15T12:30:00+05:30")
    assert dt is not None
    assert dt.tzinfo is not None


def test_parse_rfc3339_returns_none_on_invalid() -> None:
    assert _parse_rfc3339("not-a-date") is None


# ---------------------------------------------------------------------------
# from_hit – host (IPv4)
# ---------------------------------------------------------------------------


def test_from_hit_ipv4_creates_observable() -> None:
    converter = _make_converter()
    collection = _make_collection()
    host = Host(ip="1.2.3.4")
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ip_observables = [o for o in objects if isinstance(o, IPV4Address)]
    assert len(ip_observables) == 1
    assert ip_observables[0].value == "1.2.3.4"
    assert ip_observables[0].create_indicator is True
    assert ip_observables[0].score == 50


def test_from_hit_ipv4_has_external_reference() -> None:
    converter = _make_converter()
    collection = _make_collection(uid="my-coll-id")
    host = Host(ip="5.6.7.8")
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ip_obs = next(o for o in objects if isinstance(o, IPV4Address))
    assert ip_obs.external_references is not None
    ext_ref = ip_obs.external_references[0]
    assert "my-coll-id" in (ext_ref.url or "")
    assert ext_ref.external_id == "my-coll-id"


def test_from_hit_ipv4_no_ip_returns_empty() -> None:
    converter = _make_converter()
    collection = _make_collection()
    host = Host()  # no ip field
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    assert converter.from_hit(hit, collection) == []


# ---------------------------------------------------------------------------
# from_hit – host reputation score
# ---------------------------------------------------------------------------


def test_from_hit_host_uses_censys_reputation_score_when_present() -> None:
    converter = _make_converter()  # configured fallback score is 50
    collection = _make_collection()
    host = Host(ip="9.9.9.9", reputation=Reputation(score=87.0))
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ip_obs = next(o for o in objects if isinstance(o, IPV4Address))
    assert ip_obs.score == 87


def test_from_hit_host_falls_back_to_configured_score_when_reputation_missing() -> None:
    converter = _make_converter()  # configured fallback score is 50
    collection = _make_collection()
    host = Host(ip="9.9.9.8")  # no reputation at all
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ip_obs = next(o for o in objects if isinstance(o, IPV4Address))
    assert ip_obs.score == 50


def test_from_hit_host_falls_back_to_configured_score_when_score_is_none() -> None:
    converter = _make_converter()
    collection = _make_collection()
    # Reputation object present, but its score field is unset.
    host = Host(ip="9.9.9.7", reputation=Reputation(score_level=None))
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ip_obs = next(o for o in objects if isinstance(o, IPV4Address))
    assert ip_obs.score == 50


def test_from_hit_host_reputation_score_is_rounded_and_clamped() -> None:
    converter = _make_converter()
    collection = _make_collection()
    host = Host(ip="9.9.9.6", reputation=Reputation(score=99.6))
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ip_obs = next(o for o in objects if isinstance(o, IPV4Address))
    assert ip_obs.score == 100


# ---------------------------------------------------------------------------
# from_hit – auto_indicator_by_score
# ---------------------------------------------------------------------------


def test_auto_indicator_by_score_disabled_always_creates_indicator() -> None:
    """Default behavior: create_indicator is always True regardless of score."""
    converter = _make_converter(auto_indicator_by_score=False)
    collection = _make_collection()
    host = Host(ip="1.2.3.4", reputation=Reputation(score=1.0))  # very low score
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ip_obs = next(o for o in objects if isinstance(o, IPV4Address))
    assert ip_obs.score == 1
    assert ip_obs.create_indicator is True


def test_auto_indicator_by_score_enabled_creates_indicator_above_threshold() -> None:
    converter = _make_converter(auto_indicator_by_score=True, indicator_score_threshold=60)
    collection = _make_collection()
    host = Host(ip="1.2.3.5", reputation=Reputation(score=75.0))
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ip_obs = next(o for o in objects if isinstance(o, IPV4Address))
    assert ip_obs.create_indicator is True


def test_auto_indicator_by_score_enabled_skips_indicator_below_threshold() -> None:
    converter = _make_converter(auto_indicator_by_score=True, indicator_score_threshold=60)
    collection = _make_collection()
    host = Host(ip="1.2.3.6", reputation=Reputation(score=40.0))
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ip_obs = next(o for o in objects if isinstance(o, IPV4Address))
    # Observable is still created, just without the auto-indicator flag.
    assert ip_obs.create_indicator is False


def test_auto_indicator_by_score_enabled_score_equal_to_threshold_creates_indicator() -> None:
    converter = _make_converter(auto_indicator_by_score=True, indicator_score_threshold=60)
    collection = _make_collection()
    host = Host(ip="1.2.3.7", reputation=Reputation(score=60.0))
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ip_obs = next(o for o in objects if isinstance(o, IPV4Address))
    assert ip_obs.create_indicator is True


def test_auto_indicator_by_score_applies_to_certificate() -> None:
    converter = _make_converter(auto_indicator_by_score=True, indicator_score_threshold=60)
    # Converter's fallback score is 50, below the 60 threshold.
    collection = _make_collection()
    cert = Certificate(fingerprint_sha256="a" * 64)
    hit = SearchQueryHit(certificate_v1=CertificateAsset(extensions={}, resource=cert))
    objects = converter.from_hit(hit, collection)

    x509 = next(o for o in objects if isinstance(o, X509Certificate))
    assert x509.create_indicator is False


def test_auto_indicator_by_score_applies_to_webproperty() -> None:
    converter = _make_converter(auto_indicator_by_score=True, indicator_score_threshold=40)
    # Converter's fallback score is 50, above the 40 threshold.
    collection = _make_collection()
    wp = Webproperty(hostname="example.com")
    hit = SearchQueryHit(webproperty_v1=WebpropertyAsset(extensions={}, resource=wp))
    objects = converter.from_hit(hit, collection)

    domain = next(o for o in objects if isinstance(o, DomainName))
    assert domain.create_indicator is True


# ---------------------------------------------------------------------------
# from_hit – host (IPv6)
# ---------------------------------------------------------------------------


def test_from_hit_ipv6_creates_observable() -> None:
    converter = _make_converter()
    collection = _make_collection()
    host = Host(ip="2001:db8::1")
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    ipv6_obs = [o for o in objects if isinstance(o, IPV6Address)]
    assert len(ipv6_obs) == 1
    assert ipv6_obs[0].value == "2001:db8::1"


# ---------------------------------------------------------------------------
# from_hit – host with malware threat
# ---------------------------------------------------------------------------


def test_from_hit_host_with_malware_creates_malware_and_relationship() -> None:
    converter = _make_converter()
    collection = _make_collection()
    threat = Threat(malware=ThreatMalware(primary_name="CobaltStrike", all_names=["CobaltStrike", "CS"]))
    service = Service(threats=[threat])
    host = Host(ip="10.0.0.1", services=[service])
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    malware_objs = [o for o in objects if isinstance(o, Malware)]
    assert len(malware_objs) == 1
    assert malware_objs[0].name == "CobaltStrike"

    rel_objs = [
        o for o in objects
        if isinstance(o, Relationship) and o.type == RelationshipType.RELATED_TO
    ]
    assert len(rel_objs) == 1


def test_from_hit_host_deduplicates_same_malware_across_services() -> None:
    converter = _make_converter()
    collection = _make_collection()
    threat = Threat(malware=ThreatMalware(primary_name="Mirai"))
    service1 = Service(threats=[threat])
    service2 = Service(threats=[threat])
    host = Host(ip="10.0.0.2", services=[service1, service2])
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    malware_objs = [o for o in objects if isinstance(o, Malware)]
    assert len(malware_objs) == 1  # deduplicated


# ---------------------------------------------------------------------------
# from_hit – host with threat actor
# ---------------------------------------------------------------------------


def test_from_hit_host_with_actor_creates_actor_and_relationship() -> None:
    converter = _make_converter()
    collection = _make_collection()
    actor = ThreatActor(primary_name="APT28", all_names=["APT28", "Fancy Bear"])
    threat = Threat(actors=[actor])
    service = Service(threats=[threat])
    host = Host(ip="192.168.1.1", services=[service])
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    actor_objs = [o for o in objects if isinstance(o, ThreatActorGroup)]
    assert len(actor_objs) == 1
    assert actor_objs[0].name == "APT28"

    rel_objs = [
        o for o in objects
        if isinstance(o, Relationship) and o.type == RelationshipType.ATTRIBUTED_TO
    ]
    assert len(rel_objs) == 1


# ---------------------------------------------------------------------------
# from_hit – host with vulnerability
# ---------------------------------------------------------------------------


def test_from_hit_host_with_vuln_creates_vulnerability_and_relationship() -> None:
    converter = _make_converter()
    collection = _make_collection()
    vuln = Vuln(id="CVE-2021-44228")
    service = Service(vulns=[vuln])
    host = Host(ip="172.16.0.1", services=[service])
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host)
    )
    objects = converter.from_hit(hit, collection)

    vuln_objs = [o for o in objects if isinstance(o, Vulnerability)]
    assert len(vuln_objs) == 1
    assert vuln_objs[0].name == "CVE-2021-44228"

    rel_objs = [
        o for o in objects
        if isinstance(o, Relationship) and o.type == RelationshipType.RELATED_TO
    ]
    assert len(rel_objs) == 1


# ---------------------------------------------------------------------------
# from_hit – certificate
# ---------------------------------------------------------------------------


def test_from_hit_certificate_creates_x509() -> None:
    converter = _make_converter()
    collection = _make_collection()
    cert = Certificate(
        fingerprint_sha256="a" * 64,
        fingerprint_sha1="b" * 40,
        fingerprint_md5="c" * 32,
    )
    hit = SearchQueryHit(
        certificate_v1=CertificateAsset(extensions={}, resource=cert)
    )
    objects = converter.from_hit(hit, collection)

    x509_objs = [o for o in objects if isinstance(o, X509Certificate)]
    assert len(x509_objs) == 1
    assert x509_objs[0].hashes is not None
    assert x509_objs[0].hashes.get(HashAlgorithm.SHA256) == "a" * 64


def test_from_hit_certificate_no_hashes_returns_empty() -> None:
    converter = _make_converter()
    collection = _make_collection()
    cert = Certificate()  # no fingerprints
    hit = SearchQueryHit(
        certificate_v1=CertificateAsset(extensions={}, resource=cert)
    )
    assert converter.from_hit(hit, collection) == []


def test_from_hit_certificate_extracts_parsed_metadata() -> None:
    converter = _make_converter()
    collection = _make_collection()
    parsed = CertificateParsed(
        issuer_dn="CN=Test CA",
        subject_dn="CN=example.com",
        serial_number="0123456789",
        validity_period=ValidityPeriod(
            not_before="2024-01-01T00:00:00Z",
            not_after="2025-01-01T00:00:00Z",
        ),
    )
    cert = Certificate(fingerprint_sha256="a" * 64, parsed=parsed)
    hit = SearchQueryHit(
        certificate_v1=CertificateAsset(extensions={}, resource=cert)
    )
    objects = converter.from_hit(hit, collection)

    x509 = next(o for o in objects if isinstance(o, X509Certificate))
    assert x509.issuer == "CN=Test CA"
    assert x509.subject == "CN=example.com"
    assert x509.serial_number == "0123456789"
    assert x509.validity_not_before is not None
    assert x509.validity_not_after is not None


# ---------------------------------------------------------------------------
# from_hit – webproperty
# ---------------------------------------------------------------------------


def test_from_hit_webproperty_creates_domain_observable() -> None:
    converter = _make_converter()
    collection = _make_collection()
    wp = Webproperty(hostname="evil.example.com")
    hit = SearchQueryHit(
        webproperty_v1=WebpropertyAsset(extensions={}, resource=wp)
    )
    objects = converter.from_hit(hit, collection)

    domain_objs = [o for o in objects if isinstance(o, DomainName)]
    assert len(domain_objs) == 1
    assert domain_objs[0].value == "evil.example.com"
    assert domain_objs[0].create_indicator is True


def test_from_hit_webproperty_no_hostname_returns_empty() -> None:
    converter = _make_converter()
    collection = _make_collection()
    wp = Webproperty()
    hit = SearchQueryHit(
        webproperty_v1=WebpropertyAsset(extensions={}, resource=wp)
    )
    assert converter.from_hit(hit, collection) == []


def test_from_hit_webproperty_with_malware() -> None:
    converter = _make_converter()
    collection = _make_collection()
    threat = Threat(malware=ThreatMalware(primary_name="AgentTesla"))
    wp = Webproperty(hostname="phishing.example.com", threats=[threat])
    hit = SearchQueryHit(
        webproperty_v1=WebpropertyAsset(extensions={}, resource=wp)
    )
    objects = converter.from_hit(hit, collection)

    assert any(isinstance(o, Malware) for o in objects)
    assert any(
        isinstance(o, Relationship) and o.type == RelationshipType.RELATED_TO
        for o in objects
    )


def test_from_hit_webproperty_with_vuln() -> None:
    converter = _make_converter()
    collection = _make_collection()
    vuln = Vuln(id="CVE-2023-12345")
    wp = Webproperty(hostname="vuln.example.com", vulns=[vuln])
    hit = SearchQueryHit(
        webproperty_v1=WebpropertyAsset(extensions={}, resource=wp)
    )
    objects = converter.from_hit(hit, collection)

    assert any(isinstance(o, Vulnerability) for o in objects)
    assert any(
        isinstance(o, Relationship) and o.type == RelationshipType.RELATED_TO
        for o in objects
    )


# ---------------------------------------------------------------------------
# Hit with all three asset types
# ---------------------------------------------------------------------------


def test_from_hit_multiple_asset_types() -> None:
    """A hit can theoretically carry host + cert + webproperty; all are emitted."""
    converter = _make_converter()
    collection = _make_collection()
    host = Host(ip="1.1.1.1")
    cert = Certificate(fingerprint_sha256="d" * 64)
    wp = Webproperty(hostname="multi.example.com")
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=host),
        certificate_v1=CertificateAsset(extensions={}, resource=cert),
        webproperty_v1=WebpropertyAsset(extensions={}, resource=wp),
    )
    objects = converter.from_hit(hit, collection)

    assert any(isinstance(o, IPV4Address) for o in objects)
    assert any(isinstance(o, X509Certificate) for o in objects)
    assert any(isinstance(o, DomainName) for o in objects)
