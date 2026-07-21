from unittest.mock import MagicMock

import stix2
from connector.converter_to_stix import ConverterToStix
from pycti import STIX_EXT_OCTI_SCO, StixCoreRelationship


def _make_domain_entity(value: str = "discord.ma") -> dict:
    domain = stix2.DomainName(value=value)
    return {"id": domain.id, "value": value}


def _make_ip_entity(value: str = "1.2.3.4") -> dict:
    ip = stix2.IPv4Address(value=value)
    return {"id": ip.id, "type": "IPv4-Addr", "value": value}


def _score_in_extensions(stix_entity: dict):
    """Return the OpenCTI score on the entity (or raise KeyError if absent)."""
    return stix_entity["extensions"][STIX_EXT_OCTI_SCO]["score"]


def test_enrich_ip_high_sets_score_100():
    """HIGH risk must set score to 100 and create an Indicator."""
    converter = ConverterToStix(helper=MagicMock(), tlp_level="clear")
    ip_entity = _make_ip_entity()
    data = {"risk": {"latest_risk": "HIGH"}, "tags": ["c2"]}

    new_objects = converter.enrich_ip(ip_entity, data)

    assert _score_in_extensions(ip_entity) == 100
    indicators = [o for o in new_objects if isinstance(o, stix2.Indicator)]
    assert len(indicators) == 1


def test_enrich_ip_suspicious_sets_score_50():
    """SUSPICIOUS risk must set score to 50 and create no Indicator."""
    converter = ConverterToStix(helper=MagicMock(), tlp_level="clear")
    ip_entity = _make_ip_entity()
    data = {"risk": {"latest_risk": "SUSPICIOUS"}}

    new_objects = converter.enrich_ip(ip_entity, data)

    assert _score_in_extensions(ip_entity) == 50
    indicators = [o for o in new_objects if isinstance(o, stix2.Indicator)]
    assert len(indicators) == 0


def test_enrich_ip_halo_tag_sets_score_0():
    """UNRATED + `halo` tag must set score to 0 and create no Indicator."""
    converter = ConverterToStix(helper=MagicMock(), tlp_level="clear")
    ip_entity = _make_ip_entity()
    data = {
        "risk": {"latest_risk": "UNRATED"},
        "tags": ["halo", "cloud-provider"],
    }

    new_objects = converter.enrich_ip(ip_entity, data)

    assert _score_in_extensions(ip_entity) == 0
    indicators = [o for o in new_objects if isinstance(o, stix2.Indicator)]
    assert len(indicators) == 0


def test_enrich_ip_unrated_no_halo_does_not_set_score():
    """UNRATED without `halo` must NOT touch the observable's score.

    Regression: previously UNRATED mapped to 0, which silently overwrote
    higher-confidence scores from other connectors.
    """
    converter = ConverterToStix(helper=MagicMock(), tlp_level="clear")
    ip_entity = _make_ip_entity()
    assert "extensions" not in ip_entity
    data = {"risk": {"latest_risk": "UNRATED"}, "tags": ["cloud-provider"]}

    new_objects = converter.enrich_ip(ip_entity, data)

    sco_ext = ip_entity.get("extensions", {}).get(STIX_EXT_OCTI_SCO, {})
    assert "score" not in sco_ext
    indicators = [o for o in new_objects if isinstance(o, stix2.Indicator)]
    assert len(indicators) == 0


def test_enrich_domain_emits_relationship_for_each_cert():
    """Each X509Certificate must come with a domain→cert `related-to` relationship.

    Regression test: certs were previously appended to the bundle as orphan
    observables with no link back to the domain that owned them.
    """
    converter = ConverterToStix(helper=MagicMock(), tlp_level="clear")
    domain_entity = _make_domain_entity("discord.ma")

    data = {
        "risk": {"score": "UNRATED"},
        "ssl_certs": [
            {
                "cert_fingerprint_sha1": "83ce4638bc618bb0b08e17575c15ac06216e5314",
                "cert_issuer_dn": "/C=US/CN=R12/O=Let's Encrypt",
                "cert_subject_dn": "/CN=discord.ma",
                "cert_not_before_timestamp": "2026-04-20T15:58:05Z",
                "cert_not_after_timestamp": "2026-07-19T15:58:04Z",
            },
            {
                "cert_fingerprint_sha1": "53b13bf01d9e3981c5c55457ad6232ed701d81b2",
                "cert_issuer_dn": "/C=US/CN=R12/O=Let's Encrypt",
                "cert_subject_dn": "/CN=discord.ma",
                "cert_not_before_timestamp": "2026-04-20T15:58:05Z",
                "cert_not_after_timestamp": "2026-07-19T15:58:04Z",
            },
        ],
    }

    new_objects = converter.enrich_domain(domain_entity, data)

    certs = [o for o in new_objects if isinstance(o, stix2.X509Certificate)]
    cert_relationships = [
        o
        for o in new_objects
        if isinstance(o, stix2.Relationship)
        and o.relationship_type == "related-to"
        and o.source_ref == domain_entity["id"]
        and o.target_ref in {c.id for c in certs}
    ]

    assert len(certs) == 2, "expected one X509Certificate per ssl_certs entry"
    assert (
        len(cert_relationships) == 2
    ), "expected a related-to relationship from the domain to each X509Certificate"

    # Every cert must be the target of exactly one of those relationships.
    targeted = {rel.target_ref for rel in cert_relationships}
    assert targeted == {c.id for c in certs}

    # The relationship IDs MUST be deterministic via StixCoreRelationship.generate_id.
    for rel in cert_relationships:
        assert rel.id == StixCoreRelationship.generate_id(
            "related-to", domain_entity["id"], rel.target_ref
        )
