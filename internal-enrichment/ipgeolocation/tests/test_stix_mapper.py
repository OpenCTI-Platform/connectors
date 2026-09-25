"""Tests for STIX 2.1 object creation."""


class TestSTIXMapper:

    def test_bundle_contains_author_identity(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        objects = mapper.build_bundle_objects(
            intel=high_risk_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
        )
        identities = [o for o in objects if getattr(o, "type", "") == "identity"]
        author = [i for i in identities if i.name == "IPGeolocation.io"]
        assert len(author) >= 1

    def test_country_location_created(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        objects = mapper.build_bundle_objects(
            intel=high_risk_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
        )
        locations = [o for o in objects if getattr(o, "type", "") == "location"]
        country_locs = [l for l in locations if l.country == "US"]
        assert len(country_locs) >= 1

    def test_city_location_has_coordinates(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        objects = mapper.build_bundle_objects(
            intel=high_risk_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
        )
        locations = [o for o in objects if getattr(o, "type", "") == "location"]
        cities = [l for l in locations if hasattr(l, "latitude")]
        assert any(l.latitude is not None for l in cities)

    def test_asn_object_created(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        objects = mapper.build_bundle_objects(
            intel=high_risk_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
        )
        asns = [o for o in objects if getattr(o, "type", "") == "autonomous-system"]
        assert len(asns) >= 1
        assert asns[0].number == 15169

    def test_relationships_created(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        objects = mapper.build_bundle_objects(
            intel=high_risk_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
            create_relationships=True,
        )
        rels = [o for o in objects if getattr(o, "type", "") == "relationship"]
        assert len(rels) >= 2  # at least located-at + belongs-to
        rel_types = {r.relationship_type for r in rels}
        assert "located-at" in rel_types
        assert "belongs-to" in rel_types

    def test_no_relationships_when_disabled(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        objects = mapper.build_bundle_objects(
            intel=high_risk_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
            create_relationships=False,
        )
        rels = [o for o in objects if getattr(o, "type", "") == "relationship"]
        assert len(rels) == 0

    def test_indicator_created_above_threshold(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        objects = mapper.build_bundle_objects(
            intel=high_risk_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
            create_indicators=True,
            indicator_threshold=50,
        )
        indicators = [o for o in objects if getattr(o, "type", "") == "indicator"]
        assert len(indicators) >= 1
        assert "ipv4-addr" in indicators[0].pattern

    def test_no_indicator_below_threshold(self, clean_intel, mapper, scorer):
        risk = scorer.assess(clean_intel)
        objects = mapper.build_bundle_objects(
            intel=clean_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
            create_indicators=True,
            indicator_threshold=50,
        )
        indicators = [o for o in objects if getattr(o, "type", "") == "indicator"]
        assert len(indicators) == 0

    def test_note_created(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        objects = mapper.build_bundle_objects(
            intel=high_risk_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
            create_notes=True,
            create_summary=True,
        )
        notes = [o for o in objects if getattr(o, "type", "") == "note"]
        assert len(notes) >= 1
        assert "Executive Summary" in notes[0].content

    def test_labels_derived_correctly(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        labels = mapper._derive_labels(high_risk_intel, risk)
        assert "vpn" in labels
        assert "proxy" in labels
        assert "known-attacker" in labels
        assert "cloud-provider" in labels

    def test_clean_ip_labels(self, clean_intel, mapper, scorer):
        risk = scorer.assess(clean_intel)
        labels = mapper._derive_labels(clean_intel, risk)
        assert "risk:low" in labels
        assert "cloud-provider" in labels  # Google is a cloud provider
        assert "vpn" not in labels
        assert "known-attacker" not in labels

    def test_abuse_contact_identity(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        objects = mapper.build_bundle_objects(
            intel=high_risk_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
        )
        identities = [o for o in objects if getattr(o, "type", "") == "identity"]
        abuse_ids = [i for i in identities if "Abuse" in i.name]
        assert len(abuse_ids) >= 1

    def test_hostname_domain_created(self, high_risk_intel, mapper, scorer):
        risk = scorer.assess(high_risk_intel)
        objects = mapper.build_bundle_objects(
            intel=high_risk_intel,
            risk=risk,
            observable_id="ipv4-addr--212aed99-b284-414d-960e-1c77921cb867",
            observable_type="IPv4-Addr",
        )
        domains = [o for o in objects if getattr(o, "type", "") == "domain-name"]
        assert len(domains) >= 1
        assert domains[0].value == "malicious-host.example.com"

    def test_ipv6_pattern(self, mapper, scorer):
        """IPv6 addresses should produce ipv6-addr patterns."""
        from src.models import IPIntelligence, SecurityData

        intel = IPIntelligence(ip="2001:db8::1")
        intel.security = SecurityData(threat_score=60, is_vpn=True)
        risk = scorer.assess(intel)
        objects = mapper.build_bundle_objects(
            intel=intel,
            risk=risk,
            observable_id="ipv6-addr--dedf9ff5-eed4-4d9c-bfe3-29e6e0f19b35",
            observable_type="IPv6-Addr",
            create_indicators=True,
            indicator_threshold=50,
        )
        indicators = [o for o in objects if getattr(o, "type", "") == "indicator"]
        assert len(indicators) >= 1
        assert "ipv6-addr" in indicators[0].pattern
