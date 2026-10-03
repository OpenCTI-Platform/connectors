"""Tests for the markdown note generator."""


class TestMarkdownGenerator:

    def test_executive_summary_present(self, high_risk_intel, md_gen, scorer):
        risk = scorer.assess(high_risk_intel)
        md = md_gen.generate(high_risk_intel, risk)
        assert "## Executive Summary" in md
        assert "2.56.188.34" in md

    def test_summary_table_present(self, high_risk_intel, md_gen, scorer):
        risk = scorer.assess(high_risk_intel)
        md = md_gen.generate(high_risk_intel, risk)
        assert "## IP Summary" in md
        assert "| Field | Value |" in md
        assert "United States" in md

    def test_security_section_for_threats(self, high_risk_intel, md_gen, scorer):
        risk = scorer.assess(high_risk_intel)
        md = md_gen.generate(high_risk_intel, risk)
        assert "## Security Assessment" in md
        assert "VPN" in md or "vpn" in md.lower()

    def test_no_security_section_for_clean(self, clean_intel, md_gen, scorer):
        risk = scorer.assess(clean_intel)
        md = md_gen.generate(clean_intel, risk)
        # Clean IP should not have threat narrative about being an attacker
        assert "flagged for known attacker" not in md.lower()

    def test_infrastructure_profile(self, high_risk_intel, md_gen, scorer):
        risk = scorer.assess(high_risk_intel)
        md = md_gen.generate(high_risk_intel, risk)
        assert "## Infrastructure Profile" in md
        assert "Google LLC" in md

    def test_network_context(self, high_risk_intel, md_gen, scorer):
        risk = scorer.assess(high_risk_intel)
        md = md_gen.generate(high_risk_intel, risk)
        assert "## Network Context" in md
        assert "AS15169" in md

    def test_abuse_workflow(self, high_risk_intel, md_gen, scorer):
        risk = scorer.assess(high_risk_intel)
        md = md_gen.generate(high_risk_intel, risk)
        assert "## Abuse Contact" in md
        assert "abuse@packethub.net" in md

    def test_geo_intelligence(self, high_risk_intel, md_gen, scorer):
        risk = scorer.assess(high_risk_intel)
        md = md_gen.generate(high_risk_intel, risk)
        assert "## Geo Intelligence" in md
        assert "Dallas" in md
        assert "32.7767" in md  # latitude

    def test_timeline_with_dates(self, high_risk_intel, md_gen, scorer):
        risk = scorer.assess(high_risk_intel)
        md = md_gen.generate(high_risk_intel, risk)
        assert "## Timeline" in md
        assert "2025-12-12" in md  # proxy_last_seen
        assert "2026-01-19" in md  # vpn_last_seen

    def test_confidence_explanation(self, high_risk_intel, md_gen, scorer):
        risk = scorer.assess(high_risk_intel)
        md = md_gen.generate(high_risk_intel, risk)
        assert "## Enrichment Confidence" in md

    def test_footer_present(self, high_risk_intel, md_gen, scorer):
        risk = scorer.assess(high_risk_intel)
        md = md_gen.generate(high_risk_intel, risk)
        assert "IPGeolocation.io OpenCTI Connector" in md
