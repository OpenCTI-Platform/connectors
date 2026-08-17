"""Tests for CisaIcsAdvisories: RSS parsing, CSAF product-tree extraction,
and STIX bundle construction.

Mirrors the CISA KEV connector's test style: bypass `__init__` (which
connects to OpenCTI) and drive the pure-logic methods against a hand-built
instance and a real CSAF fixture (`tests/fixtures/icsa-26-225-05.json`,
fetched from cisagov/CSAF).
"""
import json
from types import SimpleNamespace
from typing import List

import stix2
from main import CisaIcsAdvisories, _CSAF_LINK_RE


def _make_connector() -> CisaIcsAdvisories:
    conn = object.__new__(CisaIcsAdvisories)
    conn.helper = SimpleNamespace(
        log_info=lambda *a, **kw: None,
        log_error=lambda *a, **kw: None,
        stix2_create_bundle=lambda objs: stix2.Bundle(
            objects=objs, allow_custom=True
        ).serialize(),
    )
    conn.org = "Cybersecurity and Infrastructure Security Agency"
    conn.set_created_by_stix()
    conn.tlp_marking = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    return conn


def _types(objs) -> List[str]:
    return [getattr(o, "type", None) or o.get("type") for o in objs]


# --------------------------------------------------------------------- RSS


class TestCsafLinkExtraction:
    def test_extracts_raw_path_from_rss_description(self, rss_item_xml):
        match = _CSAF_LINK_RE.search(rss_item_xml)
        assert match is not None
        assert match.group("path") == "csaf_files/OT/white/2026/icsa-26-225-05.json"
        assert match.group("ref") == "develop"


# --------------------------------------------------------------- Products


class TestProductTreeExtraction:
    def test_extracts_vendor_and_product_per_product_id(self, sample_csaf):
        conn = _make_connector()
        products = conn._extract_products(sample_csaf)
        assert products["CSAFPID-0001"] == {
            "vendor": "ANDRITZ",
            "product": "HIPASE-250",
        }
        assert products["CSAFPID-0002"] == {
            "vendor": "ANDRITZ",
            "product": "250 SCALA",
        }


# ------------------------------------------------------------------ Bundle


class TestBuildBundle:
    def test_report_and_vulnerabilities_emitted(self, sample_advisory, sample_csaf):
        conn = _make_connector()
        bundle_json = conn.build_bundle(sample_advisory, sample_csaf)
        data = json.loads(bundle_json)
        types = [o["type"] for o in data["objects"]]

        assert "report" in types
        # Fixture has 4 vulnerabilities, each with a distinct CVE.
        assert types.count("vulnerability") == 4

    def test_report_references_the_advisory(self, sample_advisory, sample_csaf):
        conn = _make_connector()
        bundle_json = conn.build_bundle(sample_advisory, sample_csaf)
        data = json.loads(bundle_json)
        report = [o for o in data["objects"] if o["type"] == "report"][0]
        assert "ICSA-26-225-05" in report["name"]
        assert report["external_references"][0]["external_id"] == "ICSA-26-225-05"

    def test_software_deduplicated_across_vulnerabilities(
        self, sample_advisory, sample_csaf
    ):
        """Multiple CVEs affecting the same product must yield ONE Software SCO."""
        conn = _make_connector()
        bundle_json = conn.build_bundle(sample_advisory, sample_csaf)
        data = json.loads(bundle_json)
        software = [o for o in data["objects"] if o["type"] == "software"]
        names = {s["name"] for s in software}
        # Both ANDRITZ products appear in the fixture's product_status.
        assert names <= {"HIPASE-250", "250 SCALA"}
        assert len(software) == len(names), "Expected each product emitted exactly once"

    def test_vendor_identity_emitted(self, sample_advisory, sample_csaf):
        conn = _make_connector()
        bundle_json = conn.build_bundle(sample_advisory, sample_csaf)
        data = json.loads(bundle_json)
        identities = [o for o in data["objects"] if o["type"] == "identity"]
        names = {i["name"] for i in identities}
        assert "ANDRITZ" in names
        assert "Cybersecurity and Infrastructure Security Agency" in names

    def test_vulnerability_carries_advisory_custom_property(
        self, sample_advisory, sample_csaf
    ):
        conn = _make_connector()
        bundle_json = conn.build_bundle(sample_advisory, sample_csaf)
        data = json.loads(bundle_json)
        vulns = [o for o in data["objects"] if o["type"] == "vulnerability"]
        assert all(
            v.get("x_opencti_cisa_ics_advisory") == "ICSA-26-225-05" for v in vulns
        )

    def test_software_has_vulnerability_relationship(
        self, sample_advisory, sample_csaf
    ):
        conn = _make_connector()
        bundle_json = conn.build_bundle(sample_advisory, sample_csaf)
        data = json.loads(bundle_json)
        rels = [o for o in data["objects"] if o["type"] == "relationship"]
        has_rels = [r for r in rels if r["relationship_type"] == "has"]
        assert any(
            "software" in r["source_ref"] and "vulnerability" in r["target_ref"]
            for r in has_rels
        )

    def test_no_cve_advisory_returns_none(self, sample_advisory):
        conn = _make_connector()
        empty_csaf = {"document": {"title": "No CVE Advisory", "tracking": {"id": "X"}}}
        assert conn.build_bundle(sample_advisory, empty_csaf) is None

    def test_bundle_is_stix2_serialisable(self, sample_advisory, sample_csaf):
        conn = _make_connector()
        bundle_json = conn.build_bundle(sample_advisory, sample_csaf)
        # Must round-trip through STIX's own parser, not just json.loads.
        parsed = stix2.parse(bundle_json, allow_custom=True)
        assert parsed.type == "bundle"
        assert len(parsed.objects) > 0
