"""Tests for CVEProcessor utility methods."""

from unittest.mock import MagicMock

import stix2
from cve_processor import CVEProcessor
from pycti import Vulnerability


class TestNormalizeDate:
    def test_none_returns_none(self):
        assert CVEProcessor._normalize_date(None) is None

    def test_empty_string_returns_none(self):
        assert CVEProcessor._normalize_date("") is None

    def test_already_z_suffix_unchanged(self):
        assert (
            CVEProcessor._normalize_date("2024-01-15T10:00:00Z")
            == "2024-01-15T10:00:00Z"
        )

    def test_plus_zero_offset_normalized(self):
        assert (
            CVEProcessor._normalize_date("2024-01-15T10:00:00+00:00")
            == "2024-01-15T10:00:00Z"
        )

    def test_bare_datetime_gets_z_appended(self):
        assert (
            CVEProcessor._normalize_date("2024-01-15T10:00:00")
            == "2024-01-15T10:00:00Z"
        )


class TestExtractDescription:
    def test_english_description_preferred(self):
        cna = {
            "descriptions": [
                {"lang": "fr", "value": "Description en français"},
                {"lang": "en", "value": "English description"},
            ]
        }
        assert CVEProcessor._extract_description(cna) == "English description"

    def test_en_prefix_matches(self):
        cna = {"descriptions": [{"lang": "en-US", "value": "US English"}]}
        assert CVEProcessor._extract_description(cna) == "US English"

    def test_falls_back_to_first_entry(self):
        cna = {"descriptions": [{"lang": "fr", "value": "Seule description"}]}
        assert CVEProcessor._extract_description(cna) == "Seule description"

    def test_no_descriptions_returns_none(self):
        assert CVEProcessor._extract_description({}) is None
        assert CVEProcessor._extract_description({"descriptions": []}) is None


class TestExtractLabels:
    def test_extracts_cwe_id_and_description(self):
        cna = {
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "cweId": "CWE-79",
                            "description": "CWE-79 Cross-site Scripting (XSS)",
                            "lang": "en",
                        }
                    ]
                }
            ]
        }
        labels = CVEProcessor._extract_labels(cna)
        assert "CWE-79" in labels
        assert "Cross-site Scripting (XSS)" in labels

    def test_extracts_cwe_from_description_when_no_cweId(self):
        cna = {
            "problemTypes": [
                {
                    "descriptions": [
                        {"description": "CWE-89 SQL Injection", "lang": "en"}
                    ]
                }
            ]
        }
        labels = CVEProcessor._extract_labels(cna)
        assert "CWE-89" in labels
        assert "SQL Injection" in labels

    def test_deduplicates_labels(self):
        cna = {
            "problemTypes": [
                {
                    "descriptions": [
                        {"cweId": "CWE-79", "description": "CWE-79 XSS"},
                        {"cweId": "CWE-79", "description": "CWE-79 XSS"},
                    ]
                }
            ]
        }
        labels = CVEProcessor._extract_labels(cna)
        assert labels.count("CWE-79") == 1

    def test_empty_problem_types(self):
        assert CVEProcessor._extract_labels({}) == []
        assert CVEProcessor._extract_labels({"problemTypes": []}) == []


class TestExtractCpeVersion:
    def test_full_cpe_with_update(self):
        cpe = "cpe:2.3:a:vendor:product:1.0:update1:*:*:*:*:*:*"
        assert CVEProcessor._extract_cpe_version(cpe) == "1.0-update1"

    def test_full_cpe_without_update(self):
        cpe = "cpe:2.3:a:vendor:product:2.5:*:*:*:*:*:*:*"
        assert CVEProcessor._extract_cpe_version(cpe) == "2.5"

    def test_short_cpe(self):
        cpe = "cpe:2.3:a:vendor:product:3.0"
        assert CVEProcessor._extract_cpe_version(cpe) == "3.0"

    def test_very_short_cpe(self):
        cpe = "cpe:2.3:a:vendor"
        assert CVEProcessor._extract_cpe_version(cpe) == ""


class TestFormatVersion:
    def test_less_than(self):
        assert CVEProcessor._format_version({"lessThan": "2.0"}) == "<2.0"

    def test_less_than_or_equal(self):
        assert CVEProcessor._format_version({"lessThanOrEqual": "3.5"}) == "<=3.5"

    def test_exact_version(self):
        assert CVEProcessor._format_version({"version": "1.2.3"}) == "1.2.3"

    def test_empty_dict(self):
        assert CVEProcessor._format_version({}) == ""


class TestExtractFixedVersions:
    def test_less_than_upper_bound_is_a_fix(self):
        product = {
            "versions": [{"version": "1.0", "status": "affected", "lessThan": "1.25.5"}]
        }
        assert CVEProcessor._extract_fixed_versions(product) == ["1.25.5"]

    def test_less_than_or_equal_is_not_a_fix(self):
        product = {
            "versions": [
                {"version": "1.0", "status": "affected", "lessThanOrEqual": "1.4"}
            ]
        }
        assert CVEProcessor._extract_fixed_versions(product) == []

    def test_unaffected_version_is_a_fix(self):
        product = {
            "versions": [
                {"version": "2.3.1", "status": "affected"},
                {"version": "2.3.2", "status": "unaffected"},
            ]
        }
        assert CVEProcessor._extract_fixed_versions(product) == ["2.3.2"]

    def test_change_to_unaffected_is_a_fix(self):
        product = {
            "versions": [
                {
                    "version": "5.0",
                    "status": "affected",
                    "lessThan": "5.*",
                    "changes": [{"at": "5.0.3", "status": "unaffected"}],
                }
            ]
        }
        assert CVEProcessor._extract_fixed_versions(product) == ["5.0.3"]

    def test_wildcards_zero_and_git_are_skipped(self):
        product = {
            "versions": [
                {"version": "0", "status": "unaffected", "lessThan": "1.0"},
                {"version": "1.0", "status": "affected", "lessThan": "1.*"},
                {
                    "version": "abc123",
                    "status": "affected",
                    "lessThan": "def456",
                    "versionType": "git",
                },
            ]
        }
        assert CVEProcessor._extract_fixed_versions(product) == []

    def test_duplicates_are_removed(self):
        product = {
            "versions": [
                {"version": "1.0", "status": "affected", "lessThan": "1.2"},
                {"version": "1.2", "status": "unaffected"},
            ]
        }
        assert CVEProcessor._extract_fixed_versions(product) == ["1.2"]


class TestRemediatesRelationship:
    @staticmethod
    def _vulnerability():
        return stix2.Vulnerability(
            id=Vulnerability.generate_id("CVE-2026-0001"), name="CVE-2026-0001"
        )

    def test_fixed_version_writes_software_remediates_vulnerability(self):
        processor = CVEProcessor(MagicMock())
        vulnerability = self._vulnerability()
        product = {
            "vendor": "Acme",
            "product": "widget",
            "versions": [
                {"version": "1.0", "status": "affected", "lessThan": "1.25.5"}
            ],
        }
        objects = processor._build_affected_objects(product, vulnerability)

        softwares = {o["id"]: o for o in objects if o["type"] == "software"}
        remediates = [
            o
            for o in objects
            if o["type"] == "relationship" and o["relationship_type"] == "remediates"
        ]
        assert len(remediates) == 1
        fixed = softwares[remediates[0]["source_ref"]]
        assert fixed["version"] == "1.25.5"
        assert fixed["name"] == "widget 1.25.5"
        assert remediates[0]["target_ref"] == vulnerability.id
        # The affected range keeps its existing `has` relationship.
        has = [
            o
            for o in objects
            if o["type"] == "relationship" and o["relationship_type"] == "has"
        ]
        assert len(has) == 1
        assert softwares[has[0]["source_ref"]]["version"] == "<1.25.5"

    def test_cpes_path_also_writes_remediates(self):
        processor = CVEProcessor(MagicMock())
        product = {
            "vendor": "Acme",
            "product": "widget",
            "cpes": ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"],
            "versions": [{"version": "2.0", "status": "unaffected"}],
        }
        objects = processor._build_affected_objects(product, self._vulnerability())
        types = [o["relationship_type"] for o in objects if o["type"] == "relationship"]
        assert types.count("remediates") == 1

    def test_no_fix_named_writes_no_remediates(self):
        processor = CVEProcessor(MagicMock())
        product = {
            "vendor": "Acme",
            "product": "widget",
            "versions": [{"version": "1.0", "status": "affected"}],
        }
        objects = processor._build_affected_objects(product, self._vulnerability())
        assert not any(
            o["type"] == "relationship" and o["relationship_type"] == "remediates"
            for o in objects
        )
