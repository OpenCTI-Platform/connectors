"""Tests for CVEProcessor utility methods."""

from cve_processor import CVEProcessor


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
