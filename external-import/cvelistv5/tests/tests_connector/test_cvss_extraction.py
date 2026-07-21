"""Tests for CVEProcessor CVSS extraction logic (covers fix for issue #6514)."""

from cve_processor import CVEProcessor

# ---------------------------------------------------------------------------
# Fixtures: realistic CVSS metric dicts matching cvelistV5 JSON structure
# ---------------------------------------------------------------------------

CVSS_V4_METRIC = {
    "cvssV4_0": {
        "version": "4.0",
        "baseScore": 8.8,
        "baseSeverity": "HIGH",
        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "attackRequirements": "NONE",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "vulnConfidentialityImpact": "HIGH",
        "subConfidentialityImpact": "NONE",
        "vulnIntegrityImpact": "LOW",
        "subIntegrityImpact": "NONE",
        "vulnAvailabilityImpact": "NONE",
        "subAvailabilityImpact": "NONE",
    }
}

CVSS_V31_METRIC = {
    "cvssV3_1": {
        "version": "3.1",
        "baseScore": 8.2,
        "baseSeverity": "HIGH",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "LOW",
        "availabilityImpact": "NONE",
    }
}

CVSS_V30_METRIC = {
    "cvssV3_0": {
        "version": "3.0",
        "baseScore": 7.5,
        "baseSeverity": "HIGH",
        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "NONE",
        "availabilityImpact": "NONE",
    }
}


# ---------------------------------------------------------------------------
# Tests for _extract_cvss_properties — issue #6514 fix
# ---------------------------------------------------------------------------


class TestExtractCvssProperties:
    """Ensure v3.x and v4.0 scores are extracted independently."""

    def test_both_v4_and_v31_present(self):
        """CVE-2019-25672 scenario: v4.0 must NOT overwrite v3.1 fields."""
        cna = {"metrics": [CVSS_V4_METRIC, CVSS_V31_METRIC]}
        props = CVEProcessor._extract_cvss_properties(cna, [])

        # v3.1 fields
        assert props["x_opencti_cvss_base_score"] == 8.2
        assert props["x_opencti_cvss_base_severity"] == "HIGH"
        assert props["x_opencti_cvss_vector_string"] == (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        )
        assert props["x_opencti_cvss_attack_vector"] == "NETWORK"
        assert props["x_opencti_cvss_attack_complexity"] == "LOW"
        assert props["x_opencti_cvss_privileges_required"] == "NONE"
        assert props["x_opencti_cvss_user_interaction"] == "NONE"
        assert props["x_opencti_cvss_scope"] == "UNCHANGED"
        assert props["x_opencti_cvss_confidentiality_impact"] == "HIGH"
        assert props["x_opencti_cvss_integrity_impact"] == "LOW"
        assert props["x_opencti_cvss_availability_impact"] == "NONE"

        # v4.0 fields stored separately
        assert props["x_opencti_cvss_v4_base_score"] == 8.8
        assert props["x_opencti_cvss_v4_base_severity"] == "HIGH"
        assert props["x_opencti_cvss_v4_vector_string"] == (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
        )
        assert props["x_opencti_cvss_v4_attack_vector"] == "NETWORK"
        assert props["x_opencti_cvss_v4_attack_complexity"] == "LOW"
        assert props["x_opencti_cvss_v4_attack_requirements"] == "NONE"
        assert props["x_opencti_cvss_v4_privileges_required"] == "NONE"
        assert props["x_opencti_cvss_v4_user_interaction"] == "NONE"
        assert props["x_opencti_cvss_v4_confidentiality_impact_v"] == "HIGH"
        assert props["x_opencti_cvss_v4_confidentiality_impact_s"] == "NONE"
        assert props["x_opencti_cvss_v4_integrity_impact_v"] == "LOW"
        assert props["x_opencti_cvss_v4_integrity_impact_s"] == "NONE"
        assert props["x_opencti_cvss_v4_availability_impact_v"] == "NONE"
        assert props["x_opencti_cvss_v4_availability_impact_s"] == "NONE"

    def test_only_v31_present(self):
        """When only v3.1 is available, v4 fields must be absent."""
        cna = {"metrics": [CVSS_V31_METRIC]}
        props = CVEProcessor._extract_cvss_properties(cna, [])

        assert props["x_opencti_cvss_base_score"] == 8.2
        assert props["x_opencti_cvss_vector_string"] == (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        )
        assert "x_opencti_cvss_v4_base_score" not in props

    def test_only_v4_present(self):
        """When only v4.0 is available, v3 fields must be absent."""
        cna = {"metrics": [CVSS_V4_METRIC]}
        props = CVEProcessor._extract_cvss_properties(cna, [])

        assert props["x_opencti_cvss_v4_base_score"] == 8.8
        assert props["x_opencti_cvss_v4_vector_string"] == (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
        )
        assert "x_opencti_cvss_base_score" not in props

    def test_v31_preferred_over_v30(self):
        """When both v3.1 and v3.0 exist, v3.1 takes precedence."""
        cna = {"metrics": [CVSS_V30_METRIC, CVSS_V31_METRIC]}
        props = CVEProcessor._extract_cvss_properties(cna, [])

        assert props["x_opencti_cvss_base_score"] == 8.2
        assert "3.1" in props["x_opencti_cvss_vector_string"]

    def test_fallback_to_v30_when_no_v31(self):
        """v3.0 is used when v3.1 is absent."""
        cna = {"metrics": [CVSS_V30_METRIC]}
        props = CVEProcessor._extract_cvss_properties(cna, [])

        assert props["x_opencti_cvss_base_score"] == 7.5
        assert "3.0" in props["x_opencti_cvss_vector_string"]

    def test_empty_metrics_returns_empty_dict(self):
        """No metrics at all means empty properties."""
        assert CVEProcessor._extract_cvss_properties({"metrics": []}, []) == {}
        assert CVEProcessor._extract_cvss_properties({}, []) == {}

    def test_fallback_to_adp_containers(self):
        """Metrics from ADP containers are used when CNA has none."""
        cna = {}
        adp = [{"metrics": [CVSS_V31_METRIC, CVSS_V4_METRIC]}]
        props = CVEProcessor._extract_cvss_properties(cna, adp)

        assert props["x_opencti_cvss_base_score"] == 8.2
        assert props["x_opencti_cvss_v4_base_score"] == 8.8

    def test_cna_metrics_take_priority_over_adp(self):
        """CNA metrics are used even if ADP also has metrics."""
        cna = {"metrics": [CVSS_V31_METRIC]}
        adp = [{"metrics": [CVSS_V4_METRIC]}]
        props = CVEProcessor._extract_cvss_properties(cna, adp)

        # v3 from CNA
        assert props["x_opencti_cvss_base_score"] == 8.2
        # v4 should NOT come from ADP since CNA has supported metrics
        assert "x_opencti_cvss_v4_base_score" not in props

    def test_unsupported_cna_metrics_falls_back_to_adp(self):
        """If CNA metrics has no supported version, ADP is used."""
        cna = {"metrics": [{"cvssV2_0": {"baseScore": 5.0}}]}
        adp = [{"metrics": [CVSS_V31_METRIC]}]
        props = CVEProcessor._extract_cvss_properties(cna, adp)

        assert props["x_opencti_cvss_base_score"] == 8.2


# ---------------------------------------------------------------------------
# Tests for _find_cvss_metric
# ---------------------------------------------------------------------------


class TestFindCvssMetric:
    def test_finds_v31_metric(self):
        from cve_processor import CVSS_V3_VERSIONS

        metrics = [CVSS_V4_METRIC, CVSS_V31_METRIC]
        result = CVEProcessor._find_cvss_metric(metrics, CVSS_V3_VERSIONS)
        assert result is not None
        assert result["baseScore"] == 8.2

    def test_finds_v4_metric(self):
        from cve_processor import CVSS_V4_VERSIONS

        metrics = [CVSS_V4_METRIC, CVSS_V31_METRIC]
        result = CVEProcessor._find_cvss_metric(metrics, CVSS_V4_VERSIONS)
        assert result is not None
        assert result["baseScore"] == 8.8

    def test_returns_none_when_not_found(self):
        from cve_processor import CVSS_V4_VERSIONS

        metrics = [CVSS_V31_METRIC]
        result = CVEProcessor._find_cvss_metric(metrics, CVSS_V4_VERSIONS)
        assert result is None

    def test_skips_non_dict_values(self):
        from cve_processor import CVSS_V3_VERSIONS

        metrics = [{"cvssV3_1": "not_a_dict"}, CVSS_V31_METRIC]
        result = CVEProcessor._find_cvss_metric(metrics, CVSS_V3_VERSIONS)
        assert result is not None
        assert result["baseScore"] == 8.2
