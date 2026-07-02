"""Tests for label normalization and score determination by labels."""

import pytest
from crowdstrike_feeds_services.utils.labels import (
    _normalize_label_value,
    extract_label_names,
    parse_crowdstrike_labels,
)


class TestNormalizeLabelValue:
    """Unit tests for _normalize_label_value."""

    def test_camel_case_split(self):
        """CamelCase values without spaces are split into words."""
        assert _normalize_label_value("DataObfuscation") == "Data Obfuscation"

    def test_camel_case_split_with_slash(self):
        """CamelCase values containing '/' are still split (human-readable display)."""
        assert (
            _normalize_label_value("MaliciousConfidence/High")
            == "Malicious Confidence/High"
        )
        assert (
            _normalize_label_value("MaliciousConfidence/Medium")
            == "Malicious Confidence/Medium"
        )
        assert (
            _normalize_label_value("MaliciousConfidence/Low")
            == "Malicious Confidence/Low"
        )

    def test_already_spaced_value_unchanged(self):
        """Values with spaces are not subject to CamelCase splitting."""
        assert _normalize_label_value("Data Obfuscation") == "Data Obfuscation"

    def test_empty_and_none(self):
        assert _normalize_label_value("") == ""
        assert _normalize_label_value(None) == ""

    def test_whitespace_collapse(self):
        assert _normalize_label_value("  foo   bar  ") == "foo bar"


class TestExtractLabelNames:
    """Unit tests for extract_label_names."""

    def test_string_labels_normalized(self):
        result = extract_label_names(["DataObfuscation", "MaliciousConfidence/High"])
        assert "Data Obfuscation" in result
        assert "Malicious Confidence/High" in result

    def test_dict_labels_extracted(self):
        result = extract_label_names(
            [{"value": "MaliciousConfidence/Low"}, {"name": "SomeLabel"}]
        )
        assert "Malicious Confidence/Low" in result
        assert "Some Label" in result


class TestScoreMatchingIntegration:
    """Integration: normalized labels must still match config score labels (space-insensitive)."""

    @pytest.mark.parametrize(
        "raw_label,config_label",
        [
            ("MaliciousConfidence/High", "MaliciousConfidence/High"),
            ("MaliciousConfidence/Medium", "MaliciousConfidence/Medium"),
            ("MaliciousConfidence/Low", "MaliciousConfidence/Low"),
        ],
    )
    def test_confidence_labels_match_config_space_insensitive(
        self, raw_label, config_label
    ):
        """Normalized labels match config values when spaces are stripped (Option A logic)."""
        parsed = parse_crowdstrike_labels([raw_label])
        # The normalized label (e.g. "Malicious Confidence/High") must match
        # config (e.g. "MaliciousConfidence/High") when both are lowered and space-stripped.
        config_key = config_label.lower().replace(" ", "")
        assert any(
            lbl.lower().replace(" ", "") == config_key for lbl in parsed.raw
        ), f"Expected space-insensitive match for '{config_label}' in parsed.raw={parsed.raw}"


class TestParseCrowdstrikeLabelsStructure:
    """Confidence labels stay in raw; MITRE/malware are promoted."""

    def test_raw_contains_confidence_labels(self):
        labels = [
            "MaliciousConfidence/High",
            "mitre attck/command and control/DataObfuscation",
            "malware/MofkSys",
        ]
        parsed = parse_crowdstrike_labels(labels)

        # Confidence label preserved in raw (normalized form)
        assert any("confidence" in lbl.lower() for lbl in parsed.raw)

        # MITRE and malware labels are promoted (not in raw)
        assert not any("mitre" in lbl.lower() for lbl in parsed.raw)
        assert not any("malware/" in lbl.lower() for lbl in parsed.raw)

        # Technique correctly extracted with CamelCase split
        assert "Data Obfuscation" in parsed.attack_patterns

        # Malware family correctly extracted (CamelCase normalized)
        assert "Mofk Sys" in parsed.malware_families


class TestDetermineScoreByLabels:
    """Test that _determine_score_by_labels assigns the correct score."""

    @staticmethod
    def _make_builder(**overrides):
        """Create a minimal mock builder with score config attributes."""
        from unittest.mock import MagicMock

        builder = MagicMock()
        builder.default_x_opencti_score = overrides.get("default", 50)
        builder.indicator_low_score = overrides.get("low_score", 40)
        builder.indicator_low_score_labels = overrides.get(
            "low_labels", ["MaliciousConfidence/Low"]
        )
        builder.indicator_medium_score = overrides.get("medium_score", 60)
        builder.indicator_medium_score_labels = overrides.get(
            "medium_labels", ["MaliciousConfidence/Medium"]
        )
        builder.indicator_high_score = overrides.get("high_score", 80)
        builder.indicator_high_score_labels = overrides.get(
            "high_labels", ["MaliciousConfidence/High"]
        )
        return builder

    def _call(self, builder, labels):
        from crowdstrike_feeds_connector.indicator.builder import (
            IndicatorBundleBuilder,
        )

        return IndicatorBundleBuilder._determine_score_by_labels(builder, labels)

    def test_high_score_applied(self):
        """Label 'Malicious Confidence/High' (normalized) matches config 'MaliciousConfidence/High'."""
        builder = self._make_builder()
        score = self._call(builder, ["Malicious Confidence/High"])
        assert score == 80

    def test_medium_score_applied(self):
        builder = self._make_builder()
        score = self._call(builder, ["Malicious Confidence/Medium"])
        assert score == 60

    def test_low_score_applied(self):
        builder = self._make_builder()
        score = self._call(builder, ["Malicious Confidence/Low"])
        assert score == 40

    def test_fallback_when_no_match(self):
        builder = self._make_builder()
        score = self._call(builder, ["SomeUnrelatedLabel"])
        assert score == 50

    def test_lowest_score_wins(self):
        """When both high and low labels are present, low wins (floor logic)."""
        builder = self._make_builder()
        score = self._call(
            builder, ["Malicious Confidence/High", "Malicious Confidence/Low"]
        )
        assert score == 40

    def test_medium_beats_high(self):
        """When both high and medium labels are present, medium wins."""
        builder = self._make_builder()
        score = self._call(
            builder, ["Malicious Confidence/High", "Malicious Confidence/Medium"]
        )
        assert score == 60

    def test_raw_camelcase_config_matches_normalized_label(self):
        """Config value without spaces matches normalized label with spaces."""
        builder = self._make_builder(high_labels=["MaliciousConfidence/High"])
        score = self._call(builder, ["Malicious Confidence/High"])
        assert score == 80

    def test_config_with_spaces_matches_raw_label(self):
        """Config value with spaces also matches raw label without spaces."""
        builder = self._make_builder(high_labels=["Malicious Confidence/High"])
        score = self._call(builder, ["MaliciousConfidence/High"])
        assert score == 80


class TestEndToEndScoreFromRawLabel:
    """End-to-end: raw API label → parse → score determination."""

    @pytest.mark.parametrize(
        "raw_api_labels,config_label,expected_score",
        [
            (
                ["MaliciousConfidence/High"],
                "MaliciousConfidence/High",
                80,
            ),
            (
                ["MaliciousConfidence/Medium"],
                "MaliciousConfidence/Medium",
                60,
            ),
            (
                ["MaliciousConfidence/Low"],
                "MaliciousConfidence/Low",
                40,
            ),
            (
                ["MaliciousConfidence/High", "mitre attck/execution/DataObfuscation"],
                "MaliciousConfidence/High",
                80,
            ),
        ],
    )
    def test_raw_label_produces_correct_score(
        self, raw_api_labels, config_label, expected_score
    ):
        """Simulate the full pipeline: raw labels from API → parsed → score."""
        from unittest.mock import MagicMock

        from crowdstrike_feeds_connector.indicator.builder import (
            IndicatorBundleBuilder,
        )

        # Step 1: Parse labels as the importer does
        parsed = parse_crowdstrike_labels(raw_api_labels)
        label_names = parsed.raw  # This is what gets set as indicator["label_names"]

        # Step 2: Build a mock builder with default config
        builder = MagicMock()
        builder.default_x_opencti_score = 50
        builder.indicator_low_score = 40
        builder.indicator_low_score_labels = ["MaliciousConfidence/Low"]
        builder.indicator_medium_score = 60
        builder.indicator_medium_score_labels = ["MaliciousConfidence/Medium"]
        builder.indicator_high_score = 80
        builder.indicator_high_score_labels = ["MaliciousConfidence/High"]

        # Step 3: Determine score (as builder._get_labels() would return label_names)
        score = IndicatorBundleBuilder._determine_score_by_labels(builder, label_names)

        assert score == expected_score, (
            f"Raw labels {raw_api_labels} → parsed.raw={label_names} → "
            f"score={score}, expected {expected_score}"
        )

    def test_fallback_score_when_no_confidence_label(self):
        """Labels without confidence info fall back to default score."""
        from unittest.mock import MagicMock

        from crowdstrike_feeds_connector.indicator.builder import (
            IndicatorBundleBuilder,
        )

        parsed = parse_crowdstrike_labels(
            ["mitre attck/execution/CommandLineInterface", "actor/SaltySPIDER"]
        )

        builder = MagicMock()
        builder.default_x_opencti_score = 50
        builder.indicator_low_score = 40
        builder.indicator_low_score_labels = ["MaliciousConfidence/Low"]
        builder.indicator_medium_score = 60
        builder.indicator_medium_score_labels = ["MaliciousConfidence/Medium"]
        builder.indicator_high_score = 80
        builder.indicator_high_score_labels = ["MaliciousConfidence/High"]

        score = IndicatorBundleBuilder._determine_score_by_labels(builder, parsed.raw)
        assert score == 50
