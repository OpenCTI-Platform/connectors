"""Unit tests for ConverterToStix."""

import stix2
from lab539_aitm_connector.converter_to_stix import ConverterToStix


class TestConverterToStix:
    """Tests for ConverterToStix."""

    def test_record_to_stix_returns_author_and_indicator(
        self, mock_helper, sample_record
    ):
        """Should return author identity and indicator."""
        converter = ConverterToStix(helper=mock_helper, tlp_level="amber")
        objects = converter.record_to_stix(sample_record)

        types = [obj.type for obj in objects]
        assert "identity" in types
        assert "indicator" in types

    def test_indicator_has_correct_pattern(self, mock_helper, sample_record):
        """Indicator pattern should include IP and domain."""
        converter = ConverterToStix(helper=mock_helper, tlp_level="amber")
        objects = converter.record_to_stix(sample_record)

        indicator = next(obj for obj in objects if obj.type == "indicator")
        assert sample_record["ip"] in indicator.pattern
        assert sample_record["domain"] in indicator.pattern

    def test_indicator_has_correct_confidence(self, mock_helper, sample_record):
        """Medium confidence should map to score 60."""
        converter = ConverterToStix(helper=mock_helper, tlp_level="amber")
        objects = converter.record_to_stix(sample_record)

        indicator = next(obj for obj in objects if obj.type == "indicator")
        assert indicator.confidence == 60

    def test_indicator_id_is_deterministic(self, mock_helper, sample_record):
        """Same record should always produce the same indicator ID."""
        converter = ConverterToStix(helper=mock_helper, tlp_level="amber")
        objects1 = converter.record_to_stix(sample_record)
        objects2 = converter.record_to_stix(sample_record)

        id1 = next(obj.id for obj in objects1 if obj.type == "indicator")
        id2 = next(obj.id for obj in objects2 if obj.type == "indicator")
        assert id1 == id2

    def test_ipv6_address_detected(self, mock_helper, sample_record):
        """IPv6 addresses should use ipv6-addr type in pattern."""
        sample_record["ip"] = "2606:4700:3033::ac43:9294"
        converter = ConverterToStix(helper=mock_helper, tlp_level="amber")
        objects = converter.record_to_stix(sample_record)

        indicator = next(obj for obj in objects if obj.type == "indicator")
        assert "ipv6-addr" in indicator.pattern

    def test_records_to_bundle_deduplicates(self, mock_helper, sample_record):
        """Duplicate records should produce deduplicated bundle objects."""
        converter = ConverterToStix(helper=mock_helper, tlp_level="amber")
        bundle = converter.records_to_bundle([sample_record, sample_record])

        ids = [obj.id for obj in bundle.objects]
        assert len(ids) == len(set(ids))

    def test_tlp_amber_marking_applied(self, mock_helper, sample_record):
        """All objects should have TLP:AMBER marking."""
        converter = ConverterToStix(helper=mock_helper, tlp_level="amber")
        objects = converter.record_to_stix(sample_record)

        indicator = next(obj for obj in objects if obj.type == "indicator")
        assert stix2.TLP_AMBER.id in indicator.object_marking_refs
