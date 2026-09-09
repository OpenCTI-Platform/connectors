"""VirusTotal connector unit tests."""

import unittest
from unittest.mock import MagicMock, PropertyMock

import stix2
from pycti import Identity
from virustotal.processors.ip_address import IPProcessor
from virustotal.virustotal import VirusTotalConnector


def _make_connector() -> VirusTotalConnector:
    """Build a VirusTotalConnector with all external dependencies mocked."""
    config = MagicMock()
    config.virustotal.max_tlp = "TLP:AMBER"
    config.virustotal.replace_with_lower_score = True
    config.virustotal.file_create_note_full_report = True
    config.virustotal.file_import_yara = True
    config.virustotal.file_upload_unseen_artifacts = False
    config.virustotal.ip_add_relationships = False
    config.virustotal.domain_add_relationships = False
    config.virustotal.url_upload_unseen = False
    config.virustotal.include_attributes_in_note = False
    # Default to True here so the existing per-relationship gti_include_*
    # tests below don't need to also flip the master flag on; a dedicated
    # test covers the master-flag-off behavior explicitly.
    config.virustotal.gti_enrichment_enabled = True
    config.virustotal.gti_include_malware_families = False
    config.virustotal.gti_include_threat_actors = False
    config.virustotal.gti_include_campaigns = False
    config.virustotal.gti_include_reports = False
    config.virustotal.gti_relationship_limit = 10
    config.virustotal.token.get_secret_value.return_value = "fake-token"
    config.virustotal.model_extra.get.return_value = MagicMock(
        threshold=10, valid_minutes=2880, detect=True
    )

    helper = MagicMock()
    confidence_level = PropertyMock(return_value=50)
    type(helper).connect_confidence_level = confidence_level
    helper.connect_confidence_level = 50
    helper.opencti_url = "http://localhost"

    connector = VirusTotalConnector.__new__(VirusTotalConnector)
    connector.config = config
    connector.helper = helper
    connector.max_tlp = config.virustotal.max_tlp
    connector.replace_with_lower_score = config.virustotal.replace_with_lower_score
    connector.file_create_note_full_report = (
        config.virustotal.file_create_note_full_report
    )
    connector.file_import_yara = config.virustotal.file_import_yara
    connector.file_upload_unseen_artifacts = (
        config.virustotal.file_upload_unseen_artifacts
    )
    connector.ip_add_relationships = config.virustotal.ip_add_relationships
    connector.domain_add_relationships = config.virustotal.domain_add_relationships
    connector.url_upload_unseen = config.virustotal.url_upload_unseen
    connector.include_attributes_in_note = config.virustotal.include_attributes_in_note
    connector.gti_enrichment_enabled = config.virustotal.gti_enrichment_enabled
    connector.gti_include_malware_families = (
        config.virustotal.gti_include_malware_families
    )
    connector.gti_include_threat_actors = config.virustotal.gti_include_threat_actors
    connector.gti_include_campaigns = config.virustotal.gti_include_campaigns
    connector.gti_include_reports = config.virustotal.gti_include_reports
    connector.gti_relationship_limit = config.virustotal.gti_relationship_limit
    connector.file_indicator_config = MagicMock(
        threshold=10, valid_minutes=2880, detect=True
    )
    connector.ip_indicator_config = MagicMock(
        threshold=10, valid_minutes=2880, detect=True
    )
    connector.domain_indicator_config = MagicMock(
        threshold=10, valid_minutes=2880, detect=True
    )
    connector.url_indicator_config = MagicMock(
        threshold=10, valid_minutes=2880, detect=True
    )
    connector.yara_cache = {}
    connector.author = stix2.Identity(
        id=Identity.generate_id("VirusTotal", "organization"),
        name="VirusTotal",
        identity_class="organization",
    )
    connector.client = MagicMock()
    return connector


class TestExtractObservableFromIndicator(unittest.TestCase):
    """Tests for _extract_observable_from_indicator."""

    def setUp(self):
        self.connector = _make_connector()

    def _indicator_entity(self, observable_values):
        """Build a minimal indicator opencti_entity with x_opencti_observable_values."""
        entity = {
            "entity_type": "Indicator",
            "name": "test-indicator",
            "objectMarking": [],
        }
        # Simulate what helper.get_attribute_in_extension returns.
        self.connector.helper.get_attribute_in_extension.return_value = (
            observable_values
        )
        return entity

    def test_extracts_ipv4(self):
        entity = self._indicator_entity([{"type": "IPv4-Addr", "value": "1.2.3.4"}])
        results = self.connector._extract_observable_from_indicator(entity)
        self.assertEqual(results, [("IPv4-Addr", "1.2.3.4")])

    def test_extracts_domain(self):
        entity = self._indicator_entity(
            [{"type": "Domain-Name", "value": "evil.example.com"}]
        )
        results = self.connector._extract_observable_from_indicator(entity)
        self.assertEqual(results, [("Domain-Name", "evil.example.com")])

    def test_extracts_hostname(self):
        entity = self._indicator_entity(
            [{"type": "Hostname", "value": "mail.evil.example.com"}]
        )
        results = self.connector._extract_observable_from_indicator(entity)
        self.assertEqual(results, [("Hostname", "mail.evil.example.com")])

    def test_extracts_url(self):
        entity = self._indicator_entity(
            [{"type": "Url", "value": "https://evil.example.com/payload"}]
        )
        results = self.connector._extract_observable_from_indicator(entity)
        self.assertEqual(results, [("Url", "https://evil.example.com/payload")])

    def test_extracts_stixfile(self):
        sha256 = "a" * 64
        entity = self._indicator_entity([{"type": "StixFile", "value": sha256}])
        results = self.connector._extract_observable_from_indicator(entity)
        self.assertEqual(results, [("StixFile", sha256)])

    def test_extracts_stixfile_prefers_sha256_from_hashes(self):
        """For StixFile, SHA-256 from hashes list should be preferred over value."""
        sha256 = "b" * 64
        md5 = "c" * 32
        entity = self._indicator_entity(
            [
                {
                    "type": "StixFile",
                    "value": md5,
                    "hashes": [
                        {"algorithm": "MD5", "hash": md5},
                        {"algorithm": "SHA-256", "hash": sha256},
                    ],
                }
            ]
        )
        results = self.connector._extract_observable_from_indicator(entity)
        self.assertEqual(results, [("StixFile", sha256)])

    def test_extracts_stixfile_falls_back_to_value_when_no_hashes(self):
        """For StixFile, falls back to value when hashes list is empty."""
        sha256 = "d" * 64
        entity = self._indicator_entity(
            [{"type": "StixFile", "value": sha256, "hashes": []}]
        )
        results = self.connector._extract_observable_from_indicator(entity)
        self.assertEqual(results, [("StixFile", sha256)])

    def test_extracts_all_supported_from_compound_indicator(self):
        """Compound indicators yield one (entity_type, value) pair per observable."""
        entity = self._indicator_entity(
            [
                {"type": "IPv4-Addr", "value": "1.2.3.4"},
                {"type": "Domain-Name", "value": "evil.example.com"},
            ]
        )
        results = self.connector._extract_observable_from_indicator(entity)
        self.assertEqual(
            results,
            [("IPv4-Addr", "1.2.3.4"), ("Domain-Name", "evil.example.com")],
        )

    def test_raises_when_no_observable_values(self):
        self.connector.helper.get_attribute_in_extension.return_value = None
        entity = {"entity_type": "Indicator", "name": "x", "objectMarking": []}
        with self.assertRaises(ValueError) as ctx:
            self.connector._extract_observable_from_indicator(entity)
        self.assertIn("no observable values found", str(ctx.exception))

    def test_raises_when_unsupported_type(self):
        entity = self._indicator_entity([{"type": "IPv6-Addr", "value": "::1"}])
        with self.assertRaises(ValueError) as ctx:
            self.connector._extract_observable_from_indicator(entity)
        self.assertIn("are supported", str(ctx.exception))

    def test_skips_unsupported_type_and_returns_supported(self):
        """Unsupported types are silently skipped; supported ones are still returned."""
        entity = self._indicator_entity(
            [
                {"type": "IPv6-Addr", "value": "::1"},
                {"type": "IPv4-Addr", "value": "1.2.3.4"},
            ]
        )
        results = self.connector._extract_observable_from_indicator(entity)
        self.assertEqual(results, [("IPv4-Addr", "1.2.3.4")])


class TestEnrichGtiRelationships(unittest.TestCase):
    """Tests for EntityProcessor._enrich_gti_relationships, via IPProcessor."""

    def setUp(self):
        self.connector = _make_connector()

    def _make_processor(self) -> IPProcessor:
        opencti_entity = {"entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"}
        return IPProcessor(self.connector, [], {"id": "x"}, opencti_entity, False)

    def test_all_flags_off_skips_client_entirely(self):
        processor = self._make_processor()
        builder = MagicMock()
        processor._enrich_gti_relationships(builder)
        self.connector.client.get_gti_relationship.assert_not_called()
        builder.create_malware_family.assert_not_called()
        builder.create_intrusion_set.assert_not_called()
        builder.create_campaign.assert_not_called()
        builder.create_report.assert_not_called()

    def test_enabled_flag_calls_client_with_expected_args_and_dispatches_items(self):
        self.connector.gti_include_malware_families = True
        self.connector.gti_relationship_limit = 5
        self.connector.client.get_gti_relationship.return_value = {
            "data": [{"id": "a"}, {"id": "b"}]
        }
        processor = self._make_processor()
        builder = MagicMock()
        processor._enrich_gti_relationships(builder)

        self.connector.client.get_gti_relationship.assert_called_once_with(
            "ip_addresses", "1.2.3.4", "malware_families", 5
        )
        self.assertEqual(builder.create_malware_family.call_count, 2)
        builder.create_intrusion_set.assert_not_called()

    def test_only_enabled_relationships_are_fetched(self):
        self.connector.gti_include_threat_actors = True
        self.connector.gti_include_reports = True
        self.connector.client.get_gti_relationship.return_value = {"data": []}
        processor = self._make_processor()
        builder = MagicMock()
        processor._enrich_gti_relationships(builder)

        called_relationships = {
            call.args[2]
            for call in self.connector.client.get_gti_relationship.call_args_list
        }
        self.assertEqual(called_relationships, {"threat_actors", "reports"})

    def test_empty_response_does_not_crash(self):
        self.connector.gti_include_campaigns = True
        self.connector.client.get_gti_relationship.return_value = None
        processor = self._make_processor()
        builder = MagicMock()
        processor._enrich_gti_relationships(builder)  # should not raise
        builder.create_campaign.assert_not_called()

    def test_master_flag_off_skips_everything_even_with_sub_flags_on(self):
        """gti_enrichment_enabled=False must disable all GTI relationship
        fetching regardless of the individual gti_include_* flags."""
        self.connector.gti_enrichment_enabled = False
        self.connector.gti_include_malware_families = True
        self.connector.gti_include_threat_actors = True
        self.connector.gti_include_campaigns = True
        self.connector.gti_include_reports = True
        processor = self._make_processor()
        builder = MagicMock()
        processor._enrich_gti_relationships(builder)
        self.connector.client.get_gti_relationship.assert_not_called()
        builder.create_malware_family.assert_not_called()
        builder.create_intrusion_set.assert_not_called()
        builder.create_campaign.assert_not_called()
        builder.create_report.assert_not_called()
