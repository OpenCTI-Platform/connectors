"""Unit tests for group-level enrichment: leak sites, aliases, ext refs, and TTPs."""

from unittest.mock import MagicMock, patch

import pytest
import stix2
from ransomwarelive.converter_to_stix import ConverterToStix
from ransomwarelive.utils import get_group_entry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GROUP_DATA = [
    {
        "name": "acme-ransomware",
        "description": "ACME ransomware group",
        "altname": "AcmeRW",
        "url": "https://www.ransomware.live/group/acme-ransomware",
        "type": {"raas": True},
        "lineage": None,
        "locations": [
            {
                "fqdn": "acmeabcdef1234567890.onion",
                "slug": "http://acmeabcdef1234567890.onion",
                "title": "ACME Leaks",
                "type": "DLS",
                "available": False,
                "enabled": False,
            },
            {
                "fqdn": "acme-mirror.onion",
                "slug": "http://acme-mirror.onion",
                "title": "ACME Mirror",
                "type": "DLS",
                "available": False,
                "enabled": False,
            },
        ],
        "ttps": [
            {
                "tactic_id": "TA0001",
                "tactic_name": "Initial Access",
                "techniques": [
                    {
                        "technique_id": "T1190",
                        "technique_name": "Exploit Public-Facing Application",
                        "technique_details": "...",
                    }
                ],
            }
        ],
        "tools": [],
        "profile": [],
        "meta": None,
    },
    {
        "name": "no-extras",
        "description": "Group with no locations or altname",
        "altname": None,
        "url": "https://www.ransomware.live/group/no-extras",
        "type": {"raas": False},
        "lineage": None,
        "locations": [],
        "ttps": [],
        "tools": [],
        "profile": [],
        "meta": None,
    },
]


@pytest.fixture()
def converter():
    return ConverterToStix("TLP:CLEAR")


@pytest.fixture()
def intrusion_set(converter):
    return converter.create_intrusionset(
        name="acme-ransomware",
        intrusion_description="ACME ransomware group",
    )


# ---------------------------------------------------------------------------
# utils.get_group_entry
# ---------------------------------------------------------------------------


class TestGetGroupEntry:
    def test_returns_matching_entry(self):
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        assert entry is not None
        assert entry["name"] == "acme-ransomware"

    def test_returns_none_for_unknown_group(self):
        assert get_group_entry("unknown-group", GROUP_DATA) is None

    def test_returns_none_for_empty_list(self):
        assert get_group_entry("acme-ransomware", []) is None


# ---------------------------------------------------------------------------
# ConverterToStix._extract_group_aliases
# ---------------------------------------------------------------------------


class TestExtractGroupAliases:
    def test_returns_list_when_altname_present(self, converter):
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        aliases = converter._extract_group_aliases(entry)
        assert aliases == ["AcmeRW"]

    def test_returns_none_when_altname_is_null(self, converter):
        entry = get_group_entry("no-extras", GROUP_DATA)
        assert converter._extract_group_aliases(entry) is None

    def test_returns_none_when_entry_is_none(self, converter):
        assert converter._extract_group_aliases(None) is None

    def test_returns_none_when_altname_is_whitespace(self, converter):
        entry = {"name": "x", "altname": "   "}
        assert converter._extract_group_aliases(entry) is None


# ---------------------------------------------------------------------------
# ConverterToStix._extract_group_aliases_and_refs
# ---------------------------------------------------------------------------


class TestExtractGroupAliasesAndRefs:
    def test_extracts_group_url_as_external_reference(self, converter):
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        _, ext_refs = converter._extract_group_aliases_and_refs(entry)
        assert ext_refs is not None
        urls = [r.get("url") for r in ext_refs]
        assert "https://www.ransomware.live/group/acme-ransomware" in urls

    def test_extracts_slug_urls_as_external_references(self):
        # Leak-site slug URLs are opt-in (create_leak_site_domains defaults to
        # False), so this test constructs a converter that explicitly enables it.
        converter = ConverterToStix("TLP:CLEAR", create_leak_site_domains=True)
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        _, ext_refs = converter._extract_group_aliases_and_refs(entry)
        urls = [r.get("url") for r in ext_refs]
        assert "http://acmeabcdef1234567890.onion" in urls
        assert "http://acme-mirror.onion" in urls

    def test_returns_none_refs_when_no_url_and_no_locations(self, converter):
        entry = {"name": "bare", "altname": None, "url": None, "locations": []}
        _, ext_refs = converter._extract_group_aliases_and_refs(entry)
        assert ext_refs is None

    def test_returns_none_when_entry_is_none(self, converter):
        aliases, ext_refs = converter._extract_group_aliases_and_refs(None)
        assert aliases is None
        assert ext_refs is None

    def test_deduplicates_refs_when_slug_matches_group_url(self):
        # Slug refs are only emitted when leak-site enrichment is enabled, so
        # the dedup against the group URL is exercised with it explicitly on.
        converter = ConverterToStix("TLP:CLEAR", create_leak_site_domains=True)
        entry = {
            "name": "dup-group",
            "altname": None,
            "url": "http://dupsite.onion",
            "locations": [
                {
                    "fqdn": "dupsite.onion",
                    "slug": "http://dupsite.onion",
                    "title": "DLS",
                },
                {
                    "fqdn": "dupsite.onion",
                    "slug": "http://dupsite.onion",
                    "title": "Mirror",
                },
            ],
        }
        _, ext_refs = converter._extract_group_aliases_and_refs(entry)
        urls = [r.get("url") for r in ext_refs]
        assert urls.count("http://dupsite.onion") == 1

    def test_slug_urls_omitted_when_create_leak_site_domains_false(self):
        c = ConverterToStix("TLP:CLEAR", create_leak_site_domains=False)
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        _, ext_refs = c._extract_group_aliases_and_refs(entry)
        urls = [r.get("url") for r in ext_refs]
        assert "http://acmeabcdef1234567890.onion" not in urls
        assert "https://www.ransomware.live/group/acme-ransomware" in urls

    def test_slug_urls_omitted_by_default(self, converter):
        # create_leak_site_domains defaults to False (fail closed), so the
        # default converter must not emit leak-site slug URLs.
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        _, ext_refs = converter._extract_group_aliases_and_refs(entry)
        urls = [r.get("url") for r in ext_refs]
        assert "http://acmeabcdef1234567890.onion" not in urls
        assert "https://www.ransomware.live/group/acme-ransomware" in urls


# ---------------------------------------------------------------------------
# ConverterToStix.create_intrusionset — aliases and external_references
# ---------------------------------------------------------------------------


class TestCreateIntrusionsetEnrichment:
    def test_aliases_attached_when_provided(self, converter):
        is_obj = converter.create_intrusionset(
            name="acme-ransomware",
            intrusion_description="desc",
            aliases=["AcmeRW"],
        )
        assert is_obj.get("aliases") == ["AcmeRW"]

    def test_external_references_attached_when_provided(self, converter):
        ref = converter.create_external_reference(
            url="https://www.ransomware.live/group/acme-ransomware",
            description="group page",
        )
        is_obj = converter.create_intrusionset(
            name="acme-ransomware",
            intrusion_description="desc",
            external_references=[ref],
        )
        urls = [r.get("url") for r in is_obj.get("external_references", [])]
        assert "https://www.ransomware.live/group/acme-ransomware" in urls

    def test_no_aliases_when_omitted(self, converter):
        is_obj = converter.create_intrusionset(
            name="plain-group",
            intrusion_description="desc",
        )
        assert is_obj.get("aliases") is None


# ---------------------------------------------------------------------------
# ConverterToStix.create_threat_actor — aliases
# ---------------------------------------------------------------------------


class TestCreateThreatActorAliases:
    def test_aliases_attached_when_provided(self, converter):
        ta = converter.create_threat_actor(
            threat_actor_name="acme-ransomware",
            threat_description="desc",
            aliases=["AcmeRW"],
        )
        assert ta.get("aliases") == ["AcmeRW"]

    def test_no_aliases_when_omitted(self, converter):
        ta = converter.create_threat_actor(
            threat_actor_name="plain-group",
            threat_description="desc",
        )
        assert ta.get("aliases") is None

    def test_external_references_attached_when_provided(self, converter):
        ref = stix2.ExternalReference(
            source_name="ransomware.live", url="https://ransomware.live/group/acme"
        )
        ta = converter.create_threat_actor(
            threat_actor_name="acme-ransomware",
            threat_description="desc",
            external_references=[ref],
        )
        assert ta.get("external_references") is not None
        assert any(
            "ransomware.live" in r.get("url", "") for r in ta.get("external_references")
        )

    def test_no_external_references_when_omitted(self, converter):
        ta = converter.create_threat_actor(
            threat_actor_name="plain-group",
            threat_description="desc",
        )
        assert ta.get("external_references") is None


# ---------------------------------------------------------------------------
# ConverterToStix.process_group_leak_sites
# ---------------------------------------------------------------------------


class TestProcessGroupLeakSites:
    def test_creates_domain_and_relationship_per_location(
        self, converter, intrusion_set
    ):
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        objects = converter.process_group_leak_sites(
            group_entry=entry,
            intrusion_set=intrusion_set,
        )
        domains = [o for o in objects if o.get("type") == "domain-name"]
        relations = [o for o in objects if o.get("type") == "relationship"]
        assert len(domains) == 2
        assert len(relations) == 2

    def test_domain_values_match_fqdns(self, converter, intrusion_set):
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        objects = converter.process_group_leak_sites(
            group_entry=entry,
            intrusion_set=intrusion_set,
        )
        fqdns = {o.get("value") for o in objects if o.get("type") == "domain-name"}
        assert fqdns == {"acmeabcdef1234567890.onion", "acme-mirror.onion"}

    def test_relationships_are_related_to(self, converter, intrusion_set):
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        objects = converter.process_group_leak_sites(
            group_entry=entry,
            intrusion_set=intrusion_set,
        )
        rel_types = {
            o.get("relationship_type")
            for o in objects
            if o.get("type") == "relationship"
        }
        assert rel_types == {"related-to"}

    def test_relationships_target_intrusion_set(self, converter, intrusion_set):
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        objects = converter.process_group_leak_sites(
            group_entry=entry,
            intrusion_set=intrusion_set,
        )
        targets = {
            o.get("target_ref") for o in objects if o.get("type") == "relationship"
        }
        assert targets == {intrusion_set.get("id")}

    def test_returns_empty_list_when_no_locations(self, converter, intrusion_set):
        entry = get_group_entry("no-extras", GROUP_DATA)
        objects = converter.process_group_leak_sites(
            group_entry=entry,
            intrusion_set=intrusion_set,
        )
        assert objects == []

    def test_skips_location_with_empty_fqdn(self, converter, intrusion_set):
        entry = {
            "name": "x",
            "locations": [{"fqdn": "", "slug": "http://x.onion", "title": "X"}],
        }
        objects = converter.process_group_leak_sites(
            group_entry=entry,
            intrusion_set=intrusion_set,
        )
        assert objects == []


# ---------------------------------------------------------------------------
# RansomwareAPIConnector.attack_pattern_fetcher
# ---------------------------------------------------------------------------


class TestAttackPatternFetcher:
    def _make_connector(self):
        """Build a minimal connector with mocked helper and config."""
        from ransomwarelive.ransom_conn import RansomwareAPIConnector

        mock_helper = MagicMock()
        mock_config = MagicMock()
        mock_config.connector.create_threat_actor = False
        mock_config.connector.duration_period = "PT5M"

        with patch("ransomwarelive.ransom_conn.RansomwareAPIClient"):
            connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
            connector.helper = mock_helper
            connector.config = mock_config
            connector.converter_to_stix = ConverterToStix("TLP:CLEAR")
            connector.author = connector.converter_to_stix.author
            connector.processed_groups = set()
        return connector

    def test_returns_stix_id_when_found(self):
        connector = self._make_connector()
        stix_id = "attack-pattern--aabbccdd-1234-5678-abcd-aabbccddeeff"
        connector.helper.api.attack_pattern.read.return_value = {"standard_id": stix_id}

        result = connector.attack_pattern_fetcher("T1190")

        connector.helper.api.attack_pattern.read.assert_called_once()
        assert result == stix_id

    def test_returns_none_when_technique_not_found(self):
        connector = self._make_connector()
        connector.helper.api.attack_pattern.read.return_value = None

        result = connector.attack_pattern_fetcher("T9999")

        assert result is None

    def test_returns_none_and_logs_on_exception(self):
        connector = self._make_connector()
        connector.helper.api.attack_pattern.read.side_effect = RuntimeError("API down")

        result = connector.attack_pattern_fetcher("T1190")

        assert result is None
        connector.helper.connector_logger.error.assert_called_once()


# ---------------------------------------------------------------------------
# RansomwareAPIConnector.process_group_ttps
# ---------------------------------------------------------------------------


class TestProcessGroupTtps:
    def _make_connector(self):
        from ransomwarelive.ransom_conn import RansomwareAPIConnector

        mock_helper = MagicMock()
        mock_config = MagicMock()
        mock_config.connector.create_threat_actor = False

        connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
        connector.helper = mock_helper
        connector.config = mock_config
        connector.converter_to_stix = ConverterToStix("TLP:CLEAR")
        connector.author = connector.converter_to_stix.author
        connector.processed_groups = set()
        return connector

    def _make_intrusion_set(self, connector):
        return connector.converter_to_stix.create_intrusionset(
            name="acme-ransomware", intrusion_description="desc"
        )

    def test_creates_uses_relationships_for_found_techniques(self):
        connector = self._make_connector()
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        intrusion_set = self._make_intrusion_set(connector)

        from pycti import AttackPattern as PyctiAttackPattern

        fake_ap_id = str(PyctiAttackPattern.generate_id("T1190", "T1190"))
        connector.attack_pattern_fetcher = MagicMock(return_value=fake_ap_id)

        objects = connector.process_group_ttps(
            group_entry=entry,
            intrusion_set=intrusion_set,
        )

        connector.attack_pattern_fetcher.assert_called_once_with("T1190")
        # only the relationship — attack pattern already exists in OpenCTI
        assert len(objects) == 1
        rel = objects[0]
        assert rel.get("relationship_type") == "uses"
        assert rel.get("target_ref") == fake_ap_id

    def test_skips_techniques_not_in_opencti(self):
        connector = self._make_connector()
        entry = get_group_entry("acme-ransomware", GROUP_DATA)
        intrusion_set = self._make_intrusion_set(connector)

        connector.attack_pattern_fetcher = MagicMock(return_value=None)

        objects = connector.process_group_ttps(
            group_entry=entry,
            intrusion_set=intrusion_set,
        )

        assert objects == []

    def test_returns_empty_list_for_group_with_no_ttps(self):
        connector = self._make_connector()
        entry = get_group_entry("no-extras", GROUP_DATA)
        intrusion_set = self._make_intrusion_set(connector)

        objects = connector.process_group_ttps(
            group_entry=entry,
            intrusion_set=intrusion_set,
        )

        assert objects == []


# ---------------------------------------------------------------------------
# RansomwareAPIConnector._collect_group_enrichment_objects — deduplication
# ---------------------------------------------------------------------------


class TestCollectGroupEnrichmentObjects:
    def _make_connector(self):
        from ransomwarelive.ransom_conn import RansomwareAPIConnector

        connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
        connector.helper = MagicMock()
        connector.config = MagicMock()
        connector.converter_to_stix = ConverterToStix("TLP:CLEAR")
        connector.author = connector.converter_to_stix.author
        connector.processed_groups = set()
        connector.process_group_ttps = MagicMock(return_value=[])
        connector.converter_to_stix.process_group_leak_sites = MagicMock(
            return_value=[]
        )
        return connector

    def _make_intrusion_set(self, connector):
        return connector.converter_to_stix.create_intrusionset(
            name="acme-ransomware", intrusion_description="desc"
        )

    def test_group_added_to_processed_after_first_call(self):
        connector = self._make_connector()
        intrusion_set = self._make_intrusion_set(connector)

        connector._collect_group_enrichment_objects(
            group_name="acme-ransomware",
            group_data=GROUP_DATA,
            intrusion_set=intrusion_set,
        )

        assert "acme-ransomware" in connector.processed_groups

    def test_returns_empty_list_on_second_call_for_same_group(self):
        connector = self._make_connector()
        intrusion_set = self._make_intrusion_set(connector)

        connector._collect_group_enrichment_objects(
            group_name="acme-ransomware",
            group_data=GROUP_DATA,
            intrusion_set=intrusion_set,
        )
        result = connector._collect_group_enrichment_objects(
            group_name="acme-ransomware",
            group_data=GROUP_DATA,
            intrusion_set=intrusion_set,
        )

        assert result == []

    def test_enrichment_called_only_once_for_same_group(self):
        connector = self._make_connector()
        leak_mock = connector.converter_to_stix.process_group_leak_sites
        intrusion_set = self._make_intrusion_set(connector)

        connector._collect_group_enrichment_objects(
            group_name="acme-ransomware",
            group_data=GROUP_DATA,
            intrusion_set=intrusion_set,
        )
        connector._collect_group_enrichment_objects(
            group_name="acme-ransomware",
            group_data=GROUP_DATA,
            intrusion_set=intrusion_set,
        )

        assert leak_mock.call_count == 1

    def test_returns_empty_for_unknown_group(self):
        connector = self._make_connector()
        intrusion_set = self._make_intrusion_set(connector)

        result = connector._collect_group_enrichment_objects(
            group_name="unknown-group",
            group_data=GROUP_DATA,
            intrusion_set=intrusion_set,
        )

        assert result == []
        connector.converter_to_stix.process_group_leak_sites.assert_not_called()

    def test_leak_site_domains_skipped_when_disabled(self):
        connector = self._make_connector()
        connector.config.connector.create_leak_site_domains = False
        intrusion_set = self._make_intrusion_set(connector)

        connector._collect_group_enrichment_objects(
            group_name="acme-ransomware",
            group_data=GROUP_DATA,
            intrusion_set=intrusion_set,
        )

        connector.converter_to_stix.process_group_leak_sites.assert_not_called()

    def test_leak_site_domains_called_when_enabled(self):
        connector = self._make_connector()
        connector.config.connector.create_leak_site_domains = True
        intrusion_set = self._make_intrusion_set(connector)

        connector._collect_group_enrichment_objects(
            group_name="acme-ransomware",
            group_data=GROUP_DATA,
            intrusion_set=intrusion_set,
        )

        connector.converter_to_stix.process_group_leak_sites.assert_called_once()


# ---------------------------------------------------------------------------
# ConverterToStix.process_external_references — create_leak_post_refs toggle
# ---------------------------------------------------------------------------


class TestProcessExternalReferencesToggle:
    def test_post_url_included_when_enabled(self):
        converter = ConverterToStix("TLP:CLEAR")
        item = {
            "website": "https://www.ransomware.live/id/abc",
            "screenshot": "https://images.ransomware.live/victims/abc.png",
            "post_url": "http://darkweb.onion/victim/abc",
        }
        refs = converter.process_external_references(item, create_leak_post_refs=True)
        urls = [r.get("url") for r in refs]
        assert "http://darkweb.onion/victim/abc" in urls

    def test_post_url_excluded_when_disabled(self):
        converter = ConverterToStix("TLP:CLEAR")
        item = {
            "website": "https://www.ransomware.live/id/abc",
            "screenshot": "https://images.ransomware.live/victims/abc.png",
            "post_url": "http://darkweb.onion/victim/abc",
        }
        refs = converter.process_external_references(item, create_leak_post_refs=False)
        urls = [r.get("url") for r in refs]
        assert "http://darkweb.onion/victim/abc" not in urls
        assert "https://www.ransomware.live/id/abc" in urls
        assert "https://images.ransomware.live/victims/abc.png" in urls

    def test_post_url_excluded_by_default(self):
        # create_leak_post_refs defaults to False (fail closed), so the direct
        # leak-post URL must not be emitted unless explicitly enabled.
        converter = ConverterToStix("TLP:CLEAR")
        item = {
            "website": "https://www.ransomware.live/id/abc",
            "screenshot": "https://images.ransomware.live/victims/abc.png",
            "post_url": "http://darkweb.onion/victim/abc",
        }
        refs = converter.process_external_references(item)
        urls = [r.get("url") for r in refs]
        assert "http://darkweb.onion/victim/abc" not in urls
        assert "https://www.ransomware.live/id/abc" in urls
        assert "https://images.ransomware.live/victims/abc.png" in urls


# ---------------------------------------------------------------------------
# Per-run reset of processed_groups across reused connector instances
# ---------------------------------------------------------------------------


class TestProcessedGroupsResetPerRun:
    """``schedule_iso`` reuses the connector instance across runs, so each
    collection sweep must start with an empty ``processed_groups`` set."""

    def _make_connector(self):
        from ransomwarelive.ransom_conn import RansomwareAPIConnector

        connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
        connector.helper = MagicMock()
        connector.config = MagicMock()
        connector.api_client = MagicMock()
        # Empty /groups payload makes both collectors return early right after
        # the reset, isolating the dedup-guard reset from the rest of the run.
        connector.api_client.get_feed.return_value = []
        connector.last_run = None
        # Simulate a group enriched on a previous run still being tracked.
        connector.processed_groups = {"acme-ransomware"}
        return connector

    def test_collect_intelligence_resets_processed_groups(self):
        connector = self._make_connector()

        connector.collect_intelligence()

        assert connector.processed_groups == set()

    def test_collect_historic_intelligence_resets_processed_groups(self):
        connector = self._make_connector()

        connector.collect_historic_intelligence()

        assert connector.processed_groups == set()
