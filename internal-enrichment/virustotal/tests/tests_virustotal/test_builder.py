"""Virustotal builder unittest."""

import datetime
import json
import os
import unittest
from unittest.mock import MagicMock, PropertyMock, patch

import stix2
from pycti import STIX_EXT_OCTI, Identity, Indicator
from virustotal.builder import VirusTotalBuilder
from virustotal.models.configs.virustotal_configs import IndicatorConfig


class VirusTotalBuilderTest(unittest.TestCase):
    @classmethod
    def setup_class(cls):
        cls.helper = MagicMock()
        cls.confidence_level = PropertyMock(return_value=49)
        type(cls.helper).connect_confidence_level = cls.confidence_level
        cls.helper.api.stix2.format_date.return_value = datetime.datetime.now(
            datetime.timezone.utc
        )

        # Setup author
        cls.author = stix2.Identity(
            id=Identity.generate_id("VirusTotal", "Organization"),
            name="VirusTotal",
            identity_class="Organization",
            description="VirusTotal",
            confidence=cls.helper.connect_confidence_level,
        )

    def test_init_builder(self):
        # Check that the author is created.
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "fakeid"},
            {"id": "fakeid"},
            self.load_file("vt_test_file.json")["data"],
        )
        self.assertEqual(len(builder.bundle), 1)
        self.assertEqual(builder.bundle[0].name, "VirusTotal")
        self.assertEqual(builder.bundle[0].confidence, 49)

    def test_send_bundle_uses_update_true(self):
        # update=True is required so the worker overwrites scalar fields (e.g.
        # x_opencti_score) on entities that already exist in the platform - see
        # the comment on VirusTotalBuilder.send_bundle for the full rationale.
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "fakeid"},
            {"id": "fakeid"},
            self.load_file("vt_test_file.json")["data"],
        )
        self.helper.reset_mock()
        builder.send_bundle()
        self.helper.send_stix2_bundle.assert_called_once()
        _, kwargs = self.helper.send_stix2_bundle.call_args
        self.assertTrue(kwargs.get("update"))

    def test_update_size_sets_size_when_present(self):
        stix_entity = {"id": "fakeid"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "fakeid"},
            self.load_file("vt_test_file.json")["data"],
        )
        builder.update_size()
        self.assertEqual(stix_entity["size"], 87040)

    def test_update_size_skips_when_absent(self):
        """VT returns no "size" for hashes it has only ever seen "in the
        wild" but never analysed; update_size must not raise KeyError in
        that case (see comment on VirusTotalBuilder.update_size)."""
        data = self.load_file("vt_test_file.json")["data"]
        del data["attributes"]["size"]
        stix_entity = {"id": "fakeid"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "fakeid"},
            data,
        )
        builder.update_size()  # should not raise
        self.assertNotIn("size", stix_entity)

    def test_compute_score(self):
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "fakeid"},
            {"id": "fakeid"},
            self.load_file("vt_test_file.json")["data"],
        )
        attributes = self.load_file("vt_test_file.json")["data"]["attributes"]
        self.assertEqual(
            builder._compute_score(attributes["last_analysis_stats"], {}), 72
        )

    def test_compute_score_with_gti_assessment(self):
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "fakeid"},
            {"id": "fakeid"},
            self.load_file("vt_test_file.json")["data"],
            gti_enabled=True,
        )
        attributes = self.load_file("vt_test_file.json")["data"]["attributes"]
        gti_assessment = {"threat_score": {"value": 85}}
        self.assertEqual(
            builder._compute_score(attributes["last_analysis_stats"], gti_assessment),
            85,
        )

    def test_compute_score_ignores_gti_assessment_when_disabled(self):
        """gti_enabled=False must ignore a present, usable gti_assessment
        entirely and fall back to the legacy stats-based score."""
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "fakeid"},
            {"id": "fakeid"},
            self.load_file("vt_test_file.json")["data"],
            gti_enabled=False,
        )
        attributes = self.load_file("vt_test_file.json")["data"]["attributes"]
        gti_assessment = {"threat_score": {"value": 85}}
        self.assertEqual(
            builder._compute_score(attributes["last_analysis_stats"], gti_assessment),
            72,
        )

    def test_compute_score_gti_assessment_no_threat_score(self):
        """GTI assessment present but missing threat_score falls back to stats."""
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "fakeid"},
            {"id": "fakeid"},
            self.load_file("vt_test_file.json")["data"],
            gti_enabled=True,
        )
        attributes = self.load_file("vt_test_file.json")["data"]["attributes"]
        self.assertEqual(
            builder._compute_score(attributes["last_analysis_stats"], {}), 72
        )

    def test_compute_score_gti_assessment_none(self):
        """gti_assessment=None falls back to stats-based computation."""
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "fakeid"},
            {"id": "fakeid"},
            self.load_file("vt_test_file.json")["data"],
            gti_enabled=True,
        )
        attributes = self.load_file("vt_test_file.json")["data"]["attributes"]
        self.assertEqual(
            builder._compute_score(attributes["last_analysis_stats"], None), 72
        )

    def test_create_asn_belongs_to(self):
        observable = {
            "standard_id": "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2",
            "id": "90a03625-500c-5813-abd1-5d5519f833d2",
        }
        stix_entity = {"id": "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [stix_entity],
            stix_entity,
            observable,
            self.load_file("vt_test_ipv4.json")["data"],
        )
        builder.create_asn_belongs_to()
        # Bundle should have 3 elements: the author, the asn and the relationship.
        self.assertEqual(len(builder.bundle), 4)
        self.assertEqual(builder.bundle[2].number, 13886)
        self.assertEqual(builder.bundle[2].name, "CLOUD-SOUTH")
        self.assertEqual(builder.bundle[2].rir, "RIPE NCC")
        self.assertEqual(builder.bundle[3].relationship_type, "belongs-to")
        self.assertEqual(
            builder.bundle[3].source_ref,
            "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2",
        )
        self.assertEqual(builder.bundle[3].target_ref, builder.bundle[2].id)

    def test_create_ip_resolves_to(self):
        observable = {
            "standard_id": "domain-name--c3967e18-f6e3-5b6a-8d40-16dca535fca3",
            "id": "c3967e18-f6e3-5b6a-8d40-16dca535fca3",
        }
        stix_entity = {"id": "domain-name--c3967e18-f6e3-5b6a-8d40-16dca535fca3"}
        ipv4 = "65.12.3343.66"
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            stix_objects=[stix_entity],
            stix_entity=stix_entity,
            opencti_entity=observable,
            data=self.load_file("vt_test_domain.json")["data"],
        )
        builder.create_ip_resolves_to(ipv4)
        # Bundle should have 3 elements: the author, the asn and the relationship.
        self.assertEqual(len(builder.bundle), 4)
        self.assertEqual(builder.bundle[2].value, ipv4)
        self.assertEqual(builder.bundle[3].relationship_type, "resolves-to")
        self.assertEqual(
            builder.bundle[3].source_ref,
            "domain-name--c3967e18-f6e3-5b6a-8d40-16dca535fca3",
        )
        self.assertEqual(builder.bundle[3].target_ref, builder.bundle[2].id)

    def test_create_location_located_at(self):
        observable = {
            "standard_id": "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2",
            "id": "90a03625-500c-5813-abd1-5d5519f833d2",
        }
        stix_entity = {"id": "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            stix_objects=[stix_entity],
            stix_entity=stix_entity,
            opencti_entity=observable,
            data=self.load_file("vt_test_ipv4.json")["data"],
        )
        builder.create_location_located_at()
        # Bundle should have 3 elements: the author, the asn and the relationship.
        self.assertEqual(len(builder.bundle), 4)
        self.assertEqual(builder.bundle[2].country, "GB")
        self.assertEqual(builder.bundle[2].created_by_ref, self.author.id)
        self.assertEqual(builder.bundle[3].relationship_type, "located-at")
        self.assertEqual(
            builder.bundle[3].source_ref,
            "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2",
        )
        self.assertEqual(builder.bundle[3].target_ref, builder.bundle[2].id)

    def _make_gti_builder(self):
        """Build a VirusTotalBuilder against a fake IPv4-Addr, for GTI collection tests."""
        stix_entity = {"id": "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2"}
        return stix_entity, VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            stix_objects=[stix_entity],
            stix_entity=stix_entity,
            opencti_entity={"id": "fakeid"},
            data=self.load_file("vt_test_ipv4.json")["data"],
        )

    def test_create_malware_family(self):
        stix_entity, builder = self._make_gti_builder()
        collection_data = self.load_file("vt_test_gti_malware_families.json")["data"][0]
        builder.create_malware_family(collection_data)
        # Bundle: [stix_entity, author, malware, relationship].
        self.assertEqual(len(builder.bundle), 4)
        malware = builder.bundle[2]
        self.assertEqual(malware.name, "LUMMAC.V2")
        self.assertTrue(malware.is_family)
        self.assertEqual(malware.created_by_ref, self.author.id)
        relationship = builder.bundle[3]
        self.assertEqual(relationship.relationship_type, "related-to")
        self.assertEqual(relationship.source_ref, stix_entity["id"])
        self.assertEqual(relationship.target_ref, malware.id)

    def test_create_malware_family_also_indicates_from_created_indicator(self):
        """When create_indicator_based_on already created an Indicator this
        run, GTI entities must also get an `indicates` edge from it, in
        addition to the observable's own `related-to` edge."""
        stix_entity, builder = self._make_gti_builder()
        builder.indicator = stix2.Indicator(
            id=Indicator.generate_id("[ipv4-addr:value = '1.2.3.4']"),
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="stix",
            valid_from=datetime.datetime.now(datetime.timezone.utc),
        )
        collection_data = self.load_file("vt_test_gti_malware_families.json")["data"][0]
        builder.create_malware_family(collection_data)
        # Bundle: [stix_entity, author, malware, related-to, indicates].
        self.assertEqual(len(builder.bundle), 5)
        malware = builder.bundle[2]
        related_to = builder.bundle[3]
        self.assertEqual(related_to.relationship_type, "related-to")
        self.assertEqual(related_to.source_ref, stix_entity["id"])
        indicates = builder.bundle[4]
        self.assertEqual(indicates.relationship_type, "indicates")
        self.assertEqual(indicates.source_ref, builder.indicator.id)
        self.assertEqual(indicates.target_ref, malware.id)

    def test_create_malware_family_indicates_when_enriching_indicator_directly(self):
        """When is_indicator=True, self.stix_entity IS the Indicator, so the
        link to a GTI entity should be `indicates`, not `related-to`."""
        indicator_entity = {"id": "indicator--357c4d50-72a2-40f8-8b7e-3bb59d1fa5db"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            stix_objects=[indicator_entity],
            stix_entity=indicator_entity,
            opencti_entity={"id": "fakeid"},
            data=self.load_file("vt_test_ipv4.json")["data"],
            is_indicator=True,
        )
        collection_data = self.load_file("vt_test_gti_malware_families.json")["data"][0]
        builder.create_malware_family(collection_data)
        # Bundle: [indicator_entity, author, malware, indicates] - no related-to.
        self.assertEqual(len(builder.bundle), 4)
        malware = builder.bundle[2]
        relationship = builder.bundle[3]
        self.assertEqual(relationship.relationship_type, "indicates")
        self.assertEqual(relationship.source_ref, indicator_entity["id"])
        self.assertEqual(relationship.target_ref, malware.id)

    def test_create_malware_family_skips_when_no_name(self):
        _, builder = self._make_gti_builder()
        builder.create_malware_family({"id": "threatfox_win_lumma", "attributes": {}})
        self.assertEqual(len(builder.bundle), 2)  # unchanged: stix_entity + author only

    def test_create_intrusion_set(self):
        stix_entity, builder = self._make_gti_builder()
        collection_data = self.load_file("vt_test_gti_threat_actors.json")["data"][0]
        builder.create_intrusion_set(collection_data)
        self.assertEqual(len(builder.bundle), 4)
        intrusion_set = builder.bundle[2]
        self.assertEqual(intrusion_set.name, "APT28")
        self.assertEqual(list(intrusion_set.aliases), ["Fancy Bear", "Sofacy"])
        relationship = builder.bundle[3]
        self.assertEqual(relationship.relationship_type, "related-to")
        self.assertEqual(relationship.source_ref, stix_entity["id"])
        self.assertEqual(relationship.target_ref, intrusion_set.id)

    def test_create_intrusion_set_also_indicates_from_created_indicator(self):
        stix_entity, builder = self._make_gti_builder()
        builder.indicator = stix2.Indicator(
            id=Indicator.generate_id("[ipv4-addr:value = '1.2.3.4']"),
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="stix",
            valid_from=datetime.datetime.now(datetime.timezone.utc),
        )
        collection_data = self.load_file("vt_test_gti_threat_actors.json")["data"][0]
        builder.create_intrusion_set(collection_data)
        self.assertEqual(len(builder.bundle), 5)
        indicates = builder.bundle[4]
        self.assertEqual(indicates.relationship_type, "indicates")
        self.assertEqual(indicates.source_ref, builder.indicator.id)

    def test_create_campaign(self):
        stix_entity, builder = self._make_gti_builder()
        collection_data = self.load_file("vt_test_gti_campaigns.json")["data"][0]
        builder.create_campaign(collection_data)
        self.assertEqual(len(builder.bundle), 4)
        campaign = builder.bundle[2]
        self.assertEqual(
            campaign.name,
            "Espionage-Motivated Actor Exploits Outlook Vulnerability CVE-2023-23397",
        )
        relationship = builder.bundle[3]
        self.assertEqual(relationship.relationship_type, "related-to")
        self.assertEqual(relationship.source_ref, stix_entity["id"])
        self.assertEqual(relationship.target_ref, campaign.id)

    def test_create_campaign_also_indicates_from_created_indicator(self):
        stix_entity, builder = self._make_gti_builder()
        builder.indicator = stix2.Indicator(
            id=Indicator.generate_id("[ipv4-addr:value = '1.2.3.4']"),
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="stix",
            valid_from=datetime.datetime.now(datetime.timezone.utc),
        )
        collection_data = self.load_file("vt_test_gti_campaigns.json")["data"][0]
        builder.create_campaign(collection_data)
        self.assertEqual(len(builder.bundle), 5)
        indicates = builder.bundle[4]
        self.assertEqual(indicates.relationship_type, "indicates")
        self.assertEqual(indicates.source_ref, builder.indicator.id)

    def test_create_report(self):
        stix_entity, builder = self._make_gti_builder()
        collection_data = self.load_file("vt_test_gti_reports.json")["data"][0]
        builder.create_report(collection_data)
        # Reports link via object_refs, not a separate relationship:
        # bundle is [stix_entity, author, report].
        self.assertEqual(len(builder.bundle), 3)
        report = builder.bundle[2]
        self.assertEqual(
            report.name, "Lumma Stealer actively deployed in multiple campaigns"
        )
        self.assertEqual(list(report.object_refs), [stix_entity["id"]])

    def test_create_report_also_includes_created_indicator(self):
        """When create_indicator_based_on already created an Indicator this
        run, the Report's object_refs must include it alongside the
        observable - otherwise the Indicator is silently left out of the
        Report entirely."""
        stix_entity, builder = self._make_gti_builder()
        builder.indicator = stix2.Indicator(
            id=Indicator.generate_id("[ipv4-addr:value = '1.2.3.4']"),
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="stix",
            valid_from=datetime.datetime.now(datetime.timezone.utc),
        )
        collection_data = self.load_file("vt_test_gti_reports.json")["data"][0]
        builder.create_report(collection_data)
        report = builder.bundle[2]
        self.assertEqual(
            list(report.object_refs), [stix_entity["id"], builder.indicator.id]
        )

    def test_create_report_uses_fixed_sentinel_when_no_creation_date(self):
        """A report with no creation_date must fall back to a fixed sentinel
        date, never datetime.now(), so repeat enrichment runs against the
        same report produce the same id instead of a new one every time."""
        _, builder = self._make_gti_builder()
        collection_data = {
            "id": "report--no-date",
            "attributes": {"name": "No Date Report"},
        }
        builder.create_report(collection_data)
        published_arg = self.helper.api.stix2.format_date.call_args[0][0]
        self.assertLess(published_arg.year, 2000)

    def test_create_notes(self):
        observable = {
            "standard_id": "url--94a2e4e9-bb9a-544a-b379-44923d37ca82",
            "id": "94a2e4e9-bb9a-544a-b379-44923d37ca82",
            "entity_type": "Url",
            "observable_value": "http://soclosebutyetqq.com/69.exe",
        }
        stix_entity = {"id": "url--94a2e4e9-bb9a-544a-b379-44923d37ca82"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            stix_objects=[stix_entity],
            stix_entity=stix_entity,
            opencti_entity=observable,
            data=self.load_file("vt_test_url.json")["data"],
        )
        builder.create_notes()
        # Bundle should have 3 elements: the author, the asn and the relationship.
        self.assertEqual(len(builder.bundle), 4)
        self.assertEqual(
            builder.bundle[2].abstract,
            "VirusTotal Results (Url: http://soclosebutyetqq.com/69.exe)",
        )
        self.assertTrue("Sangfor" in builder.bundle[2].content)
        self.assertEqual(builder.bundle[2].created_by_ref, self.author.id)
        self.assertTrue(
            "url--94a2e4e9-bb9a-544a-b379-44923d37ca82" in builder.bundle[2].object_refs
        )
        self.assertEqual(
            builder.bundle[3].abstract,
            "VirusTotal Categories (Url: http://soclosebutyetqq.com/69.exe)",
        )
        self.assertTrue("Sophos" in builder.bundle[3].content)
        self.assertEqual(builder.bundle[2].created_by_ref, self.author.id)
        self.assertEqual(builder.bundle[3].created_by_ref, self.author.id)
        self.assertTrue(
            "url--94a2e4e9-bb9a-544a-b379-44923d37ca82" in builder.bundle[3].object_refs
        )

    def test_create_notes_with_attributes_and_empty_serving_ip(self):
        """An empty last_serving_ip_address relationship must not break the note.

        VirusTotal returns {"data": null} for an empty to-one relationship, so
        the processor hands over an empty mapping — the note must still be
        produced, with N/A for the missing value.
        """
        observable = {
            "standard_id": "url--94a2e4e9-bb9a-544a-b379-44923d37ca82",
            "id": "94a2e4e9-bb9a-544a-b379-44923d37ca82",
            "entity_type": "Url",
            "observable_value": "http://soclosebutyetqq.com/69.exe",
        }
        stix_entity = {"id": "url--94a2e4e9-bb9a-544a-b379-44923d37ca82"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            stix_objects=[stix_entity],
            stix_entity=stix_entity,
            opencti_entity=observable,
            data=self.load_file("vt_test_url.json")["data"],
            include_attributes_in_note=True,
            url_related_object_data={},
        )
        builder.create_notes()
        self.assertIn("| Serving IP Address | N/A |", builder.bundle[2].content)

    def test_create_notes_with_attributes_and_serving_ip(self):
        """When the relationship is populated, the IP is rendered in the note."""
        observable = {
            "standard_id": "url--94a2e4e9-bb9a-544a-b379-44923d37ca82",
            "id": "94a2e4e9-bb9a-544a-b379-44923d37ca82",
            "entity_type": "Url",
            "observable_value": "http://soclosebutyetqq.com/69.exe",
        }
        stix_entity = {"id": "url--94a2e4e9-bb9a-544a-b379-44923d37ca82"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            stix_objects=[stix_entity],
            stix_entity=stix_entity,
            opencti_entity=observable,
            data=self.load_file("vt_test_url.json")["data"],
            include_attributes_in_note=True,
            url_related_object_data={"id": "1.2.3.4", "type": "ip_address"},
        )
        builder.create_notes()
        self.assertIn("| Serving IP Address | 1.2.3.4 |", builder.bundle[2].content)

    def test_create_yara(self):
        observable = {
            "standard_id": "file--3a30a5ed-003e-5ef9-9ede-10823a9fb17f",
            "id": "3a30a5ed-003e-5ef9-9ede-10823a9fb17f",
        }
        stix_entity = {"id": "file--3a30a5ed-003e-5ef9-9ede-10823a9fb17f"}
        data = self.load_file("vt_test_file.json")["data"]
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            stix_objects=[stix_entity],
            stix_entity=stix_entity,
            opencti_entity=observable,
            data=data,
        )
        yara = data["attributes"]["crowdsourced_yara_results"][0]
        ruleset = self.load_file("vt_test_yara.json")
        builder.create_yara(yara, ruleset)
        # Bundle should have 3 elements: the author, the asn and the relationship.
        self.assertEqual(len(builder.bundle), 4)
        self.assertEqual(builder.bundle[2].name, "win_kerrdown_auto")
        self.assertEqual(builder.bundle[2].pattern_type, "yara")
        self.assertEqual(builder.bundle[2].created_by_ref, self.author.id)
        self.assertEqual(builder.bundle[2].confidence, 49)
        self.assertEqual(builder.bundle[3].relationship_type, "related-to")
        self.assertEqual(builder.bundle[3].created_by_ref, self.author.id)
        self.assertEqual(
            builder.bundle[3].source_ref, "file--3a30a5ed-003e-5ef9-9ede-10823a9fb17f"
        )
        self.assertEqual(builder.bundle[3].target_ref, builder.bundle[2].id)

    def test_extract_link(self):
        self.assertEqual(
            VirusTotalBuilder._extract_link(
                "https://www.virustotal.com/api/v3/files/4bc00f7d638e042da764e8648c03c0db46700599dd4f08d117e3e9e8b538519b"
            ),
            "https://www.virustotal.com/gui/file/4bc00f7d638e042da764e8648c03c0db46700599dd4f08d117e3e9e8b538519b",
        )
        self.assertEqual(
            VirusTotalBuilder._extract_link("https://www.virustotal.com/api/v3/f/abc"),
            None,
        )
        self.assertEqual(
            VirusTotalBuilder._extract_link(
                "https://www.virustotal.com/api/v3/ip_addresses/138.128.150.133"
            ),
            "https://www.virustotal.com/gui/ip-address/138.128.150.133",
        )
        self.assertEqual(
            VirusTotalBuilder._extract_link(
                "https://www.virustotal.com/api/v3/domains/tawuhoju.com"
            ),
            "https://www.virustotal.com/gui/domain/tawuhoju.com",
        )
        self.assertEqual(
            VirusTotalBuilder._extract_link(
                "https://www.virustotal.com/api/v3/urls/7d83e9f686ff0122ded311f27aababf6922800a45a23a4dacc860b56ccada4cb"
            ),
            "https://www.virustotal.com/gui/url/7d83e9f686ff0122ded311f27aababf6922800a45a23a4dacc860b56ccada4cb",
        )

    def test_is_indicator_skips_create_indicator_based_on(self):
        """When is_indicator=True, create_indicator_based_on must be a no-op."""

        stix_entity = {"id": "indicator--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
        opencti_entity = {
            "entity_type": "IPv4-Addr",
            "observable_value": "1.2.3.4",
        }
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [stix_entity],
            stix_entity,
            opencti_entity,
            self.load_file("vt_test_ipv4.json")["data"],
            is_indicator=True,
        )
        initial_bundle_len = len(builder.bundle)
        config = IndicatorConfig(threshold=1, valid_minutes=2880, detect=True)
        builder.create_indicator_based_on(config, "[ipv4-addr:value = '1.2.3.4']")
        # Bundle must not grow — no new indicator was created.
        self.assertEqual(len(builder.bundle), initial_bundle_len)

    def test_is_indicator_sets_score_via_octi_extension(self):
        """When is_indicator=True, the STIX_EXT_OCTI extension should carry the score."""

        stix_entity = {"id": "indicator--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
        opencti_entity = {
            "entity_type": "IPv4-Addr",
            "observable_value": "1.2.3.4",
        }
        _ = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [stix_entity],
            stix_entity,
            opencti_entity,
            self.load_file("vt_test_ipv4.json")["data"],
            is_indicator=True,
        )
        ext_data = stix_entity.get("extensions", {}).get(STIX_EXT_OCTI, {})
        self.assertIn("score", ext_data)

    def test_create_indicator_gti_verdict_malicious_overrides_low_legacy_count(self):
        """A GTI-malicious verdict must trigger indicator creation even when
        the legacy multi-engine count is well below the configured
        threshold (see _meets_indicator_threshold)."""
        data = self.load_file("vt_test_ipv4.json")["data"]
        data["attributes"]["gti_assessment"] = {
            "verdict": {"value": "VERDICT_MALICIOUS"}
        }
        self.assertLess(data["attributes"]["last_analysis_stats"]["malicious"], 10)
        stix_entity = {"id": "ipv4-addr--357c4d50-72a2-40f8-8b7e-3bb59d1fa5db"}
        opencti_entity = {"entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            opencti_entity,
            data,
            gti_enabled=True,
        )
        initial_bundle_len = len(builder.bundle)
        config = IndicatorConfig(threshold=10, valid_minutes=2880, detect=True)
        # format_date is mocked class-wide to a timestamp fixed at setup_class
        # time; scope it to the real valid_until here so it stays after
        # stix2's own valid_from default (also "now") regardless of how much
        # wall-clock time has passed since setup_class ran.
        with patch.object(
            self.helper.api.stix2, "format_date", side_effect=lambda dt: dt
        ):
            builder.create_indicator_based_on(config, "[ipv4-addr:value = '1.2.3.4']")
        self.assertEqual(len(builder.bundle), initial_bundle_len + 2)
        indicator = builder.bundle[initial_bundle_len]
        self.assertIn("GTI verdict is malicious", indicator.description)
        # builder.indicator must be set so GTI-derived entities created
        # later in this same run can link to it via `indicates`.
        self.assertEqual(builder.indicator.id, indicator.id)

    def test_create_indicator_gti_verdict_ignored_when_disabled(self):
        """gti_enabled=False must ignore a malicious GTI verdict entirely,
        even when the legacy count is below threshold."""
        data = self.load_file("vt_test_ipv4.json")["data"]
        data["attributes"]["gti_assessment"] = {
            "verdict": {"value": "VERDICT_MALICIOUS"}
        }
        self.assertLess(data["attributes"]["last_analysis_stats"]["malicious"], 10)
        stix_entity = {"id": "ipv4-addr--357c4d50-72a2-40f8-8b7e-3bb59d1fa5db"}
        opencti_entity = {"entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            opencti_entity,
            data,
            gti_enabled=False,
        )
        initial_bundle_len = len(builder.bundle)
        config = IndicatorConfig(threshold=10, valid_minutes=2880, detect=True)
        builder.create_indicator_based_on(config, "[ipv4-addr:value = '1.2.3.4']")
        self.assertEqual(len(builder.bundle), initial_bundle_len)

    def test_create_indicator_not_created_leaves_builder_indicator_none(self):
        """When the threshold isn't met, builder.indicator must stay None -
        otherwise a later GTI entity would wrongly link to a stale/no-op
        Indicator that was never actually added to the bundle."""
        data = self.load_file("vt_test_ipv4.json")["data"]
        stix_entity = {"id": "ipv4-addr--357c4d50-72a2-40f8-8b7e-3bb59d1fa5db"}
        opencti_entity = {"entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"}
        builder = VirusTotalBuilder(
            self.helper, self.author, True, [], stix_entity, opencti_entity, data
        )
        config = IndicatorConfig(threshold=1000, valid_minutes=2880, detect=True)
        builder.create_indicator_based_on(config, "[ipv4-addr:value = '1.2.3.4']")
        self.assertIsNone(builder.indicator)

    def test_create_indicator_threshold_zero_disables_even_with_gti_verdict(self):
        """threshold=0 is documented as fully disabling indicator creation;
        that must still hold even when GTI's verdict is malicious."""
        data = self.load_file("vt_test_ipv4.json")["data"]
        data["attributes"]["gti_assessment"] = {
            "verdict": {"value": "VERDICT_MALICIOUS"}
        }
        stix_entity = {"id": "fakeid"}
        opencti_entity = {"entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            opencti_entity,
            data,
            gti_enabled=True,
        )
        initial_bundle_len = len(builder.bundle)
        config = IndicatorConfig(threshold=0, valid_minutes=2880, detect=True)
        builder.create_indicator_based_on(config, "[ipv4-addr:value = '1.2.3.4']")
        self.assertEqual(len(builder.bundle), initial_bundle_len)

    def test_create_indicator_legacy_threshold_without_gti_assessment(self):
        """Without a gti_assessment at all, the legacy count-vs-threshold
        behavior must be unchanged."""
        data = self.load_file("vt_test_ipv4.json")["data"]
        malicious_count = data["attributes"]["last_analysis_stats"]["malicious"]
        stix_entity = {"id": "ipv4-addr--16f93f1a-5e85-44aa-9fa6-10ea5da66de3"}
        opencti_entity = {"entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"}
        builder = VirusTotalBuilder(
            self.helper, self.author, True, [], stix_entity, opencti_entity, data
        )
        initial_bundle_len = len(builder.bundle)
        config = IndicatorConfig(
            threshold=malicious_count, valid_minutes=2880, detect=True
        )
        with patch.object(
            self.helper.api.stix2, "format_date", side_effect=lambda dt: dt
        ):
            builder.create_indicator_based_on(config, "[ipv4-addr:value = '1.2.3.4']")
        self.assertEqual(len(builder.bundle), initial_bundle_len + 2)
        indicator = builder.bundle[initial_bundle_len]
        self.assertIn("positive count was >=", indicator.description)

    def test_create_indicator_gti_verdict_not_malicious_falls_back_to_legacy(self):
        """A gti_assessment present but not malicious must not bypass the
        legacy threshold check."""
        data = self.load_file("vt_test_ipv4.json")["data"]
        data["attributes"]["gti_assessment"] = {
            "verdict": {"value": "VERDICT_HARMLESS"}
        }
        self.assertLess(data["attributes"]["last_analysis_stats"]["malicious"], 10)
        stix_entity = {"id": "fakeid"}
        opencti_entity = {"entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            opencti_entity,
            data,
            gti_enabled=True,
        )
        initial_bundle_len = len(builder.bundle)
        config = IndicatorConfig(threshold=10, valid_minutes=2880, detect=True)
        builder.create_indicator_based_on(config, "[ipv4-addr:value = '1.2.3.4']")
        self.assertEqual(len(builder.bundle), initial_bundle_len)

    def test_update_labels_for_indicator(self):
        """When is_indicator=True, update_labels should set labels directly on stix_entity."""
        stix_entity = {"id": "indicator--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
        opencti_entity = {
            "entity_type": "StixFile",
            "observable_value": "abc123",
        }
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [stix_entity],
            stix_entity,
            opencti_entity,
            self.load_file("vt_test_file.json")["data"],
            is_indicator=True,
        )
        builder.update_labels()
        # Tags from vt_test_file should now be in stix_entity["labels"].
        self.assertIn("labels", stix_entity)
        self.assertIsInstance(stix_entity["labels"], list)
        self.assertTrue(len(stix_entity["labels"]) > 0)

    def test_update_hashes_sets_all_when_present(self):
        stix_entity = {"id": "fakeid", "hashes": {}}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "fakeid"},
            self.load_file("vt_test_file.json")["data"],
        )
        builder.update_hashes()
        self.assertEqual(
            stix_entity["hashes"]["MD5"], "546bb6ef89bebfb053999777f6930d7e"
        )
        self.assertEqual(
            stix_entity["hashes"]["SHA-1"], "44392b16e2db656104579e83d603b363bf91ccb2"
        )
        self.assertEqual(
            stix_entity["hashes"]["SHA-256"],
            "4bc00f7d638e042da764e8648c03c0db46700599dd4f08d117e3e9e8b538519b",
        )

    def test_update_hashes_skips_missing_algos(self):
        """VT may omit some hash fields for unanalysed files; update_hashes
        must not raise KeyError in that case (see comment on the method)."""
        data = self.load_file("vt_test_file.json")["data"]
        del data["attributes"]["md5"]
        stix_entity = {"id": "fakeid", "hashes": {}}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "fakeid"},
            data,
        )
        builder.update_hashes()  # should not raise
        self.assertNotIn("MD5", stix_entity["hashes"])
        self.assertIn("SHA-1", stix_entity["hashes"])

    def test_update_labels_skips_when_tags_absent(self):
        """VT may omit "tags" entirely for unanalysed files; update_labels
        must not raise KeyError in that case (see comment on the method)."""
        data = self.load_file("vt_test_file.json")["data"]
        del data["attributes"]["tags"]
        stix_entity = {"id": "indicator--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [stix_entity],
            stix_entity,
            {"id": "fakeid"},
            data,
            is_indicator=True,
        )
        builder.update_labels()  # should not raise
        self.assertNotIn("labels", stix_entity)

    def test_update_names_sets_main_when_present(self):
        stix_entity = {"id": "fakeid"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "fakeid"},
            self.load_file("vt_test_file.json")["data"],
        )
        builder.update_names(main=True)
        self.assertIn("name", stix_entity)

    def test_update_names_skips_when_absent(self):
        """VT may omit "names" entirely for unanalysed files; update_names
        must not raise KeyError in that case (see comment on the method)."""
        data = self.load_file("vt_test_file.json")["data"]
        del data["attributes"]["names"]
        stix_entity = {"id": "fakeid"}
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "fakeid"},
            data,
        )
        builder.update_names(main=True)  # should not raise
        self.assertNotIn("name", stix_entity)

    @staticmethod
    def load_file(filename: str):
        """Utility function to load a json file to a dict."""
        filepath = os.path.join(os.path.dirname(__file__), "resources", filename)
        with open(filepath, encoding="utf-8") as json_file:
            return json.load(json_file)
