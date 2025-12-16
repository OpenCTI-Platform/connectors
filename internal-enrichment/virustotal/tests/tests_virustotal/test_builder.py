# -*- coding: utf-8 -*-
"""Virustotal builder unittest."""
import datetime
import json
import os
import unittest
from unittest.mock import MagicMock, PropertyMock

import stix2
from pycti import Identity
from virustotal.builder import VirusTotalBuilder


class VirusTotalBuilderTest(unittest.TestCase):
    @classmethod
    def setup_class(cls):
        cls.helper = MagicMock()
        cls.confidence_level = PropertyMock(return_value=49)
        type(cls.helper).connect_confidence_level = cls.confidence_level
        cls.helper.api.stix2.format_date.return_value = datetime.datetime.utcnow()

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
        self.assertEqual(builder._compute_score(attributes["last_analysis_stats"]), 72)

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

    def test_create_notes(self):
        observable = {
            "standard_id": "url--94a2e4e9-bb9a-544a-b379-44923d37ca82",
            "id": "94a2e4e9-bb9a-544a-b379-44923d37ca82",
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
        self.assertEqual(builder.bundle[2].abstract, "VirusTotal Results")
        self.assertTrue("Sangfor" in builder.bundle[2].content)
        self.assertEqual(builder.bundle[2].created_by_ref, self.author.id)
        self.assertTrue(
            "url--94a2e4e9-bb9a-544a-b379-44923d37ca82" in builder.bundle[2].object_refs
        )
        self.assertEqual(builder.bundle[3].abstract, "VirusTotal Categories")
        self.assertTrue("Sophos" in builder.bundle[3].content)
        self.assertEqual(builder.bundle[2].created_by_ref, self.author.id)
        self.assertEqual(builder.bundle[3].created_by_ref, self.author.id)
        self.assertTrue(
            "url--94a2e4e9-bb9a-544a-b379-44923d37ca82" in builder.bundle[3].object_refs
        )

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

    @staticmethod
    def load_file(filename: str):
        """Utility function to load a json file to a dict."""
        filepath = os.path.join(os.path.dirname(__file__), "resources", filename)
        with open(filepath, encoding="utf-8") as json_file:
            return json.load(json_file)
