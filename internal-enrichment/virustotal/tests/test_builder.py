# -*- coding: utf-8 -*-
"""Virustotal builder unittest."""
import datetime
import json
import unittest
from unittest.mock import MagicMock, PropertyMock

import stix2

from src.virustotal.builder import VirusTotalBuilder


class VirusTotalBuilderTest(unittest.TestCase):
    @classmethod
    def setup_class(cls):
        cls.helper = MagicMock()
        cls.confidence_level = PropertyMock(return_value=49)
        type(cls.helper).connect_confidence_level = cls.confidence_level
        cls.helper.api.stix2.format_date.return_value = datetime.datetime.utcnow()

        # Setup author
        cls.author = stix2.Identity(
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
            {"id": "fakeid"},
            self.load_file("./resources/vt_test_file.json")["data"]["attributes"],
        )
        self.assertEqual(len(builder.bundle), 1)
        self.assertEqual(builder.bundle[0].name, "VirusTotal")
        self.assertEqual(builder.bundle[0].confidence, 49)

    def test_compute_score(self):
        attributes = self.load_file("./resources/vt_test_file.json")["data"][
            "attributes"
        ]
        self.assertEqual(
            VirusTotalBuilder._compute_score(attributes["last_analysis_stats"]), 72
        )

    def test_create_asn_belongs_to(self):
        observable = {
            "standard_id": "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2",
            "id": "90a03625-500c-5813-abd1-5d5519f833d2",
        }
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            observable,
            self.load_file("./resources/vt_test_ipv4.json")["data"]["attributes"],
        )
        builder.create_asn_belongs_to()
        # Bundle should have 3 elements: the author, the asn and the relationship.
        self.assertEqual(len(builder.bundle), 3)
        self.assertEqual(builder.bundle[1].number, 13886)
        self.assertEqual(builder.bundle[1].name, "CLOUD-SOUTH")
        self.assertEqual(builder.bundle[1].rir, "RIPE NCC")
        self.assertEqual(builder.bundle[2].relationship_type, "belongs-to")
        self.assertEqual(
            builder.bundle[2].source_ref,
            "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2",
        )
        self.assertEqual(builder.bundle[2].target_ref, builder.bundle[1].id)

    def test_create_ip_resolves_to(self):
        observable = {
            "standard_id": "domain-name--c3967e18-f6e3-5b6a-8d40-16dca535fca3",
            "id": "c3967e18-f6e3-5b6a-8d40-16dca535fca3",
        }
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            observable,
            self.load_file("./resources/vt_test_domain.json")["data"]["attributes"],
        )
        builder.create_asn_belongs_to()
        # Bundle should have 3 elements: the author, the asn and the relationship.
        self.assertEqual(len(builder.bundle), 3)
        self.assertEqual(builder.bundle[1].value, "65.8.243.66")
        self.assertEqual(builder.bundle[2].relationship_type, "resolves-to")
        self.assertEqual(
            builder.bundle[2].source_ref,
            "domain-name--c3967e18-f6e3-5b6a-8d40-16dca535fca3",
        )
        self.assertEqual(builder.bundle[2].target_ref, builder.bundle[1].id)

    def test_create_location_located_at(self):
        observable = {
            "standard_id": "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2",
            "id": "90a03625-500c-5813-abd1-5d5519f833d2",
        }
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            observable,
            self.load_file("./resources/vt_test_ipv4.json")["data"]["attributes"],
        )
        builder.create_location_located_at()
        # Bundle should have 3 elements: the author, the asn and the relationship.
        self.assertEqual(len(builder.bundle), 3)
        self.assertEqual(builder.bundle[1].country, "GB")
        self.assertEqual(builder.bundle[1].created_by_ref, self.author.id)
        self.assertEqual(builder.bundle[2].relationship_type, "located-at")
        self.assertEqual(
            builder.bundle[2].source_ref,
            "ipv4-addr--90a03625-500c-5813-abd1-5d5519f833d2",
        )
        self.assertEqual(builder.bundle[2].target_ref, builder.bundle[1].id)

    def test_create_notes(self):
        observable = {
            "standard_id": "url--94a2e4e9-bb9a-544a-b379-44923d37ca82",
            "id": "94a2e4e9-bb9a-544a-b379-44923d37ca82",
        }
        builder = VirusTotalBuilder(
            self.helper,
            self.author,
            observable,
            self.load_file("./resources/vt_test_url.json")["data"]["attributes"],
        )
        builder.create_notes()
        # Bundle should have 3 elements: the author, the asn and the relationship.
        self.assertEqual(len(builder.bundle), 3)
        self.assertEqual(builder.bundle[1].abstract, "VirusTotal Positives")
        self.assertTrue("Sangfor" in builder.bundle[1].content)
        self.assertEqual(builder.bundle[1].created_by_ref, self.author.id)
        self.assertTrue(
            "url--94a2e4e9-bb9a-544a-b379-44923d37ca82" in builder.bundle[1].object_refs
        )
        self.assertEqual(builder.bundle[2].abstract, "VirusTotal Categories")
        self.assertTrue("Sophos" in builder.bundle[2].content)
        self.assertEqual(builder.bundle[1].created_by_ref, self.author.id)
        self.assertEqual(builder.bundle[2].created_by_ref, self.author.id)
        self.assertTrue(
            "url--94a2e4e9-bb9a-544a-b379-44923d37ca82" in builder.bundle[2].object_refs
        )

    def test_create_yara(self):
        observable = {
            "standard_id": "file--3a30a5ed-003e-5ef9-9ede-10823a9fb17f",
            "id": "3a30a5ed-003e-5ef9-9ede-10823a9fb17f",
        }
        attributes = self.load_file("./resources/vt_test_file.json")["data"][
            "attributes"
        ]
        builder = VirusTotalBuilder(self.helper, self.author, observable, attributes)
        yara = attributes["crowdsourced_yara_results"][0]
        ruleset = self.load_file("./resources/vt_test_yara.json")
        builder.create_yara(yara, ruleset)
        # Bundle should have 3 elements: the author, the asn and the relationship.
        self.assertEqual(len(builder.bundle), 3)
        self.assertEqual(builder.bundle[1].name, "win_kerrdown_auto")
        self.assertEqual(builder.bundle[1].pattern_type, "yara")
        self.assertEqual(builder.bundle[1].created_by_ref, self.author.id)
        self.assertEqual(builder.bundle[1].confidence, 49)
        self.assertEqual(builder.bundle[2].relationship_type, "related-to")
        self.assertEqual(builder.bundle[2].created_by_ref, self.author.id)
        self.assertEqual(
            builder.bundle[2].source_ref, "file--3a30a5ed-003e-5ef9-9ede-10823a9fb17f"
        )
        self.assertEqual(builder.bundle[2].target_ref, builder.bundle[1].id)

    @staticmethod
    def load_file(path: str):
        """Utility function to load a json file to a dict."""
        with open(path) as json_file:
            return json.load(json_file)
