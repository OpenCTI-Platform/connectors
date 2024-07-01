# -*- coding: utf-8 -*-
"""CrowdSec builder unittest."""
import datetime
import json
import os
import unittest
from unittest.mock import MagicMock

import stix2
from crowdsec.builder import CrowdSecBuilder
from crowdsec.constants import FAKE_INDICATOR_ID
from dateutil.parser import parse


def load_file(filename: str):
    """Utility function to load a json file to a dict."""
    filepath = os.path.join(os.path.dirname(__file__), "resources", filename)
    with open(filepath, encoding="utf-8") as json_file:
        return json.load(json_file)


class CrowdSecBuilderTest(unittest.TestCase):
    @classmethod
    def setup_class(cls):
        cls.helper = MagicMock()
        cls.helper.api.indicator.generate_id.return_value = (
            "indicator--94c598e8-9174-58e0-9731-316e18f26916"
        )
        cls.helper.api.stix_domain_object.get_by_stix_id_or_name.return_value = {
            "standard_id": "identity--5f18c204-0a7f-5061-a146-d29561d9c8aa"
        }
        cls.helper.api.attack_pattern.generate_id.return_value = (
            "attack-pattern--76a389ac-1746-5f7f-a290-38f84e7d90e0"
        )
        cls.helper.api.note.generate_id.return_value = (
            "note--76cc9e78-e842-55fb-a0a0-8dbe3618cadd"
        )
        cls.helper.api.location.generate_id.return_value = (
            "location--76cc9e78-e842-55fb-a0a0-8dbe3618cadd"
        )
        cls.helper.api.stix2.format_date.return_value = datetime.datetime.utcnow()
        cls.cti_data = load_file("malicious_ip.json")
        cls.indicator = stix2.Indicator(
            id="indicator--94c598e8-9174-58e0-9731-316e18f26916",
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="stix",
            pattern_version="2.1",
            valid_from=datetime.datetime.utcnow(),
            created=datetime.datetime.utcnow(),
            modified=datetime.datetime.utcnow(),
            labels=["malicious-activity"],
            confidence=90,
            external_references=[
                {
                    "source_name": "Firehol cybercrime tracker list",
                    "description": "CyberCrime, a project tracking command and control. "
                    "This list contains command and control IP addresses.",
                    "url": "https://iplists.firehol.org/?ipset=cybercrime",
                }
            ],
        )

    def test_init_builder(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        self.assertEqual(len(builder.bundle_objects), 0)
        self.assertEqual(builder.crowdsec_ent_name, "CrowdSec")
        self.assertEqual(
            builder.crowdsec_ent_desc,
            "Curated Threat Intelligence Powered by the Crowd",
        )
        self.assertEqual(builder.labels_scenario_name, True)
        self.assertEqual(builder.labels_scenario_label, True)
        self.assertEqual(builder.labels_scenario_color, "#2E2A14")
        self.assertEqual(builder.labels_cve, False)
        self.assertEqual(builder.labels_cve_color, "#800080")
        self.assertEqual(builder.labels_mitre, False)
        self.assertEqual(builder.labels_mitre_color, "#000080")
        self.assertEqual(builder.labels_behavior, False)
        self.assertEqual(builder.labels_behavior_color, "#808000")
        self.assertEqual(builder.labels_reputation, False)
        self.assertEqual(builder.labels_reputation_malicious_color, "#FF0000")
        self.assertEqual(builder.labels_reputation_suspicious_color, "#FFA500")
        self.assertEqual(builder.labels_reputation_known_color, "#808080")
        self.assertEqual(builder.labels_reputation_safe_color, "#00BFFF")
        # CTI data
        self.assertEqual(builder.reputation, "malicious")
        self.assertEqual(builder.confidence, "high")
        self.assertEqual(builder.first_seen, "2023-06-13T19:00:00+00:00")
        self.assertEqual(builder.last_seen, "2024-04-18T08:15:00+00:00")
        self.assertEqual(builder.origin_city, "New York")
        self.assertEqual(builder.origin_country, "US")
        self.assertEqual(builder.behaviors, self.cti_data.get("behaviors", []))
        self.assertEqual(builder.references, self.cti_data.get("references", []))
        self.assertEqual(
            builder.mitre_techniques, self.cti_data.get("mitre_techniques", [])
        )
        self.assertEqual(
            builder.attack_details, self.cti_data.get("attack_details", [])
        )
        self.assertEqual(builder.cves, self.cti_data.get("cves", []))
        self.assertEqual(
            builder.target_countries, self.cti_data.get("target_countries", {})
        )

    def test_add_to_bundle(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        observable = stix2.IPv4Address(
            value="1.2.3.4",
        )
        builder.add_to_bundle([observable])

        self.assertEqual(len(builder.bundle_objects), 1)
        self.assertEqual(builder.bundle_objects[0], observable)

        other_observable = stix2.IPv4Address(
            value="4.5.6.7",
        )
        builder.add_to_bundle([other_observable])
        self.assertEqual(len(builder.bundle_objects), 2)
        self.assertEqual(builder.bundle_objects[1], other_observable)

    def test_add_external_reference_to_observable(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        stix_observable = load_file("stix_observable.json")

        external_reference = builder.add_external_reference_to_observable(
            stix_observable=stix_observable,
            source_name="CrowdSec CTI TEST",
            url="https://crowdsec.net",
            description="CrowdSec CTI url for this IP",
        )

        self.assertEqual(external_reference["source_name"], "CrowdSec CTI TEST")
        self.assertEqual(
            stix_observable["external_references"],
            [stix_observable["external_references"][0], external_reference],
        )

    def test_get_or_create_crowdsec_entity(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        entity = builder.get_or_create_crowdsec_ent()
        # Value is mocked on setup_class
        self.assertEqual(
            entity["standard_id"], "identity--5f18c204-0a7f-5061-a146-d29561d9c8aa"
        )

    def test_add_indicator_based_on(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )

        observable_id = load_file("observable.json")["standard_id"]
        stix_observable = load_file("stix_observable.json")

        indicator = builder.add_indicator_based_on(
            observable_id=observable_id,
            stix_observable=stix_observable,
            pattern=f"[ipv4-addr:value = '{stix_observable['value']}']",
            markings=[],
        )
        # Check indicator
        self.assertEqual(indicator.get("pattern_type"), "stix")
        self.assertEqual(indicator.get("confidence"), 90)  # high
        expected_ext_ref = stix2.ExternalReference(
            source_name="Firehol cybercrime tracker list",
            description="CyberCrime, a project tracking command and control. "
            "This list contains command and control IP addresses.",
            url="https://iplists.firehol.org/?ipset=cybercrime",
        )
        self.assertEqual(indicator.get("external_references"), [expected_ext_ref])
        # Check bundle
        self.assertEqual(len(builder.bundle_objects), 2)
        self.assertEqual(builder.bundle_objects[0], indicator)
        # Check relationship
        relationship = builder.bundle_objects[1]
        self.assertEqual(relationship["source_ref"], indicator["id"])
        self.assertEqual(relationship["relationship_type"], "based-on")

    def test_add_attack_pattern_for_mitre(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )

        indicator = self.indicator

        attack_pattern = builder.add_attack_pattern_for_mitre(
            mitre_technique={
                "label": "T1046",
                "description": "Network Service Scanning ...",
                "name": "Network Service Scanning",
            },
            markings=[],
            indicator_id=indicator.id,
            observable_id=None,
            external_references=[],
        )

        self.assertEqual(
            attack_pattern["name"], "MITRE ATT&CK (Network Service Scanning - T1046)"
        )
        # Check bundle
        self.assertEqual(len(builder.bundle_objects), 2)
        self.assertEqual(builder.bundle_objects[1], attack_pattern)
        # Check relationship
        relationship = builder.bundle_objects[0]
        self.assertEqual(relationship["target_ref"], attack_pattern["id"])
        self.assertEqual(relationship["relationship_type"], "indicates")

    def test_add_attack_pattern_for_mitre_with_observable_relation(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        observable_id = load_file("observable.json")["standard_id"]

        attack_pattern = builder.add_attack_pattern_for_mitre(
            mitre_technique={
                "label": "T1046",
                "description": "Network Service Scanning ...",
                "name": "Network Service Scanning",
            },
            markings=[],
            indicator_id=None,
            observable_id=observable_id,
            external_references=[],
        )

        self.assertEqual(
            attack_pattern["name"], "MITRE ATT&CK (Network Service Scanning - T1046)"
        )
        # Check bundle
        self.assertEqual(len(builder.bundle_objects), 2)
        self.assertEqual(builder.bundle_objects[1], attack_pattern)
        # Check relationship
        relationship = builder.bundle_objects[0]
        self.assertEqual(relationship["target_ref"], attack_pattern["id"])
        self.assertEqual(relationship["relationship_type"], "related-to")

    def test_add_note(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        observable = load_file("observable.json")
        observable_id = observable["standard_id"]
        ip = observable["value"]
        note = builder.add_note(
            observable_id=observable_id,
            markings=[],
        )

        self.assertEqual(note["abstract"], f"CrowdSec enrichment for {ip}")
        # Check bundle
        self.assertEqual(len(builder.bundle_objects), 1)
        self.assertEqual(builder.bundle_objects[0], note)

    def test_add_sighting(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )

        observable_id = load_file("observable.json")["standard_id"]
        sighting = builder.add_sighting(
            observable_id=observable_id,
            markings=[],
            sighting_ext_refs=[],  # External references
            indicator=None,
        )

        self.assertEqual(sighting["sighting_of_ref"], FAKE_INDICATOR_ID)

        sighting_2 = builder.add_sighting(
            observable_id=observable_id,
            markings=[],
            sighting_ext_refs=[],  # External references
            indicator=self.indicator,
        )

        self.assertEqual(
            sighting_2["sighting_of_ref"],
            "indicator--94c598e8-9174-58e0-9731-316e18f26916",
        )
        first_seen = self.cti_data.get("history", {}).get("first_seen", "")
        last_seen = self.cti_data.get("history", {}).get("last_seen", "")
        self.assertEqual(
            datetime.datetime.utcfromtimestamp(
                sighting_2.get("first_seen").timestamp()
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            parse(first_seen).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        self.assertEqual(
            datetime.datetime.utcfromtimestamp(
                sighting_2.get("last_seen").timestamp()
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            parse(last_seen).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def test_handle_target_countries(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        indicator = self.indicator

        attack_patterns = ["attack-pattern--76a389ac-1746-5f7f-a290-38f84e7d90e0"]
        markings = []
        observable_id = load_file("observable.json")["standard_id"]
        builder.handle_target_countries(
            attack_patterns=attack_patterns,
            markings=markings,
            observable_id=observable_id,
            indicator_id=indicator.id,
        )

        self.assertEqual(
            len(builder.bundle_objects), 30
        )  # 10 countries + 10 relationships + 10 sightings
        # Check countries
        self.assertEqual(builder.bundle_objects[0]["name"], "United States")
        self.assertEqual(builder.bundle_objects[9]["name"], "United Kingdom")
        # Check sightings
        self.assertEqual(
            builder.bundle_objects[10]["sighting_of_ref"],
            "indicator--94c598e8-9174-58e0-9731-316e18f26916",
        )
        self.assertEqual(
            builder.bundle_objects[10]["description"],
            "CrowdSec CTI sighting for country: GB",
        )
        # Check attack patterns relationships
        self.assertEqual(
            builder.bundle_objects[29]["source_ref"],
            "attack-pattern--76a389ac-1746-5f7f-a290-38f84e7d90e0",
        )

    def test_handle_target_countries_without_observable(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        indicator = self.indicator

        attack_patterns = ["attack-pattern--76a389ac-1746-5f7f-a290-38f84e7d90e0"]
        markings = []
        builder.handle_target_countries(
            attack_patterns=attack_patterns,
            markings=markings,
            observable_id=None,
            indicator_id=indicator.id,
        )

        self.assertEqual(
            len(builder.bundle_objects), 20
        )  # 10 countries + 10 relationships
        # Check countries
        self.assertEqual(builder.bundle_objects[0]["name"], "United States")
        self.assertEqual(builder.bundle_objects[8]["name"], "Japan")
        self.assertEqual(builder.bundle_objects[10]["name"], "Netherlands")
        # Check attack patterns relationships
        self.assertEqual(
            builder.bundle_objects[9]["source_ref"],
            "attack-pattern--76a389ac-1746-5f7f-a290-38f84e7d90e0",
        )

    def test_handle_target_countries_without_attack_patterns(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        indicator = self.indicator

        attack_patterns = []
        markings = []
        builder.handle_target_countries(
            attack_patterns=attack_patterns,
            markings=markings,
            observable_id=load_file("observable.json")["standard_id"],
            indicator_id=indicator.id,
        )

        self.assertEqual(len(builder.bundle_objects), 20)  # 10 countries + 10 sightings
        # Check countries
        self.assertEqual(builder.bundle_objects[0]["name"], "United States")
        self.assertEqual(builder.bundle_objects[8]["name"], "Japan")
        self.assertEqual(builder.bundle_objects[10]["name"], "Netherlands")
        # Check sightings
        self.assertEqual(
            builder.bundle_objects[9]["sighting_of_ref"],
            "indicator--94c598e8-9174-58e0-9731-316e18f26916",
        )
        self.assertEqual(
            builder.bundle_objects[9]["description"],
            "CrowdSec CTI sighting for country: JP",
        )
