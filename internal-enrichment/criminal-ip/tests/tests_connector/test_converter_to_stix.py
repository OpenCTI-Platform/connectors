from unittest.mock import MagicMock

from connector.converter_to_stix import ConverterToStix

IPV4_STIX_ID = "ipv4-addr--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"


class TestConverterToStix:
    """Tests for ConverterToStix methods."""

    def setup_method(self):
        self.helper = MagicMock()
        self.converter = ConverterToStix(helper=self.helper)

    def test_create_author(self):
        author = self.converter.create_author()
        stix_obj = author.to_stix2_object()
        assert stix_obj["type"] == "identity"
        assert stix_obj["name"] == "Criminal IP"

    def test_create_tlp_marking_clear(self):
        tlp = self.converter.create_tlp_marking("clear")
        stix_obj = tlp.to_stix2_object()
        assert stix_obj["type"] == "marking-definition"

    def test_create_tlp_marking_amber(self):
        tlp = self.converter.create_tlp_marking("amber")
        stix_obj = tlp.to_stix2_object()
        assert stix_obj["type"] == "marking-definition"
        assert stix_obj["name"] == "TLP:AMBER"

    def test_create_autonomous_system(self):
        asn = self.converter.create_autonomous_system(number="15169", name="GOOGLE")
        stix_obj = asn.to_stix2_object()
        assert stix_obj["type"] == "autonomous-system"
        assert stix_obj["number"] == 15169
        assert stix_obj["name"] == "GOOGLE"

    def test_create_city(self):
        city = self.converter.create_city(
            name="Paris", latitude=48.8566, longitude=2.3522
        )
        stix_obj = city.to_stix2_object()
        assert stix_obj["type"] == "location"
        assert stix_obj["name"] == "Paris"
        assert stix_obj["latitude"] == 48.8566
        assert stix_obj["longitude"] == 2.3522

    def test_create_country(self):
        country = self.converter.create_country(name="FR")
        stix_obj = country.to_stix2_object()
        assert stix_obj["type"] == "location"
        assert stix_obj["name"] == "FR"

    def test_create_indicator(self):
        indicator = self.converter.create_indicator(
            name="Test Indicator",
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="stix",
            description="Test description",
            labels=["malicious"],
        )
        stix_obj = indicator.to_stix2_object()
        assert stix_obj["type"] == "indicator"
        assert stix_obj["name"] == "Test Indicator"
        assert stix_obj["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
        assert stix_obj["pattern_type"] == "stix"
        assert "malicious" in stix_obj["labels"]

    def test_create_ipv4(self):
        ipv4 = self.converter.create_ipv4(ip="192.168.1.1")
        stix_obj = ipv4.to_stix2_object()
        assert stix_obj["type"] == "ipv4-addr"
        assert stix_obj["value"] == "192.168.1.1"

    def test_create_reference(self):
        ref = self.converter.create_reference(obs_id=IPV4_STIX_ID)
        assert ref.id == IPV4_STIX_ID

    def test_create_relationship(self):
        ipv4 = self.converter.create_ipv4(ip="1.2.3.4")
        asn = self.converter.create_autonomous_system(number="15169", name="GOOGLE")
        rel = self.converter.create_relationship(
            relationship_type="belongs-to",
            source_obj=ipv4,
            target_obj=asn,
        )
        stix_obj = rel.to_stix2_object()
        assert stix_obj["type"] == "relationship"
        assert stix_obj["relationship_type"] == "belongs-to"

    def test_create_vulnerability(self):
        vuln = self.converter.create_vulnerability(
            name="CVE-2021-44228", description="Log4Shell vulnerability"
        )
        stix_obj = vuln.to_stix2_object()
        assert stix_obj["type"] == "vulnerability"
        assert stix_obj["name"] == "CVE-2021-44228"

    def test_create_region(self):
        region = self.converter.create_region(name="Europe")
        stix_obj = region.to_stix2_object()
        assert stix_obj["type"] == "location"
        assert stix_obj["name"] == "Europe"
