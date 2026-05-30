from unittest.mock import MagicMock

from connector.converter_to_stix import ConverterToStix
from connector.use_cases.enrich_ipv4 import Ipv4Enricher

IPV4_STIX_ID = "ipv4-addr--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"


class TestIpv4Enricher:
    """Tests for IPv4 enrichment use case."""

    def setup_method(self):
        self.helper = MagicMock()
        self.client = MagicMock()
        self.converter = ConverterToStix(helper=self.helper)
        self.enricher = Ipv4Enricher(
            connector_logger=self.helper.connector_logger,
            client=self.client,
            converter_to_stix=self.converter,
        )

    def test_process_ipv4_enrichment_no_data(self):
        """Should return empty list when API returns no data."""
        self.client.get_data.return_value = None
        observable = {"id": IPV4_STIX_ID, "value": "1.2.3.4", "type": "ipv4-addr"}
        result = self.enricher.process_ipv4_enrichment(observable)
        assert result == []

    def test_process_ipv4_enrichment_no_ip_in_response(self):
        """Should return empty list when response has no ip field."""
        self.client.get_data.return_value = {"status": 200}
        observable = {"id": IPV4_STIX_ID, "value": "1.2.3.4", "type": "ipv4-addr"}
        result = self.enricher.process_ipv4_enrichment(observable)
        assert result == []

    def test_process_ipv4_enrichment_basic(self):
        """Should produce STIX objects for a basic enrichment response."""
        ip_data = {
            "ip": "1.2.3.4",
            "issues": {"is_tor": True, "is_proxy": False},
            "ip_category": {"data": [{"type": "scanner"}]},
            "score": {"inbound": "Critical", "outbound": "Moderate"},
            "whois": {"data": []},
            "vulnerability": {"data": []},
        }
        self.client.get_data.side_effect = [
            ip_data,  # /v1/asset/ip/report
            {
                "is_malicious": True,
                "is_anonymous_vpn": False,
                "can_remote_access": False,
                "is_vpn": False,
            },  # malicious-info
        ]

        observable = {"id": IPV4_STIX_ID, "value": "1.2.3.4", "type": "ipv4-addr"}
        result = self.enricher.process_ipv4_enrichment(observable)

        # Should contain at least: author, tlp_clear, tlp_amber, indicator, relationship
        assert len(result) >= 5
        types = [obj["type"] for obj in result]
        assert "indicator" in types
        assert "relationship" in types

    def test_process_ipv4_enrichment_with_whois_and_vulnerabilities(self):
        """Should produce AS, location, and vulnerability STIX objects."""
        ip_data = {
            "ip": "8.8.8.8",
            "issues": {},
            "ip_category": {"data": []},
            "score": {"inbound": "Safe", "outbound": "Safe"},
            "whois": {
                "data": [
                    {
                        "as_no": "15169",
                        "as_name": "GOOGLE",
                        "org_country_code": "US",
                        "region": None,
                        "city": "Mountain View",
                        "latitude": 37.386,
                        "longitude": -122.0838,
                    }
                ]
            },
            "vulnerability": {
                "data": [
                    {
                        "cve_id": "CVE-2021-44228",
                        "cve_description": "Log4Shell",
                    }
                ]
            },
        }
        self.client.get_data.side_effect = [
            ip_data,  # /v1/asset/ip/report
            None,  # malicious-info returns None
        ]

        observable = {"id": IPV4_STIX_ID, "value": "8.8.8.8", "type": "ipv4-addr"}
        result = self.enricher.process_ipv4_enrichment(observable)

        types = [obj["type"] for obj in result]
        assert "autonomous-system" in types
        assert "location" in types
        assert "vulnerability" in types
        # Should have relationships for belongs-to, located-at, indicates
        relationships = [obj for obj in result if obj["type"] == "relationship"]
        rel_types = [r["relationship_type"] for r in relationships]
        assert "belongs-to" in rel_types
        assert "located-at" in rel_types
        assert "indicates" in rel_types

    def test_process_ipv4_enrichment_labels_from_issues(self):
        """Should build labels from issues flags."""
        ip_data = {
            "ip": "10.0.0.1",
            "issues": {"is_tor": True, "is_vpn": True, "is_proxy": False},
            "ip_category": {"data": []},
            "score": {"inbound": "Low", "outbound": "Low"},
            "whois": {"data": []},
            "vulnerability": {"data": []},
        }
        self.client.get_data.side_effect = [
            ip_data,
            None,
        ]

        observable = {"id": IPV4_STIX_ID, "value": "10.0.0.1", "type": "ipv4-addr"}
        result = self.enricher.process_ipv4_enrichment(observable)

        # Find the indicator and check labels
        indicators = [obj for obj in result if obj["type"] == "indicator"]
        assert len(indicators) == 1
        labels = indicators[0]["labels"]
        assert "TOR" in labels
        assert "VPN" in labels
        assert "PROXY" not in labels

    def test_process_ipv4_enrichment_whois_region_fallback(self):
        """Should fallback to region when city is not available."""
        ip_data = {
            "ip": "10.0.0.2",
            "issues": {},
            "ip_category": {"data": []},
            "score": {"inbound": "Low", "outbound": "Low"},
            "whois": {
                "data": [
                    {
                        "as_no": None,
                        "as_name": None,
                        "org_country_code": "DE",
                        "region": "Europe",
                        "city": None,
                        "latitude": None,
                        "longitude": None,
                    }
                ]
            },
            "vulnerability": {"data": []},
        }
        self.client.get_data.side_effect = [ip_data, None]

        observable = {"id": IPV4_STIX_ID, "value": "10.0.0.2", "type": "ipv4-addr"}
        result = self.enricher.process_ipv4_enrichment(observable)

        locations = [obj for obj in result if obj["type"] == "location"]
        assert len(locations) == 1
        assert locations[0]["name"] == "Europe"
