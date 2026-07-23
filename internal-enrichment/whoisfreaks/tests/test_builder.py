import pytest
import stix2
from whoisfreaks.src.builder import WhoisFreaksStixBuilder


@pytest.fixture
def builder():
    return WhoisFreaksStixBuilder()


def test_builder_init(builder):
    assert builder.author.name == "WhoisFreaks"
    assert builder.author.identity_class == "organization"


def test_is_privacy_protected():
    assert WhoisFreaksStixBuilder.is_privacy_protected("WHOISGuard Protected") is True
    assert WhoisFreaksStixBuilder.is_privacy_protected("REDACTED FOR PRIVACY") is True
    assert WhoisFreaksStixBuilder.is_privacy_protected("John Doe") is False


def test_is_ip_address():
    assert WhoisFreaksStixBuilder.is_ip_address("1.2.3.4") is True
    assert WhoisFreaksStixBuilder.is_ip_address("2001:db8::1") is True
    assert WhoisFreaksStixBuilder.is_ip_address("example.com") is False
    assert WhoisFreaksStixBuilder.is_ip_address("  1.2.3.4  ") is True


def test_build_whois_bundle_empty(builder):
    assert builder.build_whois_bundle("example.com", {}) is None


def test_build_whois_bundle_full(builder):
    whois_data = {
        "registrar_name": "GoDaddy.com, LLC",
        "registrant": {"name": "John Doe", "company": "Example Inc."},
        "name_servers": ["ns1.example.com", "ns2.example.com"],
    }
    bundle = builder.build_whois_bundle("example.com", whois_data)
    assert isinstance(bundle, stix2.Bundle)

    # Extract objects from the bundle
    objects = {obj["type"]: obj for obj in bundle.objects}
    assert "identity" in objects
    assert "domain-name" in objects

    # Check registrar and registrant identities
    identities = [obj for obj in bundle.objects if obj["type"] == "identity"]
    names = [id_obj.name for id_obj in identities]
    assert "WhoisFreaks" in names
    assert "GoDaddy.com, LLC" in names
    assert "John Doe" in names

    # Check relationships
    relationships = [obj for obj in bundle.objects if obj["type"] == "relationship"]
    rel_types = [rel.relationship_type for rel in relationships]
    assert "registered-by" in rel_types
    assert "owned-by" in rel_types
    assert "related-to" in rel_types


def test_build_whois_bundle_privacy_protected(builder):
    whois_data = {
        "registrar_name": "GoDaddy.com, LLC",
        "registrant": {"name": "REDACTED FOR PRIVACY", "company": "Privacy Inc."},
    }
    bundle = builder.build_whois_bundle("example.com", whois_data)
    assert isinstance(bundle, stix2.Bundle)

    identities = [obj for obj in bundle.objects if obj["type"] == "identity"]
    names = [id_obj.name for id_obj in identities]
    assert "WhoisFreaks" in names
    assert "GoDaddy.com, LLC" in names
    # REDACTED FOR PRIVACY should be filtered out
    assert "REDACTED FOR PRIVACY" not in names

    relationships = [obj for obj in bundle.objects if obj["type"] == "relationship"]
    rel_types = [rel.relationship_type for rel in relationships]
    assert "registered-by" in rel_types
    assert "owned-by" not in rel_types


def test_build_dns_bundle_empty(builder):
    assert builder.build_dns_bundle("example.com", {}) is None


def test_build_dns_bundle_ipv4_source(builder):
    dns_data = {
        "dns_records": [
            {"type": "A", "address": "1.2.3.4"},
            {"type": "AAAA", "address": "2001:db8::1"},
            {"type": "CNAME", "value": "alias.example.com"},
            {"type": "MX", "value": "mail.example.com"},
            {"type": "NS", "value": "ns.example.com"},
            {
                "type": "TXT",
                "value": "v=spf1 ...",
            },  # Unsupported type, should be skipped
        ]
    }
    bundle = builder.build_dns_bundle("1.2.3.4", dns_data)
    assert isinstance(bundle, stix2.Bundle)

    # Check source observable
    ipv4s = [obj for obj in bundle.objects if obj["type"] == "ipv4-addr"]
    assert len(ipv4s) == 2  # The source "1.2.3.4" and the record "1.2.3.4"

    ipv6s = [obj for obj in bundle.objects if obj["type"] == "ipv6-addr"]
    assert len(ipv6s) == 1
    assert ipv6s[0].value == "2001:db8::1"

    domains = [obj for obj in bundle.objects if obj["type"] == "domain-name"]
    domain_vals = [d.value for d in domains]
    assert "alias.example.com" in domain_vals
    assert "mail.example.com" in domain_vals
    assert "ns.example.com" in domain_vals

    relationships = [obj for obj in bundle.objects if obj["type"] == "relationship"]
    rel_types = [rel.relationship_type for rel in relationships]
    assert "resolves-to" in rel_types
    assert "related-to" in rel_types


def test_build_dns_bundle_historical(builder):
    dns_data = {
        "historicalDnsRecords": [
            {"dnsRecords": [{"dnsType": "A", "address": "5.6.7.8"}]}
        ]
    }
    bundle = builder.build_dns_bundle("example.com", dns_data)
    assert isinstance(bundle, stix2.Bundle)

    ipv4s = [obj for obj in bundle.objects if obj["type"] == "ipv4-addr"]
    assert len(ipv4s) == 1
    assert ipv4s[0].value == "5.6.7.8"


def test_build_ssl_bundle_empty(builder):
    assert builder.build_ssl_bundle("example.com", {}) is None


def test_build_ssl_bundle_success(builder):
    ssl_data = {
        "sslCertificates": [
            {
                "certificate_info": {
                    "issuer_dn": "CN=DigiCert, O=DigiCert Inc",
                    "subject_dn": "CN=example.com, O=Example Org",
                    "serial_number": "1234567890",
                }
            }
        ]
    }
    bundle = builder.build_ssl_bundle("example.com", ssl_data)
    assert isinstance(bundle, stix2.Bundle)

    certs = [obj for obj in bundle.objects if obj["type"] == "x509-certificate"]
    assert len(certs) == 1
    assert certs[0].issuer == "CN=DigiCert, O=DigiCert Inc"
    assert certs[0].subject == "CN=example.com, O=Example Org"
    assert certs[0].serial_number == "1234567890"

    relationships = [obj for obj in bundle.objects if obj["type"] == "relationship"]
    assert len(relationships) == 1
    assert relationships[0].relationship_type == "related-to"


def test_build_ip_geolocation_bundle_empty(builder):
    assert builder.build_ip_geolocation_bundle("1.2.3.4", {}) is None


def test_build_ip_geolocation_bundle_success(builder):
    geo_data = {
        "location": {
            "country_name": "United States",
            "country_code": "US",
            "city": "Austin",
            "latitude": "30.2672",
            "longitude": "-97.7431",
        }
    }
    bundle = builder.build_ip_geolocation_bundle("1.2.3.4", geo_data)
    assert isinstance(bundle, stix2.Bundle)

    locations = [obj for obj in bundle.objects if obj["type"] == "location"]
    assert len(locations) == 1
    assert locations[0].name == "Austin"
    assert locations[0].country == "United States"
    assert locations[0].city == "Austin"
    assert locations[0].latitude == 30.2672
    assert locations[0].longitude == -97.7431

    relationships = [obj for obj in bundle.objects if obj["type"] == "relationship"]
    assert len(relationships) == 1
    assert relationships[0].relationship_type == "located-at"


def test_build_subdomains_bundle_empty(builder):
    assert builder.build_subdomains_bundle("example.com", {}) is None


def test_build_subdomains_bundle_success(builder):
    sub_data = {
        "subdomains": [
            {"subdomain": "www.example.com"},
            {"subdomain": "api.example.com"},
        ]
    }
    bundle = builder.build_subdomains_bundle("example.com", sub_data)
    assert isinstance(bundle, stix2.Bundle)

    domains = [obj for obj in bundle.objects if obj["type"] == "domain-name"]
    domain_vals = [d.value for d in domains]
    assert "example.com" in domain_vals
    assert "www.example.com" in domain_vals
    assert "api.example.com" in domain_vals

    relationships = [obj for obj in bundle.objects if obj["type"] == "relationship"]
    assert len(relationships) == 2
    assert relationships[0].relationship_type == "related-to"


def test_build_ip_reputation_bundle_empty(builder):
    assert builder.build_ip_reputation_bundle("1.2.3.4", {}) is None


def test_build_ip_reputation_bundle_success(builder):
    rep_data = {"security": {"threat_score": 85}}
    bundle = builder.build_ip_reputation_bundle("1.2.3.4", rep_data)
    assert isinstance(bundle, stix2.Bundle)

    notes = [obj for obj in bundle.objects if obj["type"] == "note"]
    assert len(notes) == 1
    assert "Threat Score: 85" in notes[0].abstract
    assert "Threat Score: 85" in notes[0].content


def test_build_domain_reputation_bundle_empty(builder):
    assert builder.build_domain_reputation_bundle("example.com", {}) is None


def test_build_domain_reputation_bundle_success(builder):
    rep_data = {"reputation_score": 45}
    bundle = builder.build_domain_reputation_bundle("example.com", rep_data)
    assert isinstance(bundle, stix2.Bundle)

    notes = [obj for obj in bundle.objects if obj["type"] == "note"]
    assert len(notes) == 1
    assert "Score: 45" in notes[0].abstract
    assert "Score: 45" in notes[0].content
