"""Tests for ConverterToStix."""

import stix2
from connector.converter_to_stix import ConverterToStix
from connectors_sdk.models.enums import TLPLevel


class TestConverterToStixInit:
    """Test ConverterToStix initialization."""

    def test_init_with_amber(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        assert converter.tlp_marking == stix2.TLP_AMBER
        assert converter.author is not None
        assert converter.author.name == "Sublime"

    def test_init_with_red(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.RED)
        assert converter.tlp_marking == stix2.TLP_RED

    def test_init_with_green(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.GREEN)
        assert converter.tlp_marking == stix2.TLP_GREEN

    def test_init_with_clear(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.CLEAR)
        assert converter.tlp_marking == stix2.TLP_WHITE

    def test_init_with_amber_strict(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER_STRICT)
        assert converter.tlp_marking.id is not None
        assert "AMBER+STRICT" in converter.tlp_marking.x_opencti_definition


class TestCreateAuthor:
    """Test author creation."""

    def test_create_author(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        author = converter.author
        assert author.type == "identity"
        assert author.name == "Sublime"
        assert author.identity_class == "organization"
        assert author.description == "Email Security Platform"

    def test_author_has_deterministic_id(self, mock_helper):
        c1 = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        c2 = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        assert c1.author.id == c2.author.id


class TestCreateDomainName:
    """Test domain name observable creation."""

    def test_create_domain_name(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        domain = converter.create_domain_name("example.com")
        assert domain.type == "domain-name"
        assert domain.value == "example.com"
        assert stix2.TLP_AMBER.id in domain.object_marking_refs

    def test_create_domain_name_has_author_ref(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        domain = converter.create_domain_name("test.org")
        assert domain.x_opencti_created_by_ref == converter.author["id"]


class TestCreateEmailAddress:
    """Test email address observable creation."""

    def test_create_email_address(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        email = converter.create_email_address("user@example.com")
        assert email.type == "email-addr"
        assert email.value == "user@example.com"
        assert stix2.TLP_AMBER.id in email.object_marking_refs

    def test_create_email_address_tlp_red(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.RED)
        email = converter.create_email_address("user@example.com")
        assert stix2.TLP_RED.id in email.object_marking_refs


class TestCreateFile:
    """Test file observable creation."""

    def test_create_file_with_hash(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        sha256 = "a" * 64  # valid SHA-256 hash
        file_obj = converter.create_file(
            hashes={"SHA-256": sha256},
            file_name="malware.exe",
            file_size=1024,
            mime_type="application/x-executable",
        )
        assert file_obj.type == "file"
        assert file_obj.hashes["SHA-256"] == sha256
        assert file_obj.name == "malware.exe"
        assert file_obj.size == 1024
        assert file_obj.mime_type == "application/x-executable"

    def test_create_file_with_none_fields(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        md5 = "d41d8cd98f00b204e9800998ecf8427e"  # valid MD5 hash
        file_obj = converter.create_file(
            hashes={"MD5": md5},
            file_name=None,
            file_size=None,
            mime_type=None,
        )
        assert file_obj.type == "file"
        assert file_obj.hashes["MD5"] == md5


class TestCreateIncident:
    """Test incident creation."""

    def test_create_incident(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        incident = converter.create_incident(
            name="Test Incident",
            created_timestamp="2026-01-15T10:00:00Z",
            description="A phishing incident",
            group_id="group-123",
            incident_type="phishing",
            url="https://sublime.security/messages/group-123",
            severity="high",
        )
        assert incident.type == "incident"
        assert incident.name == "Test Incident"
        assert incident.description == "A phishing incident"
        assert incident.created.year == 2026
        assert incident.created.month == 1
        assert incident.created.day == 15
        assert incident.severity == "high"
        assert stix2.TLP_AMBER.id in incident.object_marking_refs

    def test_create_incident_deterministic_id(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        i1 = converter.create_incident(
            name="Incident",
            created_timestamp="2026-01-01T00:00:00Z",
            description="desc",
            group_id="g1",
            incident_type="phishing",
            url="http://example.com",
            severity="high",
        )
        i2 = converter.create_incident(
            name="Incident",
            created_timestamp="2026-01-01T00:00:00Z",
            description="desc",
            group_id="g1",
            incident_type="phishing",
            url="http://example.com",
            severity="high",
        )
        assert i1.id == i2.id

    def test_create_incident_external_reference(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        incident = converter.create_incident(
            name="Test",
            created_timestamp="2026-01-15T10:00:00Z",
            description="desc",
            group_id="abc-123",
            incident_type="phishing",
            url="https://sublime.security/messages/abc-123",
            severity="high",
        )
        ext_ref = incident.external_references[0]
        assert ext_ref.source_name == "Sublime"
        assert ext_ref.external_id == "abc-123"
        assert "abc-123" in ext_ref.url


class TestCreateIndicator:
    """Test indicator creation."""

    def test_create_indicator(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        pattern = "[email-addr:value = 'evil@phish.com']"
        indicator = converter.create_indicator(pattern=pattern)
        assert indicator.type == "indicator"
        assert indicator.pattern == pattern
        assert indicator.pattern_type == "stix"
        assert "malicious-activity" in indicator.labels

    def test_create_indicator_deterministic_id(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        pattern = "[ipv4-addr:value = '1.2.3.4']"
        ind1 = converter.create_indicator(pattern=pattern)
        ind2 = converter.create_indicator(pattern=pattern)
        assert ind1.id == ind2.id


class TestCreateIpAddress:
    """Test IP address observable creation."""

    def test_create_ipv4(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        ip = converter.create_ip_address("192.168.1.1")
        assert ip.type == "ipv4-addr"
        assert ip.value == "192.168.1.1"
        assert stix2.TLP_AMBER.id in ip.object_marking_refs

    def test_create_ipv6(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        ip = converter.create_ip_address("2001:db8::1")
        assert ip.type == "ipv6-addr"
        assert ip.value == "2001:db8::1"

    def test_create_invalid_ip_returns_none(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        result = converter.create_ip_address("not-an-ip")
        assert result is None


class TestCreateRelationship:
    """Test relationship creation."""

    def test_create_relationship(self, mock_helper):
        from pycti import Incident, Indicator

        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        source_id = Indicator.generate_id("[ipv4-addr:value = '1.2.3.4']")
        target_id = Incident.generate_id("Test", "2026-01-01T00:00:00Z")
        rel = converter.create_relationship(
            source_id=source_id,
            target_id=target_id,
            relationship_type="indicates",
        )
        assert rel.type == "relationship"
        assert rel.relationship_type == "indicates"
        assert rel.source_ref == source_id
        assert rel.target_ref == target_id

    def test_create_relationship_deterministic_id(self, mock_helper):
        from pycti import Incident, Indicator

        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        source_id = Indicator.generate_id("[ipv4-addr:value = '1.2.3.4']")
        target_id = Incident.generate_id("Test", "2026-01-01T00:00:00Z")
        r1 = converter.create_relationship(source_id, target_id, "indicates")
        r2 = converter.create_relationship(source_id, target_id, "indicates")
        assert r1.id == r2.id


class TestCreateUrl:
    """Test URL observable creation."""

    def test_create_url(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        url = converter.create_url("https://evil.com/phish")
        assert url.type == "url"
        assert url.value == "https://evil.com/phish"
        assert stix2.TLP_AMBER.id in url.object_marking_refs


class TestCreateCaseIncident:
    """Test case incident creation."""

    def test_create_case_incident(self, mock_helper):
        from pycti import Incident

        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        incident_id = Incident.generate_id("Test", "2026-01-15T10:00:00Z")
        case = converter.create_case_incident(
            name="Test Case",
            created="2026-01-15T10:00:00Z",
            description="Test description",
            object_refs=[incident_id],
            severity="high",
            priority="P1",
        )
        assert case.type == "case-incident"
        assert case.name == "Test Case"
        assert case.severity == "high"
        assert case.priority == "P1"
        assert stix2.TLP_AMBER.id in case.object_marking_refs

    def test_create_case_incident_deterministic_id(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        c1 = converter.create_case_incident(name="Case", created="2026-01-01T00:00:00Z")
        c2 = converter.create_case_incident(name="Case", created="2026-01-01T00:00:00Z")
        assert c1.id == c2.id

    def test_create_case_incident_without_optional_fields(self, mock_helper):
        converter = ConverterToStix(mock_helper, tlp_level=TLPLevel.AMBER)
        case = converter.create_case_incident(
            name="Minimal Case", created="2026-01-01T00:00:00Z"
        )
        assert case.type == "case-incident"
        assert case.name == "Minimal Case"
