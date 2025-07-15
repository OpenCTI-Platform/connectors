"""Module to test the STIX 2.1 SCO (STIX Cyber-observable Objects) models."""

from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

import pytest
from connector.src.stix.v21.models.ovs.account_type_ov_enums import AccountTypeOV
from connector.src.stix.v21.models.ovs.hashing_algorithm_ov_enums import HashAlgorithmOV
from connector.src.stix.v21.models.ovs.windows_registry_datatype_ov_enums import (
    WindowsRegistryDatatypeOV,
)
from connector.src.stix.v21.models.scos.directory_model import DirectoryModel
from connector.src.stix.v21.models.scos.domain_name_model import DomainNameModel
from connector.src.stix.v21.models.scos.email_address_model import EmailAddressModel
from connector.src.stix.v21.models.scos.file_model import FileModel
from connector.src.stix.v21.models.scos.ipv4_address_model import IPv4AddressModel
from connector.src.stix.v21.models.scos.ipv6_address_model import IPv6AddressModel
from connector.src.stix.v21.models.scos.mac_address_model import MACAddressModel
from connector.src.stix.v21.models.scos.mutex_model import MutexModel
from connector.src.stix.v21.models.scos.network_traffic_model import NetworkTrafficModel
from connector.src.stix.v21.models.scos.process_model import ProcessModel
from connector.src.stix.v21.models.scos.software_model import SoftwareModel
from connector.src.stix.v21.models.scos.url_model import URLModel
from connector.src.stix.v21.models.scos.user_account_model import UserAccountModel
from connector.src.stix.v21.models.scos.windows_registry_key_model import (
    WindowsRegistryKeyModel,
    WindowsRegistryValueModel,
)
from connector.src.stix.v21.models.scos.x509_certificate_model import (
    X509CertificateModel,
)
from pydantic import ValidationError

# =====================
# Fixtures
# =====================


@pytest.fixture
def now() -> datetime:
    """Fix timestamp for deterministic test results."""
    return datetime.now(timezone.utc)


@pytest.fixture
def common_sco_fields() -> Dict[str, Any]:
    """Create Common fields for all SCO objects."""
    return {
        "spec_version": "2.1",
        "object_marking_refs": [
            "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
        ],
        "defanged": False,
    }


# =====================
# Test Cases
# =====================

# Scenario: Testing File model


def test_file_basic_creation(common_sco_fields):
    """Test basic creation of a File model with minimal fields."""
    # Given: Basic data for a file
    file_id = f"file--{str(uuid4())}"
    file_data = {
        **common_sco_fields,
        "type": "file",
        "id": file_id,
        "name": "malware.exe",
    }

    # When: Creating a FileModel
    file_obj = FileModel(**file_data)

    # Then: The model should have expected values
    assert file_obj.type == "file"  # noqa: S101
    assert file_obj.id == file_id  # noqa: S101
    assert file_obj.name == "malware.exe"  # noqa: S101


def test_file_full_creation(common_sco_fields, now):
    """Test creation of a File model with all fields."""
    # Given: Complete data for a file
    file_id = f"file--{str(uuid4())}"
    file_data = {
        **common_sco_fields,
        "type": "file",
        "id": file_id,
        "name": "malware.exe",
        "size": 56320,
        "name_enc": "UTF-8",
        "magic_number_hex": "4D5A",
        "mime_type": "application/x-dosexec",
        "ctime": now,
        "mtime": now,
        "atime": now,
        "hashes": {
            HashAlgorithmOV.MD5: "B0D98FA45B242F9B08DE5CEF142DE91E",
            HashAlgorithmOV.SHA1: "84DE5CEF142DE91EB0D98FA45B242F9B08",
            HashAlgorithmOV.SHA256: "8E5CEF142DE91EB0D98FA45B242F9B084D3B0D98FA45B242F9B08DE5CEF142DE",
        },
    }

    # When: Creating a FileModel
    file_obj = FileModel(**file_data)

    # Then: The model should have all expected values
    assert file_obj.type == "file"  # noqa: S101
    assert file_obj.id == file_id  # noqa: S101
    assert file_obj.name == "malware.exe"  # noqa: S101
    assert file_obj.size == 56320  # noqa: S101
    assert file_obj.mime_type == "application/x-dosexec"  # noqa: S101
    assert (  # noqa: S101
        file_obj.hashes[HashAlgorithmOV.MD5] == "B0D98FA45B242F9B08DE5CEF142DE91E"
    )
    assert (  # noqa: S101
        file_obj.hashes[HashAlgorithmOV.SHA256]
        == "8E5CEF142DE91EB0D98FA45B242F9B084D3B0D98FA45B242F9B08DE5CEF142DE"
    )


def test_file_to_stix_object(common_sco_fields):
    """Test conversion of FileModel to a STIX object."""
    # Given: A FileModel
    file_id = f"file--{str(uuid4())}"
    file_obj = FileModel(
        **{
            **common_sco_fields,
            "type": "file",
            "id": file_id,
            "name": "malware.exe",
            "size": 56320,
        }
    )

    # When: Converting to a STIX object
    stix_obj = file_obj.to_stix2_object()

    # Then: The STIX object should have expected properties
    assert stix_obj.type == "file"  # noqa: S101
    assert stix_obj.id == file_id  # noqa: S101
    assert stix_obj.name == "malware.exe"  # noqa: S101
    assert stix_obj.size == 56320  # noqa: S101


# Scenario: Testing IP Address models


def test_ipv4_address_creation(common_sco_fields):
    """Test creation of an IPv4Address model."""
    # Given: Data for an IPv4 address
    ipv4_id = f"ipv4-addr--{str(uuid4())}"
    ipv4_data = {
        **common_sco_fields,
        "type": "ipv4-addr",
        "id": ipv4_id,
        "value": "192.168.1.1",
    }

    # When: Creating an IPv4AddressModel
    ipv4_obj = IPv4AddressModel(**ipv4_data)

    # Then: The model should have expected values
    assert ipv4_obj.type == "ipv4-addr"  # noqa: S101
    assert ipv4_obj.id == ipv4_id  # noqa: S101
    assert ipv4_obj.value == "192.168.1.1"  # noqa: S101


def test_ipv4_address_cidr_notation(common_sco_fields):
    """Test creation of an IPv4Address model with CIDR notation."""
    # Given: Data for an IPv4 address with CIDR notation
    ipv4_id = f"ipv4-addr--{str(uuid4())}"
    ipv4_data = {
        **common_sco_fields,
        "type": "ipv4-addr",
        "id": ipv4_id,
        "value": "192.168.0.0/16",
    }

    # When: Creating an IPv4AddressModel
    ipv4_obj = IPv4AddressModel(**ipv4_data)

    # Then: The model should have expected values
    assert ipv4_obj.value == "192.168.0.0/16"  # noqa: S101


def test_ipv6_address_creation(common_sco_fields):
    """Test creation of an IPv6Address model."""
    # Given: Data for an IPv6 address
    ipv6_id = f"ipv6-addr--{str(uuid4())}"
    ipv6_data = {
        **common_sco_fields,
        "type": "ipv6-addr",
        "id": ipv6_id,
        "value": "2001:db8::1",
    }

    # When: Creating an IPv6AddressModel
    ipv6_obj = IPv6AddressModel(**ipv6_data)

    # Then: The model should have expected values
    assert ipv6_obj.type == "ipv6-addr"  # noqa: S101
    assert ipv6_obj.id == ipv6_id  # noqa: S101
    assert ipv6_obj.value == "2001:db8::1"  # noqa: S101


# Scenario: Testing URL model


def test_url_creation(common_sco_fields):
    """Test creation of a URL model."""
    # Given: Data for a URL
    url_id = f"url--{str(uuid4())}"
    url_data = {
        **common_sco_fields,
        "type": "url",
        "id": url_id,
        "value": "https://example.com/malicious",
    }

    # When: Creating a URLModel
    url_obj = URLModel(**url_data)

    # Then: The model should have expected values
    assert url_obj.type == "url"  # noqa: S101
    assert url_obj.id == url_id  # noqa: S101
    assert url_obj.value == "https://example.com/malicious"  # noqa: S101


# Scenario: Testing Email Address model


def test_email_address_basic_creation(common_sco_fields):
    """Test basic creation of an EmailAddress model."""
    # Given: Basic data for an email address
    email_id = f"email-addr--{str(uuid4())}"
    email_data = {
        **common_sco_fields,
        "type": "email-addr",
        "id": email_id,
        "value": "john.doe@example.com",
    }

    # When: Creating an EmailAddressModel
    email_obj = EmailAddressModel(**email_data)

    # Then: The model should have expected values
    assert email_obj.type == "email-addr"  # noqa: S101
    assert email_obj.id == email_id  # noqa: S101
    assert email_obj.value == "john.doe@example.com"  # noqa: S101


def test_email_address_with_display_name(common_sco_fields):
    """Test creation of an EmailAddress model with display name."""
    # Given: Data for an email address with display name
    email_id = f"email-addr--{str(uuid4())}"
    email_data = {
        **common_sco_fields,
        "type": "email-addr",
        "id": email_id,
        "value": "john.doe@example.com",
        "display_name": "John Doe",
    }

    # When: Creating an EmailAddressModel
    email_obj = EmailAddressModel(**email_data)

    # Then: The model should have expected values
    assert email_obj.value == "john.doe@example.com"  # noqa: S101
    assert email_obj.display_name == "John Doe"  # noqa: S101


# Scenario: Testing Domain Name model


def test_domain_name_creation(common_sco_fields):
    """Test creation of a DomainName model."""
    # Given: Data for a domain name
    domain_id = f"domain-name--{str(uuid4())}"
    domain_data = {
        **common_sco_fields,
        "type": "domain-name",
        "id": domain_id,
        "value": "example.com",
    }

    # When: Creating a DomainNameModel
    domain_obj = DomainNameModel(**domain_data)

    # Then: The model should have expected values
    assert domain_obj.type == "domain-name"  # noqa: S101
    assert domain_obj.id == domain_id  # noqa: S101
    assert domain_obj.value == "example.com"  # noqa: S101


# Scenario: Testing MAC Address model


def test_mac_address_creation(common_sco_fields):
    """Test creation of a MACAddress model."""
    # Given: Data for a MAC address
    mac_id = f"mac-addr--{str(uuid4())}"
    mac_data = {
        **common_sco_fields,
        "type": "mac-addr",
        "id": mac_id,
        "value": "00:11:22:33:44:55",
    }

    # When: Creating a MACAddressModel
    mac_obj = MACAddressModel(**mac_data)

    # Then: The model should have expected values
    assert mac_obj.type == "mac-addr"  # noqa: S101
    assert mac_obj.id == mac_id  # noqa: S101
    assert mac_obj.value == "00:11:22:33:44:55"  # noqa: S101


def test_mac_address_validation(common_sco_fields):
    """Test validation of MAC addresses."""
    # Given: Data for an invalid MAC address (wrong format)
    mac_id = f"mac-addr--{str(uuid4())}"
    invalid_mac_data = {
        **common_sco_fields,
        "type": "mac-addr",
        "id": mac_id,
        "value": "00-11-22-33-44-55",
    }

    # When/Then: Creating a MACAddressModel should fail validation
    with pytest.raises(ValidationError) as excinfo:
        MACAddressModel(**invalid_mac_data)

    assert "colon-delimited" in str(excinfo.value)  # noqa: S101


# Scenario: Testing Mutex model


def test_mutex_creation(common_sco_fields):
    """Test creation of a Mutex model."""
    # Given: Data for a mutex
    mutex_id = f"mutex--{str(uuid4())}"
    mutex_data = {
        **common_sco_fields,
        "type": "mutex",
        "id": mutex_id,
        "name": "Global\\MalwareMutex",
    }

    # When: Creating a MutexModel
    mutex_obj = MutexModel(**mutex_data)

    # Then: The model should have expected values
    assert mutex_obj.type == "mutex"  # noqa: S101
    assert mutex_obj.id == mutex_id  # noqa: S101
    assert mutex_obj.name == "Global\\MalwareMutex"  # noqa: S101


# Scenario: Testing Windows Registry Key model


def test_windows_registry_value_creation():
    """Test creation of a WindowsRegistryValue model."""
    # Given: Data for a Windows registry value
    value_data = {
        "name": "DisplayName",
        "data": "Malware Service",
        "data_type": WindowsRegistryDatatypeOV.REG_SZ,
    }

    # When: Creating a WindowsRegistryValueModel
    value_obj = WindowsRegistryValueModel(**value_data)

    # Then: The model should have expected values
    assert value_obj.name == "DisplayName"  # noqa: S101
    assert value_obj.data == "Malware Service"  # noqa: S101
    assert value_obj.data_type == WindowsRegistryDatatypeOV.REG_SZ  # noqa: S101


def test_windows_registry_key_creation(common_sco_fields):
    """Test creation of a WindowsRegistryKey model."""
    # Given: Data for a Windows registry key with values
    registry_id = f"windows-registry-key--{str(uuid4())}"
    registry_data = {
        **common_sco_fields,
        "type": "windows-registry-key",
        "id": registry_id,
        "key": "HKEY_LOCAL_MACHINE\\Software\\Malware",
        "values": [
            {
                "name": "DisplayName",
                "data": "Malware Service",
                "data_type": WindowsRegistryDatatypeOV.REG_SZ,
            },
            {
                "name": "InstallPath",
                "data": "C:\\Program Files\\Malware",
                "data_type": WindowsRegistryDatatypeOV.REG_SZ,
            },
        ],
    }

    # When: Creating a WindowsRegistryKeyModel
    registry_obj = WindowsRegistryKeyModel(**registry_data)

    # Then: The model should have expected values
    assert registry_obj.type == "windows-registry-key"  # noqa: S101
    assert registry_obj.id == registry_id  # noqa: S101
    assert registry_obj.key == "HKEY_LOCAL_MACHINE\\Software\\Malware"  # noqa: S101
    assert len(registry_obj.values) == 2  # noqa: S101
    assert registry_obj.values[0].name == "DisplayName"  # noqa: S101
    assert registry_obj.values[1].data == "C:\\Program Files\\Malware"  # noqa: S101


# Scenario: Testing Network Traffic model


def test_network_traffic_basic_creation(common_sco_fields):
    """Test basic creation of a NetworkTraffic model."""
    # Given: Basic data for network traffic
    traffic_id = f"network-traffic--{str(uuid4())}"
    traffic_data = {
        **common_sco_fields,
        "type": "network-traffic",
        "id": traffic_id,
        "protocols": ["tcp"],
    }

    # When: Creating a NetworkTrafficModel
    traffic_obj = NetworkTrafficModel(**traffic_data)

    # Then: The model should have expected values
    assert traffic_obj.type == "network-traffic"  # noqa: S101
    assert traffic_obj.id == traffic_id  # noqa: S101
    assert "tcp" in traffic_obj.protocols  # noqa: S101


def test_network_traffic_full_creation(common_sco_fields, now):
    """Test full creation of a NetworkTraffic model."""
    # Given: Complete data for network traffic
    traffic_id = f"network-traffic--{str(uuid4())}"
    ipv4_id = f"ipv4-addr--{str(uuid4())}"
    traffic_data = {
        **common_sco_fields,
        "type": "network-traffic",
        "id": traffic_id,
        "protocols": ["tcp", "http"],
        "src_ref": ipv4_id,
        "src_port": 12345,
        "dst_port": 80,
        "start": now,
        "end": now,
        "src_byte_count": 1024,
        "dst_byte_count": 2048,
        "src_packets": 10,
        "dst_packets": 15,
    }

    # When: Creating a NetworkTrafficModel
    traffic_obj = NetworkTrafficModel(**traffic_data)

    # Then: The model should have expected values
    assert traffic_obj.protocols[0] == "tcp"  # noqa: S101
    assert traffic_obj.protocols[1] == "http"  # noqa: S101
    assert traffic_obj.src_ref == ipv4_id  # noqa: S101
    assert traffic_obj.src_port == 12345  # noqa: S101
    assert traffic_obj.dst_port == 80  # noqa: S101
    assert traffic_obj.src_byte_count == 1024  # noqa: S101
    assert traffic_obj.dst_byte_count == 2048  # noqa: S101
    assert traffic_obj.src_packets == 10  # noqa: S101
    assert traffic_obj.dst_packets == 15  # noqa: S101


# Scenario: Testing User Account model


def test_user_account_basic_creation(common_sco_fields):
    """Test basic creation of a UserAccount model."""
    # Given: Basic data for a user account
    account_id = f"user-account--{str(uuid4())}"
    account_data = {
        **common_sco_fields,
        "type": "user-account",
        "id": account_id,
        "user_id": "jdoe",
        "account_login": "jdoe",
    }

    # When: Creating a UserAccountModel
    account_obj = UserAccountModel(**account_data)

    # Then: The model should have expected values
    assert account_obj.type == "user-account"  # noqa: S101
    assert account_obj.id == account_id  # noqa: S101
    assert account_obj.user_id == "jdoe"  # noqa: S101
    assert account_obj.account_login == "jdoe"  # noqa: S101


def test_user_account_full_creation(common_sco_fields, now):
    """Test full creation of a UserAccount model."""
    # Given: Complete data for a user account
    account_id = f"user-account--{str(uuid4())}"
    account_data = {
        **common_sco_fields,
        "type": "user-account",
        "id": account_id,
        "user_id": "jdoe",
        "account_login": "jdoe",
        "account_type": AccountTypeOV.WINDOWS_LOCAL,
        "display_name": "John Doe",
        "is_service_account": False,
        "is_privileged": True,
        "can_escalate_privs": True,
        "is_disabled": False,
        "account_created": now,
        "account_expires": datetime(
            now.year + 1, now.month, now.day, tzinfo=timezone.utc
        ),
        "credential_last_changed": now,
        "account_first_login": now,
        "account_last_login": now,
    }

    # When: Creating a UserAccountModel
    account_obj = UserAccountModel(**account_data)

    # Then: The model should have expected values
    assert account_obj.account_login == "jdoe"  # noqa: S101
    assert account_obj.account_type == AccountTypeOV.WINDOWS_LOCAL  # noqa: S101
    assert account_obj.display_name == "John Doe"  # noqa: S101
    assert account_obj.is_privileged is True  # noqa: S101
    assert account_obj.can_escalate_privs is True  # noqa: S101
    assert account_obj.is_disabled is False  # noqa: S101
    assert account_obj.account_created == now  # noqa: S101


# Scenario: Testing Software model


def test_software_basic_creation(common_sco_fields):
    """Test basic creation of a Software model."""
    # Given: Basic data for software
    software_id = f"software--{str(uuid4())}"
    software_data = {
        **common_sco_fields,
        "type": "software",
        "id": software_id,
        "name": "Vulnerable Web Server",
    }

    # When: Creating a SoftwareModel
    software_obj = SoftwareModel(**software_data)

    # Then: The model should have expected values
    assert software_obj.type == "software"  # noqa: S101
    assert software_obj.id == software_id  # noqa: S101
    assert software_obj.name == "Vulnerable Web Server"  # noqa: S101


def test_software_full_creation(common_sco_fields):
    """Test full creation of a Software model."""
    # Given: Complete data for software
    software_id = f"software--{str(uuid4())}"
    software_data = {
        **common_sco_fields,
        "type": "software",
        "id": software_id,
        "name": "Vulnerable Web Server",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "vendor": "Apache",
        "version": "2.4.49",
        "languages": ["en", "fr", "de"],
    }

    # When: Creating a SoftwareModel
    software_obj = SoftwareModel(**software_data)

    # Then: The model should have expected values
    assert software_obj.name == "Vulnerable Web Server"  # noqa: S101
    assert (  # noqa: S101
        software_obj.cpe == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    )
    assert software_obj.vendor == "Apache"  # noqa: S101
    assert software_obj.version == "2.4.49"  # noqa: S101
    assert "en" in software_obj.languages  # noqa: S101
    assert "fr" in software_obj.languages  # noqa: S101


# Scenario: Testing X509Certificate model


def test_x509_certificate_basic_creation(common_sco_fields):
    """Test basic creation of a X509Certificate model."""
    # Given: Basic data for a certificate
    cert_id = f"x509-certificate--{str(uuid4())}"
    cert_data = {
        **common_sco_fields,
        "type": "x509-certificate",
        "id": cert_id,
        "hashes": {
            HashAlgorithmOV.SHA256: "8E5CEF142DE91EB0D98FA45B242F9B084D3B0D98FA45B242F9B08DE5CEF142DE",
        },
    }

    # When: Creating a X509CertificateModel
    cert_obj = X509CertificateModel(**cert_data)

    # Then: The model should have expected values
    assert cert_obj.type == "x509-certificate"  # noqa: S101
    assert cert_obj.id == cert_id  # noqa: S101
    assert (  # noqa: S101
        cert_obj.hashes[HashAlgorithmOV.SHA256]
        == "8E5CEF142DE91EB0D98FA45B242F9B084D3B0D98FA45B242F9B08DE5CEF142DE"
    )


def test_x509_certificate_full_creation(common_sco_fields, now):
    """Test full creation of a X509Certificate model."""
    # Given: Complete data for a certificate
    cert_id = f"x509-certificate--{str(uuid4())}"
    cert_data = {
        **common_sco_fields,
        "type": "x509-certificate",
        "id": cert_id,
        "is_self_signed": False,
        "hashes": {
            HashAlgorithmOV.SHA256: "8E5CEF142DE91EB0D98FA45B242F9B084D3B0D98FA45B242F9B08DE5CEF142DE",
        },
        "version": "3",
        "serial_number": "01:23:45:67:89:AB:CD:EF",
        "signature_algorithm": "sha256WithRSAEncryption",
        "issuer": "CN=Example CA, O=Example Corp, C=US",
        "validity_not_before": now,
        "validity_not_after": datetime(
            now.year + 1, now.month, now.day, tzinfo=timezone.utc
        ),
        "subject": "CN=example.com, O=Example Corp, C=US",
        "subject_public_key_algorithm": "rsaEncryption",
        "subject_public_key_modulus": "00:a1:b2:c3:...",
        "subject_public_key_exponent": 65537,
    }

    # When: Creating a X509CertificateModel
    cert_obj = X509CertificateModel(**cert_data)

    # Then: The model should have expected values
    assert cert_obj.is_self_signed is False  # noqa: S101
    assert cert_obj.version == "3"  # noqa: S101
    assert cert_obj.serial_number == "01:23:45:67:89:AB:CD:EF"  # noqa: S101
    assert cert_obj.signature_algorithm == "sha256WithRSAEncryption"  # noqa: S101
    assert cert_obj.issuer == "CN=Example CA, O=Example Corp, C=US"  # noqa: S101
    assert cert_obj.subject == "CN=example.com, O=Example Corp, C=US"  # noqa: S101
    assert cert_obj.subject_public_key_exponent == 65537  # noqa: S101


# Scenario: Testing models that reference other models


def test_directory_model_with_contains_refs(common_sco_fields):
    """Test a Directory model with references to contained files."""
    # Given: Data for a directory with file references
    dir_id = f"directory--{str(uuid4())}"
    file_id1 = f"file--{str(uuid4())}"
    file_id2 = f"file--{str(uuid4())}"

    dir_data = {
        **common_sco_fields,
        "type": "directory",
        "id": dir_id,
        "path": "/var/www/malware",
        "contains_refs": [file_id1, file_id2],
    }

    # When: Creating a DirectoryModel
    dir_obj = DirectoryModel(**dir_data)

    # Then: The model should have expected values
    assert dir_obj.type == "directory"  # noqa: S101
    assert dir_obj.id == dir_id  # noqa: S101
    assert dir_obj.path == "/var/www/malware"  # noqa: S101
    assert file_id1 in dir_obj.contains_refs  # noqa: S101
    assert file_id2 in dir_obj.contains_refs  # noqa: S101


def test_process_model_with_references(common_sco_fields, now):
    """Test a Process model with references to other objects."""
    # Given: Data for a process with references
    process_id = f"process--{str(uuid4())}"
    image_ref = f"file--{str(uuid4())}"
    parent_ref = f"process--{str(uuid4())}"

    process_data = {
        **common_sco_fields,
        "type": "process",
        "id": process_id,
        "pid": 1234,
        "created_time": now,
        "command_line": "/usr/bin/malware --stealth",
        "image_ref": image_ref,
        "parent_ref": parent_ref,
    }

    # When: Creating a ProcessModel
    process_obj = ProcessModel(**process_data)

    # Then: The model should have expected values
    assert process_obj.type == "process"  # noqa: S101
    assert process_obj.id == process_id  # noqa: S101
    assert process_obj.pid == 1234  # noqa: S101
    assert process_obj.command_line == "/usr/bin/malware --stealth"  # noqa: S101
    assert process_obj.image_ref == image_ref  # noqa: S101
    assert process_obj.parent_ref == parent_ref  # noqa: S101
