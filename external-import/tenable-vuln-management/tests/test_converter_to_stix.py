import json
import sys
from pathlib import Path

import pytest

sys.path.append(str((Path(__file__).resolve().parent.parent / "src")))

from unittest.mock import MagicMock

from tenable_vuln_management.converter_to_stix import (
    ConverterToStix,
    tlp_marking_definition_handler,
)
from tenable_vuln_management.models.opencti import (
    HasRelationship,
    System,
    Vulnerability,
)
from tenable_vuln_management.models.tenable import Asset, Plugin, VulnerabilityFinding

BASE_DIR = Path(__file__).parent
RESPONSE_FILE = BASE_DIR / "resources" / "tenable_api_response.json"


def load_responses():
    # Load the JSON file
    with open(RESPONSE_FILE, "r") as file:
        responses = json.load(file)
    return responses


@pytest.fixture
def mock_helper():
    return MagicMock()


@pytest.fixture
def mock_config():
    return MagicMock()


@pytest.fixture
def fake_asset():
    return Asset.model_validate_json(
        """
        {
        "device_type": "general-purpose",
        "fqdn": "sharepoint2016.target.example.com",
        "hostname": "sharepoint2016",
        "uuid": "53ed0fa2-ccd5-4d2e-92ee-c072635889e3",
        "ipv4": "203.0.113.71",
        "ipv6": "2001:db8:199e:6fb9:2edd:67f0:3f30:c7",
        "mac_address": "00:50:56:a6:22:93",
        "operating_system": [
            "Microsoft Windows Server 2016 Standard"
        ],
        "network_id": "00000000-0000-0000-0000-000000000000",
        "tracked": true,
        "last_scan_target": "192.0.0.1"
        }
        """
    )


@pytest.fixture
def fake_plugin():
    return Plugin.model_validate_json(
        """
        {
          "bid": [
            156641
          ],
          "checks_for_default_account": false,
          "checks_for_malware": false,
          "cpe": [
            "cpe:/a:microsoft:sharepoint_server"
          ],
          "cvss3_base_score": 8.8,
          "cvss3_temporal_score": 7.7,
          "cvss3_temporal_vector": {
            "exploitability": "Unproven",
            "remediation_level": "Official Fix",
            "report_confidence": "Confirmed",
            "raw": "E:U/RL:O/RC:C"
          },
          "cvss3_vector": {
            "access_complexity": "Low",
            "access_vector": "Network",
            "availability_impact": "High",
            "confidentiality_impact": "High",
            "integrity_impact": "High",
            "raw": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "cvss_base_score": 9,
          "cvss_temporal_score": 6.7,
          "cvss_temporal_vector": {
            "exploitability": "Unproven",
            "remediation_level": "Official Fix",
            "report_confidence": "Confirmed",
            "raw": "E:U/RL:OF/RC:C"
          },
          "cvss_vector": {
            "access_complexity": "Low",
            "access_vector": "Network",
            "authentication": "Single",
            "availability_impact": "Complete",
            "confidentiality_impact": "Complete",
            "integrity_impact": "Complete",
            "raw": "AV:N/AC:L/Au:S/C:C/I:C/A:C"
          },
          "description": "The Microsoft SharePoint Server 2013 installation on the remote host is missing security updates. It is, therefore, affected by a remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute unauthorized arbitrary commands. (CVE-2022-21837, CVE-2022-21840, CVE-2022-21842)",
          "exploit_available": false,
          "exploit_framework_canvas": false,
          "exploit_framework_core": false,
          "exploit_framework_d2_elliot": false,
          "exploit_framework_exploithub": false,
          "exploit_framework_metasploit": false,
          "exploitability_ease": "No known exploits are available",
          "exploited_by_malware": false,
          "exploited_by_nessus": false,
          "family": "Windows : Microsoft Bulletins",
          "family_id": 41,
          "has_patch": true,
          "has_workaround": false,
          "id": 156641,
          "in_the_news": false,
          "ms_bulletin": [
            "5002113"
          ],
          "name": "Security Updates for Microsoft SharePoint Server 2016 (January 2022)",
          "patch_publication_date": "2022-01-11T00:00:00Z",
          "modification_date": "2022-05-06T00:00:00Z",
          "publication_date": "2022-01-12T00:00:00Z",
          "risk_factor": "high",
          "see_also": [
            "https://support.microsoft.com/en-us/help/5002113"
          ],
          "solution": "Microsoft has released security update KB5002113 to address this issue.",
          "stig_severity": "I",
          "synopsis": "The Microsoft SharePoint Server 2016 installation on the remote host is missing security updates.",
          "unsupported_by_vendor": false,
          "version": "1.6",
          "vuln_publication_date": "2022-01-11T00:00:00Z",
          "xrefs": [
            {
              "type": "CVE",
              "id": "2022-21837"
            },
            {
              "type": "CVE",
              "id": "2022-21840"
            },
            {
              "type": "CVE",
              "id": "2022-21842"
            },
            {
              "type": "IAVA",
              "id": "2022-A-0007-S"
            },
            {
              "type": "MSFT",
              "id": "MS22-5002113"
            },
            {
              "type": "MSKB",
              "id": "5002113"
            }
          ],
          "vpr": {
            "score": 6.7,
            "drivers": {
              "age_of_vuln": {
                "lower_bound": 731
              },
              "exploit_code_maturity": "UNPROVEN",
              "cvss_impact_score_predicted": false,
              "cvss3_impact_score": 5.9,
              "threat_intensity_last28": "VERY_LOW",
              "threat_sources_last28": [
                "No recorded events"
              ],
              "product_coverage": "LOW"
            },
            "updated": "2024-02-04T06:03:56Z"
          },
          "cve": [
            "CVE-2022-21837",
            "CVE-2022-21840",
            "CVE-2022-21842"
          ],
          "type": "local"
        }
    """
    )


@pytest.fixture
def fake_vuln_finding():
    return VulnerabilityFinding.model_validate_json(
        """{
            "asset": {
              "device_type": "hypervisor",
              "fqdn": "vcsa8.target.example.com",
              "hostname": "vcsa8.target.example.com",
              "uuid": "1babf006-b1f0-4dee-86a1-7a55888336c3",
              "ipv4": "192.0.2.246",
              "operating_system": [
                "VMware vCenter Server 8.0.0 build-20037386"
              ],
              "network_id": "00000000-0000-0000-0000-000000000000",
              "tracked": true,
              "last_scan_target": "192.0.0.1"
            },
            "output": "The following pages do not set a Content-Security-Policy frame-ancestors response header or set a permissive policy:  - https://vcsa8.target.example.com/  - https://vcsa8.target.example.com/ui/",
            "plugin": {
              "bid": [
                50344
              ],
              "checks_for_default_account": false,
              "checks_for_malware": false,
              "cpe": [],
              "description": "The remote web server in some responses sets a permissive Content-Security-Policy (CSP) frame-ancestors response header or does not set one at all.The CSP frame-ancestors header has been proposed by the W3C Web Application Security Working Group as a way to mitigate cross-site scripting and clickjacking attacks.",
              "exploit_available": false,
              "exploit_framework_canvas": false,
              "exploit_framework_core": false,
              "exploit_framework_d2_elliot": false,
              "exploit_framework_exploithub": false,
              "exploit_framework_metasploit": false,
              "exploited_by_malware": false,
              "exploited_by_nessus": false,
              "family": "CGI abuses",
              "family_id": 3,
              "has_patch": false,
              "has_workaround": false,
              "id": 50344,
              "in_the_news": false,
              "name": "Missing or Permissive Content-Security-Policy frame-ancestors HTTP Response Header",
              "modification_date": "2021-01-19T00:00:00Z",
              "publication_date": "2010-10-26T00:00:00Z",
              "risk_factor": "info",
              "see_also": [
                "http://www.nessus.org/u?55aa8f57",
                "http://www.nessus.org/u?07cc2a06",
                "https://content-security-policy.com/",
                "https://www.w3.org/TR/CSP2/"
              ],
              "solution": "Set a non-permissive Content-Security-Policy frame-ancestors header for all requested resources.",
              "synopsis": "The remote web server does not take steps to mitigate a class of web application vulnerabilities.",
              "unsupported_by_vendor": false,
              "version": "1.6",
              "xrefs": [],
              "type": "remote"
            },
            "port": {
              "port": 443,
              "protocol": "TCP",
              "service": "www"
            },
            "scan": {
              "schedule_uuid": "16cf08d3-3f94-79f4-8038-996376eabd4f186741fe15533e70",
              "started_at": "2023-05-03T14:13:56.983Z",
              "uuid": "e86252a3-8dc0-43b6-8ddd-afb219d040ed",
              "target": "192.0.0.1"
            },
            "severity": "info",
            "severity_id": 0,
            "severity_default_id": 0,
            "severity_modification_type": "NONE",
            "first_found": "2022-11-08T06:12:27.940Z",
            "last_found": "2023-05-04T09:39:26.415Z",
            "state": "OPEN",
            "indexed": "2023-05-04T09:44:55.673359Z",
            "source": "NESSUS"
          }
          """
    )


def test_tlp_marking_definition_handler_should_fails_with_unsupported_TLP():
    # GIVEN: An invalid TLP marking definition
    invalid_marking = "TLP:BLUE"

    # WHEN/THEN: We expect a ValueError when calling the function
    with pytest.raises(ValueError) as exc_info:
        tlp_marking_definition_handler(invalid_marking)

    # Assert that the exception message is as expected
    assert "Unsupported TLP" in str(exc_info.value)


def test_converter_to_stix_make_author(mock_helper, mock_config):
    # Given a converter to stix instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )
    # When calling make_author
    author = converter_to_stix._make_author()
    # Then a valid Author should be returned and assigned to converter attribute
    assert converter_to_stix.author == author


def test_converter_to_stix_make_system(mock_helper, mock_config, fake_asset):
    # Given a converter to stix instance
    # and a valid asset instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )
    asset = fake_asset
    # When calling make_system
    system = converter_to_stix._make_system(asset=asset)
    # Then a valid System should be returned
    assert system.name == "sharepoint2016"


def test_converter_to_stix_make_mac_address(mock_helper, mock_config, fake_asset):
    # Given a converter to stix instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )

    # Case 1: Asset with a valid MAC address
    asset_with_mac = fake_asset
    mac_address = converter_to_stix._make_mac_address(asset_with_mac)

    # Then it should return a valid MACAddress object
    assert mac_address.value == "00:50:56:a6:22:93"

    # Case 2: Asset without a MAC address
    asset_without_mac = fake_asset.model_copy(update={"mac_address": None})
    mac_address_none = converter_to_stix._make_mac_address(asset_without_mac)

    # Then it should return None
    assert mac_address_none is None


def test_converter_to_stix_make_ipv4_address(mock_helper, mock_config, fake_asset):
    # Given a converter to stix instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )
    asset = fake_asset

    # When calling make_ipv4_address
    ipv4_address = converter_to_stix._make_ipv4_address(asset=asset)

    # Then a valid IPAddress object should be returned
    assert ipv4_address.version == "v4"
    assert ipv4_address.value == "203.0.113.71"
    assert len(ipv4_address.resolves_to_mac_addresses) == 1


def test_converter_to_stix_make_ipv6_address(mock_helper, mock_config, fake_asset):
    # Given a converter to stix instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )

    # Case 1: Asset with a valid IPv6 address
    asset_with_ipv6 = fake_asset
    ipv6_address = converter_to_stix._make_ipv6_address(asset_with_ipv6)

    # Then it should return a valid IPAddress object
    assert ipv6_address.version == "v6"
    assert ipv6_address.value == "2001:db8:199e:6fb9:2edd:67f0:3f30:c7"

    # Case 2: Asset without an IPv6 address
    asset_without_ipv6 = fake_asset.model_copy(update={"ipv6": None})
    ipv6_address_none = converter_to_stix._make_ipv6_address(asset_without_ipv6)

    # Then it should return None
    assert ipv6_address_none is None


def test_converter_to_stix_make_hostname(mock_helper, mock_config, fake_asset):
    # Given a converter to stix instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )
    asset = fake_asset

    # When calling make_hostname
    hostname = converter_to_stix._make_hostname(asset=asset)

    # Then a valid Hostname object should be returned
    assert hostname.value == "sharepoint2016"


def test_converter_to_stix_make_operating_systems(mock_helper, mock_config, fake_asset):
    # Given a converter to stix instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )
    asset = fake_asset

    # When calling make_operating_systems
    operating_systems = converter_to_stix.make_operating_systems(asset=asset)

    # Then a list of OperatingSystem objects should be returned
    assert operating_systems[0].name == "Microsoft Windows Server 2016 Standard"


def test_converter_to_stix_make_domain_name(mock_helper, mock_config, fake_asset):
    # Given a converter to stix instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )

    # Case 1: Asset with a valid FQDN
    asset_with_fqdn = fake_asset
    domain_name = converter_to_stix._make_domain_name(asset_with_fqdn)

    # Then it should return a valid DomainName object
    assert domain_name.value == "sharepoint2016.target.example.com"
    assert len(domain_name.resolves_to_ips) == 2

    # Case 2: Asset without an FQDN
    asset_without_fqdn = fake_asset.model_copy(update={"fqdn": None})
    domain_name_none = converter_to_stix._make_domain_name(asset_without_fqdn)

    # Then it should return None
    assert domain_name_none is None


def test_converter_to_stix_make_targeted_software_s(
    mock_helper, mock_config, fake_plugin
):
    # Given a converter to stix instance and a fake plugin
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )

    # When calling _make_targeted_software_s
    targeted_software = converter_to_stix._make_targeted_software_s(plugin=fake_plugin)

    # Then it should return a list of Software objects with extracted information from CPE Uri
    assert len(targeted_software) == 1
    software = targeted_software[0]
    assert software.name == "sharepoint_server"
    assert software.vendor == "microsoft"
    assert software.cpe == "cpe:/a:microsoft:sharepoint_server"


def test_converter_to_stix_make_vulnerabilities(mock_helper, mock_config, fake_plugin):
    # Given a converter to stix instance and a fake plugin instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )

    # When calling _make_vulnerabilities
    vulnerabilities = converter_to_stix._make_vulnerabilities(plugin=fake_plugin)

    # Then it should return a list of Vulnerability objects
    assert len(vulnerabilities) == 3  # Three CVEs in the plugin
    # with the CVE name as Vulnerability name
    vulnerability = vulnerabilities[0]
    assert vulnerability.name == "CVE-2022-21837"


def test_converter_to_stix_process_asset(mock_helper, mock_config, fake_asset):
    # Given a converter to stix instance and a fake asset
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )

    # When calling process_asset
    result = converter_to_stix.process_asset(asset=fake_asset)

    # Validate the system object
    assert result["system"].name == "sharepoint2016"
    # Validate observables
    assert (
        len(result["observables"]) == 6
    )  # ipv4, hostname, mac, ipv6, domain_name, operating_system
    # Validate relationships
    assert len(result["relationships"]) == 6


def test_converter_to_stix_process_plugin(mock_helper, mock_config, fake_plugin):
    # Given a converter to stix instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )

    # When calling process_plugin
    result = converter_to_stix.process_plugin(plugin=fake_plugin)

    # Then the result should contain vulnerabilities, software, and relationships
    # Validate vulnerabilities
    assert len(result["vulnerabilities"]) == 3  # Three CVEs in the plugin
    # Validate software objects
    assert len(result["software_s"]) == 1  # One software from the plugin's CPE
    # Validate relationships between vulnerabilities and software
    assert len(result["relationships"]) == 3


def test_converter_to_stix_process_vuln_finding(
    mock_helper, mock_config, fake_vuln_finding
):
    # Given a converter to stix instance
    converter_to_stix = ConverterToStix(
        helper=mock_helper, config=mock_config, default_marking="TLP:CLEAR"
    )

    # When calling process_vuln_findings
    result = converter_to_stix.process_vuln_finding(vuln_finding=fake_vuln_finding)

    # Then the result contains 1 system
    systems = [item for item in result if isinstance(item, System)]
    assert len(systems) == 1

    # & the result contains 1 vulnerability (proper to the given fake data)
    vulnerabilities = [item for item in result if isinstance(item, Vulnerability)]
    assert len(vulnerabilities) == 1

    # &the System and the Vulnerability are linked with a Has Relationship
    has_relationships = [item for item in result if isinstance(item, HasRelationship)]
    assert (
        len(has_relationships) == 1
    )  # Note: OK because there is no cpe uris in the fake plugin used

    assert (
        has_relationships[0].source_ref == systems[0].id
        and has_relationships[0].target_ref == vulnerabilities[0].id
    )
