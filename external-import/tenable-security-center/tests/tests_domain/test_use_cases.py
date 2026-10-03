# pragma: no cover  # do not test coverage of tests...
# isort: skip_file
# type: ignore
"""Provide unit tests for the use case."""

import pytest
from unittest.mock import Mock

from datetime import datetime

from stix2 import TLP_WHITE

from tenable_security_center.domain.use_case import ConverterToStix
from tenable_security_center.ports.asset import (
    AssetsChunkPort,
    AssetPort,
    FindingPort,
    CVEPort,
)


def _mock_logger():
    return Mock()


@pytest.fixture()
def mock_logger():
    return _mock_logger()


class MockCVE(CVEPort):
    @property
    def name(self):
        return "CVE-2021-1234"

    @property
    def description(self):
        return "Description"

    @property
    def publication_datetime(self):
        return datetime.fromisoformat("2021-01-01T00:00:00Z")

    @property
    def last_modified_datetime(self):
        return datetime.fromisoformat("2021-01-02T00:00:00Z")

    @property
    def cpes(self):
        return None

    @property
    def cvss_v3_score(self):
        return None

    @property
    def cvss_v3_vector(self):
        return None

    @property
    def epss_percentile(self):
        return None

    @property
    def epss_score(self):
        return None


class MockDegradedCVE(CVEPort):
    """A CVE for which Tenable Security Center returned no details, only its id.

    See https://github.com/OpenCTI-Platform/connectors/issues (empty response
    from the CVE endpoint must still produce a Vulnerability/relationship).
    """

    @property
    def name(self):
        return "CVE-9999-0000"

    @property
    def description(self):
        return None

    @property
    def publication_datetime(self):
        return None

    @property
    def last_modified_datetime(self):
        return None

    @property
    def cpes(self):
        return None

    @property
    def cvss_v3_score(self):
        return None

    @property
    def cvss_v3_vector(self):
        return None

    @property
    def epss_percentile(self):
        return None

    @property
    def epss_score(self):
        return None


class MockVulnerability(FindingPort):
    def __init__(self, has_cves=False, degraded_cve=False):
        if degraded_cve:
            self._cves = [MockDegradedCVE()]
        elif has_cves:
            self._cves = [MockCVE()]
        else:
            self._cves = None

    @property
    def cves(self):
        return self._cves

    @property
    def plugin_name(self):
        return "Example Plugin"

    @property
    def plugin_id(self):
        return "12345"

    @property
    def has_been_mitigated(self):
        return False

    @property
    def accept_risk(self):
        return False

    @property
    def recast_risk(self):
        return False

    @property
    def ip(self):
        return "192.0.0.1"

    @property
    def port(self):
        return 80

    @property
    def protocol(self):
        return "TCP"

    @property
    def first_seen(self):
        return datetime.fromisoformat("2021-01-01T00:00:00Z")

    @property
    def last_seen(self):
        return datetime.fromisoformat("2021-01-02T00:00:00Z")

    @property
    def tenable_severity(self):
        return "High"

    @property
    def seol_date(self):
        return datetime.fromisoformat("2021-01-03T00:00:00Z")

    @property
    def host_uniqueness(self):
        return []

    @property
    def vuln_uniqueness(self):
        return []

    @property
    def uniqueness(self):
        return []

    @property
    def accept_risk_rule_comment(self):
        return None

    @property
    def acr_score(self):
        return None

    @property
    def asset_exposure_score(self):
        return None

    @property
    def base_score(self):
        return None

    @property
    def bid(self):
        return None

    @property
    def check_type(self):
        return None

    @property
    def cpes(self):
        return None

    @property
    def cvss_v3_base_score(self):
        return None

    @property
    def cvss_v3_temporal_score(self):
        return None

    @property
    def cvss_v3_vector(self):
        return None

    @property
    def cvss_vector(self):
        return None

    @property
    def description(self):
        return None

    @property
    def dns_name(self):
        return None

    @property
    def exploit_available(self):
        return None

    @property
    def exploit_ease(self):
        return None

    @property
    def exploit_frameworks(self):
        return None

    @property
    def host_uuid(self):
        return None

    @property
    def mac_address(self):
        return None

    @property
    def netbios_name(self):
        return None

    @property
    def operating_system(self):
        return None

    @property
    def patch_pub_date(self):
        return None

    @property
    def plugin_mod_date(self):
        return None

    @property
    def plugin_pub_date(self):
        return None

    @property
    def plugin_text(self):
        return None

    @property
    def recast_risk_rule_comment(self):
        return None

    @property
    def risk_factor(self):
        return None

    @property
    def see_also(self):
        return None

    @property
    def solution(self):
        return None

    @property
    def stig_severity(self):
        return None

    @property
    def synopsis(self):
        return None

    @property
    def temporal_score(self):
        return None

    @property
    def uuid(self):
        return None

    @property
    def version(self):
        return None

    @property
    def vpr_context(self):
        return None

    @property
    def vpr_score(self):
        return None

    @property
    def vuln_pub_date(self):
        return None

    @property
    def vuln_uuid(self):
        return None

    @property
    def xref(self):
        return None


class MockAsset(AssetPort):
    def __init__(
        self, findings: bool, with_cves: bool, degraded_cve: bool = False
    ) -> None:
        self._findings = []
        if findings:
            self._findings.append(
                MockVulnerability(has_cves=with_cves, degraded_cve=degraded_cve)
            )

    @property
    def id(self):
        return "1234"

    @property
    def uuid(self):
        return "1234"

    @property
    def name(self):
        return "name"

    @property
    def first_seen(self):
        return datetime.fromisoformat("1970-01-01T00:00:00Z")

    @property
    def last_seen(self):
        return datetime.fromisoformat("1970-01-01T00:00:00Z")

    @property
    def created_time(self):
        return datetime.fromisoformat("1970-01-01T00:00:00Z")

    @property
    def modified_time(self):
        return datetime.fromisoformat("1970-01-01T00:00:00Z")

    @property
    def ip_address(self):
        return "192.0.0.1"

    @property
    def repository_id(self):
        return "1"

    @property
    def findings(self):
        return self._findings

    @property
    def mac_address(self):
        return None

    @property
    def operating_systems(self):
        return None

    @property
    def tenable_uuid(self):
        return "1234"


class MockAssetsChunk(AssetsChunkPort):
    def __init__(self, findings=False, with_cves=False, degraded_cve=False) -> None:
        self._findings = findings
        self._with_cves = with_cves
        self._degraded_cve = degraded_cve

    @property
    def assets(self):
        return [
            MockAsset(
                findings=self._findings,
                with_cves=self._with_cves,
                degraded_cve=self._degraded_cve,
            )
        ]


@pytest.fixture()
def mock_assets_chunk_without_finding():
    return MockAssetsChunk()


@pytest.fixture()
def mock_assets_chunk_with_finding():
    return MockAssetsChunk(findings=True)


@pytest.fixture()
def mock_assets_chunk_with_finding_and_cves():
    return MockAssetsChunk(findings=True, with_cves=True)


@pytest.fixture()
def mock_assets_chunk_with_finding_and_degraded_cve():
    return MockAssetsChunk(findings=True, with_cves=True, degraded_cve=True)


def test_constructor(mock_logger):
    # Given a mock logger
    logger = mock_logger
    # When creating a new ConverterToStix
    converter = ConverterToStix(logger=logger, tlp_marking=TLP_WHITE)
    # Then the converter should be correctly initialized with an Author
    assert converter._author is not None


def test_converter_should_process_an_asset_chunk(
    mock_logger, mock_assets_chunk_without_finding
):
    # Given a mock logger
    logger = mock_logger

    # a ConverterToStix Instance
    converter = ConverterToStix(logger=logger, tlp_marking=TLP_WHITE)
    # an assets_chunk
    assets_chunk = mock_assets_chunk_without_finding

    # When processing an asset chunk
    results = converter.process_assets_chunk(
        assets_chunk=assets_chunk, process_systems_without_vulnerabilities=True
    )
    # Then the results should contain at least a author, a system and an ipadress pointing to the system
    assert any(
        value.get("identity_class") == "organization" for _, value in results.items()
    )
    assert any(value.get("identity_class") == "system" for _, value in results.items())
    assert any(value["type"] == "ipv4-addr" for _, value in results.items())
    assert any(
        (
            value["type"] == "relationship"
            and value.get("source_ref", "").startswith("identity--")
            and value.get("target_ref", "").startswith("ipv4-addr--")
        )
        for _, value in results.items()
    )


def test_converter_should_process_an_asset_with_finding(
    mock_logger, mock_assets_chunk_with_finding
):
    # Given a mock logger
    logger = mock_logger
    # a ConverterToStix Instance
    converter = ConverterToStix(logger=logger, tlp_marking=TLP_WHITE)
    # an assets_chunk containing an asset with a finding
    assets_chunk = mock_assets_chunk_with_finding

    # When processing an asset chunk
    results = converter.process_assets_chunk(
        assets_chunk=assets_chunk, process_systems_without_vulnerabilities=False
    )
    # Then the results should contain at least a system and a vulnerability pointing to the system
    print(results)
    assert any(value.get("identity_class") == "system" for _, value in results.items())
    assert any(value["type"] == "vulnerability" for _, value in results.items())
    assert any(
        (
            value["type"] == "relationship"
            and value.get("source_ref", "").startswith("identity--")
            and value.get("target_ref", "").startswith("vulnerability--")
        )
        for _, value in results.items()
    )


def test_converter_should_process_an_asset_with_finding_and_cves(
    mock_logger, mock_assets_chunk_with_finding_and_cves
):
    # Given a mock logger
    logger = mock_logger
    # a ConverterToStix Instance
    converter = ConverterToStix(logger=logger, tlp_marking=TLP_WHITE)
    # an assets_chunk containing an asset with a finding
    assets_chunk = mock_assets_chunk_with_finding_and_cves

    # When processing an asset chunk
    results = converter.process_assets_chunk(
        assets_chunk=assets_chunk, process_systems_without_vulnerabilities=False
    )
    # Then the results should contain at least a system and a vulnerability as a CVE pointing to the system
    assert any(value.get("identity_class") == "system" for _, value in results.items())
    assert any(
        value["type"] == "vulnerability" and value["name"].startswith("CVE")
        for _, value in results.items()
    )
    assert any(
        (
            value["type"] == "relationship"
            and value.get("source_ref", "").startswith("identity--")
            and value.get("target_ref", "").startswith("vulnerability--")
        )
        for _, value in results.items()
    )


def test_converter_should_process_an_asset_with_finding_and_degraded_cve(
    mock_logger, mock_assets_chunk_with_finding_and_degraded_cve
):
    """Regression test: a CVE for which Tenable Security Center returned no
    details (only its id was known, e.g. an empty response from the CVE
    endpoint) must still produce a Vulnerability node named after the CVE id
    and a relationship to the system, not be dropped.
    """
    # Given a mock logger
    logger = mock_logger
    # a ConverterToStix Instance
    converter = ConverterToStix(logger=logger, tlp_marking=TLP_WHITE)
    # an assets_chunk containing an asset with a finding whose CVE has no details
    assets_chunk = mock_assets_chunk_with_finding_and_degraded_cve

    # When processing an asset chunk
    results = converter.process_assets_chunk(
        assets_chunk=assets_chunk, process_systems_without_vulnerabilities=False
    )
    # Then the results should still contain a vulnerability named after the CVE id...
    assert any(
        value["type"] == "vulnerability" and value["name"] == "CVE-9999-0000"
        for _, value in results.items()
    )
    # ...and a relationship from the system to that vulnerability
    assert any(
        (
            value["type"] == "relationship"
            and value.get("source_ref", "").startswith("identity--")
            and value.get("target_ref", "").startswith("vulnerability--")
        )
        for _, value in results.items()
    )


# --- CPE handling on the CVE path ---------------------------------------------------

NVD_CPE = "cpe:/a:nvd_vendor:nvd_product"
PLUGIN_CPE = "cpe:/a:apache:http_server"


class MockCVEWithCpes(MockCVE):
    """A CVE carrying its generic NVD applicability CPE list."""

    @property
    def cpes(self):
        return [NVD_CPE]


class MockVulnerabilityWithCpes(MockVulnerability):
    """A finding with a CVE (carrying NVD CPEs) and its own plugin CPEs."""

    def __init__(self, finding_cpes):
        super().__init__()
        self._cves = [MockCVEWithCpes()]
        self._finding_cpes = finding_cpes

    @property
    def cpes(self):
        return self._finding_cpes


class MockSingleFindingAssetsChunk(AssetsChunkPort):
    """An assets chunk with a single asset carrying the provided finding."""

    def __init__(self, finding):
        self._finding = finding

    @property
    def assets(self):
        asset = MockAsset(findings=False, with_cves=False)
        asset._findings = [self._finding]
        return [asset]


def _softwares_cpes(results):
    return {
        value.get("cpe")
        for _, value in results.items()
        if value["type"] == "software" and value.get("cpe")
    }


def test_converter_should_not_create_softwares_from_cve_cpes(mock_logger):
    """The CVE's generic NVD CPE list must not be turned into Software objects."""
    # Given a finding with a CVE carrying NVD CPEs, and no plugin CPE
    converter = ConverterToStix(logger=mock_logger, tlp_marking=TLP_WHITE)
    assets_chunk = MockSingleFindingAssetsChunk(
        MockVulnerabilityWithCpes(finding_cpes=None)
    )

    # When processing the assets chunk
    results = converter.process_assets_chunk(
        assets_chunk=assets_chunk, process_systems_without_vulnerabilities=False
    )

    # Then the CVE is imported but no Software is created from its NVD CPEs
    assert any(
        value["type"] == "vulnerability" and value["name"] == "CVE-2021-1234"
        for _, value in results.items()
    )
    assert NVD_CPE not in _softwares_cpes(results)


def test_converter_should_create_softwares_from_finding_cpes_on_cve_path(mock_logger):
    """On the CVE path, Softwares come from the CPEs of the plugin that triggered the finding."""
    # Given a finding with a CVE carrying NVD CPEs, and its own plugin CPE
    converter = ConverterToStix(logger=mock_logger, tlp_marking=TLP_WHITE)
    assets_chunk = MockSingleFindingAssetsChunk(
        MockVulnerabilityWithCpes(finding_cpes=[PLUGIN_CPE])
    )

    # When processing the assets chunk
    results = converter.process_assets_chunk(
        assets_chunk=assets_chunk, process_systems_without_vulnerabilities=False
    )

    # Then only the plugin CPE is turned into a Software...
    assert _softwares_cpes(results) == {PLUGIN_CPE}
    # ...linked to the CVE vulnerability with a "has" relationship
    software_ids = {
        key
        for key, value in results.items()
        if value["type"] == "software" and value.get("cpe") == PLUGIN_CPE
    }
    vulnerability_ids = {
        key
        for key, value in results.items()
        if value["type"] == "vulnerability" and value["name"] == "CVE-2021-1234"
    }
    assert any(
        value["type"] == "relationship"
        and value["relationship_type"] == "has"
        and value["source_ref"] in software_ids
        and value["target_ref"] in vulnerability_ids
        for _, value in results.items()
    )
