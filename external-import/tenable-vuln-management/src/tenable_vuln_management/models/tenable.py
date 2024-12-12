"""Offer Ports for the origin API Response."""

from datetime import datetime
from typing import Any, Optional

from pydantic import Field

from .common import FrozenBaseModelWithWarnedExtra


def _convert_empty_dicts_and_lists_to_none(value: Any) -> Any:
    """Convert recursively nested empty dictionaries and lists to None value.

    This is useful when receiving empty objects from Tenable Vuln Management API response.

    Args:
        value (Any): The structure to clean. This is typed to Any for the recursion application.

    Returns:
        (Any): The cleaned structure.

    Notes:
        Removing empty dict, rather than replacing them with null value, could also be a strategy to clean a response
            body. However, it appears to be more complex solution as a first pass of the algorythm could also create
            empty dictionaries. This simplier implemented method does fullfill our needs.

    Examples:
        >>> to_clean = {'a': {"b": {}, "c": [1, {"e": {}}]}}
        >>> _convert_empty_dicts_and_lists_to_none(to_clean)
        {'a': {"b":None, "c": [1, "e": None]}}
    """
    # If the value is a dictionary, recursively process it
    if isinstance(value, dict):
        return {
            k: _convert_empty_dicts_and_lists_to_none(v) if v != {} else None
            for k, v in value.items()
        }
    # If the value is a list, apply the conversion to each item
    if isinstance(value, list):
        return (
            [_convert_empty_dicts_and_lists_to_none(item) for item in value]
            if value
            else None
        )
    return value


class CvssVector(FrozenBaseModelWithWarnedExtra):
    """
    Represents a CVSS vector that includes impact and access details for vulnerability scoring.
    """

    access_complexity: str = Field(
        ..., description="The complexity required to exploit the vulnerability."
    )
    access_vector: str = Field(
        ..., description="The network location required to exploit the vulnerability."
    )
    authentication: Optional[str] = Field(
        None, description="The network authentication method;"
    )
    availability_impact: str = Field(
        ..., description="The impact on availability of the target system."
    )
    confidentiality_impact: str = Field(
        ..., description="The impact on confidentiality of the target system."
    )
    integrity_impact: str = Field(
        ..., description="The impact on integrity of the target system."
    )
    raw: str = Field(..., description="Raw CVSS vector string.")


class CvssTemporalVector(FrozenBaseModelWithWarnedExtra):
    """
    Represents the temporal CVSS vector, which includes factors that change over time, like exploitability.
    """

    exploitability: Optional[str] = Field(
        None, description="The level of exploitability of the vulnerability."
    )
    remediation_level: str = Field(
        ..., description="Remediation status of the vulnerability."
    )
    report_confidence: str = Field(
        ..., description="The confidence level of the vulnerability report."
    )
    raw: str = Field(..., description="Raw CVSS temporal vector string.")


class VprDrivers(FrozenBaseModelWithWarnedExtra):
    """
    VPR score drivers providing insight into factors like age, threat intensity, and product coverage.
    """

    age_of_vuln: dict = Field(..., description="Age of the vulnerability in days.")
    exploit_code_maturity: str = Field(
        ..., description="Maturity of available exploit code."
    )
    cvss_impact_score_predicted: bool = Field(
        ..., description="Indicates if the CVSS impact score is predicted."
    )
    cvss3_impact_score: float = Field(..., description="The CVSS v3 impact score.")
    threat_intensity_last28: str = Field(
        ..., description="Threat intensity over the last 28 days."
    )
    threat_sources_last28: list[str] = Field(
        ..., description="Sources of threats observed in the last 28 days."
    )
    product_coverage: str = Field(
        ..., description="The coverage of the affected product."
    )


class Vpr(FrozenBaseModelWithWarnedExtra):
    """
    Vulnerability Priority Rating (VPR) score details, which reflect the threat level of a vulnerability.
    """

    score: float = Field(..., description="The VPR score of the vulnerability.")
    drivers: VprDrivers = Field(
        ..., description="The drivers contributing to the VPR score."
    )
    updated: datetime = Field(
        ..., description="The date when the VPR score was last updated."
    )


class Xref(FrozenBaseModelWithWarnedExtra):
    """
    Cross-references (Xrefs) for the vulnerability, including external references like CVEs.
    """

    type: str = Field(..., description="The type of reference (e.g., CVE, IAVA, MSFT).")
    id: str = Field(..., description="The identifier of the reference.")


class Plugin(FrozenBaseModelWithWarnedExtra):
    """
    Represents plugin details that provide information about the detected vulnerability.
    """

    bid: list[int] = Field(..., description="Bugtraq IDs related to the vulnerability.")
    checks_for_default_account: bool = Field(
        ..., description="Indicates if the plugin checks for default accounts."
    )
    checks_for_malware: bool = Field(
        ..., description="Indicates if the plugin checks for malware."
    )
    cpe: Optional[list[str]] = Field(
        None, description="Common Platform Enumeration (CPE) identifiers."
    )
    cvss3_base_score: Optional[float] = Field(
        None, description="The CVSS v3 base score.", ge=0, le=10
    )
    cvss3_temporal_score: Optional[float] = Field(
        None, description="The CVSS v3 temporal score."
    )
    cvss3_temporal_vector: Optional[CvssTemporalVector] = Field(
        None, description="The CVSS v3 temporal vector."
    )
    cvss3_vector: Optional[CvssVector] = Field(None, description="The CVSS v3 vector.")
    cvss_base_score: Optional[float] = Field(None, description="The CVSS base score.")
    cvss_temporal_score: Optional[float] = Field(
        None, description="The CVSS temporal score."
    )
    cvss_temporal_vector: Optional[CvssTemporalVector] = Field(
        None, description="The CVSS temporal vector."
    )
    cvss_vector: Optional[CvssVector] = Field(None, description="The CVSS vector.")
    description: str = Field(..., description="A description of the vulnerability.")
    exploit_available: bool = Field(
        ..., description="Indicates if an exploit is available."
    )
    exploit_framework_canvas: bool = Field(
        ..., description="Indicates if the vulnerability is exploited by Canvas."
    )
    exploit_framework_core: bool = Field(
        ..., description="Indicates if the vulnerability is exploited by Core Impact."
    )
    exploit_framework_d2_elliot: bool = Field(
        ..., description="Indicates if the vulnerability is exploited by D2 Elliot."
    )
    exploit_framework_exploithub: bool = Field(
        ..., description="Indicates if the vulnerability is exploited by ExploitHub."
    )
    exploit_framework_metasploit: bool = Field(
        ..., description="Indicates if the vulnerability is exploited by Metasploit."
    )
    exploitability_ease: Optional[str] = Field(
        None, description="Ease of exploitation."
    )
    exploited_by_malware: bool = Field(
        ..., description="Indicates if the vulnerability is exploited by malware."
    )
    exploited_by_nessus: bool = Field(
        ..., description="Indicates if Nessus exploits the vulnerability."
    )
    family: str = Field(
        ..., description="The family of vulnerabilities this plugin belongs to."
    )
    family_id: Optional[int] = Field(
        None, description="The ID of the vulnerability family."
    )
    has_patch: bool = Field(..., description="Indicates if a patch is available.")
    id: int = Field(..., description="The plugin ID.")
    in_the_news: bool = Field(
        ..., description="Indicates if the vulnerability is in the news."
    )
    ms_bulletin: Optional[list[str]] = Field(
        None, description="Microsoft security bulletin numbers."
    )
    name: str = Field(..., description="The name of the plugin.")
    patch_publication_date: Optional[datetime] = Field(
        None, description="The date when the patch was published."
    )
    modification_date: Optional[datetime] = Field(
        None, description="The date when the plugin was last modified."
    )
    publication_date: Optional[datetime] = Field(
        None, description="The date when the vulnerability was published."
    )
    risk_factor: str = Field(
        ..., description="The risk factor associated with the vulnerability."
    )
    see_also: Optional[list[str]] = Field(
        None, description="Additional links for reference."
    )
    solution: Optional[str] = Field(
        None, description="The solution to address the vulnerability."
    )
    stig_severity: Optional[str] = Field(
        None, description="Severity based on STIG guidelines."
    )
    synopsis: str = Field(..., description="A brief synopsis of the vulnerability.")
    unsupported_by_vendor: bool = Field(
        ...,
        description="Indicates if the software is no longer supported by the vendor.",
    )
    version: Optional[str] = Field(None, description="The version of the plugin.")
    vuln_publication_date: Optional[datetime] = Field(
        None, description="The date the vulnerability was first published."
    )
    xrefs: Optional[list[Xref]] = Field(
        None, description="Cross-references to related identifiers like CVEs."
    )
    vpr: Optional[Vpr] = Field(
        None, description="Vulnerability Priority Rating details."
    )
    cve: Optional[list[str]] = Field(
        None, description="CVE identifiers associated with the vulnerability."
    )
    type: str = Field(..., description="The type of vulnerability (local or remote).")
    has_workaround: bool = Field(..., description="")


class Asset(FrozenBaseModelWithWarnedExtra):
    """
    Represents an asset's key properties, including network, hardware, and operating system details.
    """

    bios_uuid: Optional[str] = Field(None, description="The BIOS UUID of the asset.")
    device_type: str = Field(
        ..., description="The type of device (e.g., hypervisor, general-purpose)."
    )
    fqdn: Optional[str] = Field(
        None, description="The fully qualified domain name of the asset."
    )
    hostname: str = Field(..., description="The hostname of the asset.")
    uuid: str = Field(..., description="The UUID of the asset.")
    ipv4: str = Field(..., description="The IPv4 address of the asset.")
    ipv6: Optional[str] = Field(None, description="The IPv6 address of the asset.")
    last_authenticated_results: Optional[datetime] = Field(
        None, description="The timestamp of the last authentication results."
    )
    mac_address: Optional[str] = Field(
        None, description="The MAC address of the asset."
    )
    netbios_name: Optional[str] = Field(
        None, description="The NetBIOS name of the asset."
    )
    operating_system: list[str] = Field(
        ..., description="List of operating systems running on the asset."
    )
    network_id: str = Field(
        ..., description="The ID of the network the asset belongs to."
    )
    tracked: bool = Field(..., description="Indicates if the asset is being tracked.")
    last_scan_target: str = Field(
        ...,
        description="The IP address or fully qualified domain name \
                                  (FQDN) of the asset targeted in the last scan.",
    )


class Port(FrozenBaseModelWithWarnedExtra):
    """
    Represents details of the port associated with the detected vulnerability.
    """

    port: int = Field(
        ..., description="The port number on which the service is running."
    )
    protocol: str = Field(..., description="The protocol of the port (e.g., TCP).")
    service: Optional[str] = Field(
        None, description="The service running on the port (e.g., HTTP, CIFS)."
    )


class Scan(FrozenBaseModelWithWarnedExtra):
    """
    Represents details about the scan that detected the vulnerability.
    """

    schedule_uuid: str = Field(..., description="The UUID of the scan schedule.")
    started_at: datetime = Field(
        ..., description="The timestamp when the scan started."
    )
    uuid: str = Field(..., description="The UUID of the scan.")
    target: str = Field(
        ...,
        description="The IP address or fully qualified domain name of the asset targeted in the scan.",
    )


class VulnerabilityFinding(FrozenBaseModelWithWarnedExtra):
    """
    Represents the full report of an asset's vulnerability detection, including its plugin, port, scan, and metadata.
    """

    asset: Asset = Field(..., description="The asset associated with the report.")
    output: str = Field(..., description="Detailed output of the vulnerability scan.")
    plugin: Plugin = Field(
        ..., description="Plugin details about the detected vulnerability."
    )
    port: Optional[Port] = Field(
        None, description="Port information where the vulnerability was detected."
    )
    scan: Scan = Field(..., description="Scan details that detected the vulnerability.")
    severity: str = Field(..., description="The severity level of the vulnerability.")
    severity_id: int = Field(..., description="The ID of the severity level.")
    severity_default_id: int = Field(..., description="Default severity level ID.")
    severity_modification_type: str = Field(
        ..., description="Indicates if the severity has been modified."
    )
    first_found: datetime = Field(
        ..., description="Timestamp when the vulnerability was first found."
    )
    last_found: datetime = Field(
        ..., description="Timestamp when the vulnerability was last found."
    )
    last_fixed: Optional[datetime] = Field(
        None, description="Timestamp when the vulnerability was last fixed."
    )
    state: str = Field(
        ..., description="The state of the vulnerability (e.g., OPEN, CLOSED)."
    )
    indexed: datetime = Field(..., description="Timestamp when the report was indexed.")
    source: str = Field(
        ...,
        description="The source that provided the vulnerability data (e.g., NESSUS).",
    )
    finding_id: Optional[str] = Field(
        None, description="the Tenable Vuln Management finding internal uuid."
    )

    @classmethod
    def from_api_response_body(
        cls,
        data_vuln_export: list[dict[str, Any]],
        metadata: list[dict[str, Any]],
    ) -> list["VulnerabilityFinding"]:
        """Make a list of VulnerabilityFinding from API response body.

        Args:
            data_vuln_export (list[dict[str, Any]]): Raw response body from TenableIO API.
            metadata(list[dict[str, Any]]): Response from the Tenable V3 API containing:
                - id : vulnerability Tenable internal id
                - asset_id: the id of the targeted asset
                - definition_id: the id of the plugin

        Returns:
            (list[VulnerabilityFinding]): List of VulnerabilityFinding objects.
        """

        data_vuln_export = _convert_empty_dicts_and_lists_to_none(
            value=data_vuln_export
        )

        # Create a lookup dictionary for fast meta_data access based on 'id', 'asset_id', and 'definition_id'
        meta_data_lookup = {
            (item["asset.id"], item["definition.id"]): item["id"] for item in metadata
        }
        joined_data = []  # result holder
        for item in data_vuln_export:
            meta_item = meta_data_lookup.get(
                (item["asset"]["uuid"], item["plugin"]["id"])
            )
            if meta_item:
                item["finding_id"] = meta_item
            joined_data.append(item)
        return [cls(**item) for item in joined_data]
