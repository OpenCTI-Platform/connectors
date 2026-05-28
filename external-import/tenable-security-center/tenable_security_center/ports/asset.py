"""Provide Interfaces for the Tenable Security Center input objects."""

import datetime
from abc import ABC, abstractmethod
from typing import Iterable, Optional


class CVEPort(ABC):
    """Port to Represent a CVE."""

    @property
    @abstractmethod
    def name(self) -> str:
        """ID of the CVE."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Description of the CVE."""

    @property
    @abstractmethod
    def publication_datetime(self) -> datetime.datetime:
        """Published date of the CVE."""

    @property
    @abstractmethod
    def last_modified_datetime(self) -> datetime.datetime:
        """Last modified date of the CVE."""

    @property
    @abstractmethod
    def cpes(self) -> Optional[Iterable[str]]:
        """CPE URIs of the CVE."""

    @property
    @abstractmethod
    def cvss_v3_score(self) -> Optional[float]:
        """CVSS v3 score of the CVE."""

    @property
    @abstractmethod
    def cvss_v3_vector(self) -> Optional[str]:
        """CVSS v3 vector of the CVE."""

    @property
    @abstractmethod
    def epss_score(self) -> Optional[float]:
        """EPSS score of the CVE."""

    @property
    @abstractmethod
    def epss_percentile(self) -> Optional[float]:
        """EPSS percentile of the CVE."""


class FindingPort(ABC):
    """For code clarity: we refer to the Tenable Vulnerability as a "Finding" to avoid confusion with the STIX
    Vulnerability object.
    """

    @property
    @abstractmethod
    def plugin_name(self) -> str:
        """The name of the plugin that found the vulnerability."""

    @property
    @abstractmethod
    def cves(self) -> Optional[list[CVEPort]]:
        """List of Common Vulnerabilities and Exposures (CVEs) associated with the vulnerability."""

    @property
    @abstractmethod
    def cpes(self) -> Optional[list[str]]:
        """List of Common Platform Enumeration URIs (CPEs) related to the vulnerability."""

    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """The unique identifier for the plugin that found the vulnerability."""

    @property
    @abstractmethod
    def has_been_mitigated(self) -> bool:
        """Indicates if the vulnerability has been mitigated."""

    @property
    @abstractmethod
    def accept_risk(self) -> bool:
        """Indicates if the risk has been accepted."""

    @property
    @abstractmethod
    def recast_risk(self) -> bool:
        """Indicates if the risk is being recast."""

    @property
    @abstractmethod
    def ip(self) -> str:
        """The IP address associated with the vulnerability."""

    @property
    @abstractmethod
    def uuid(self) -> Optional[str]:
        """Unique identifier for the vulnerability (optional)."""

    @property
    @abstractmethod
    def port(self) -> int:
        """The port number associated with the vulnerability."""

    @property
    @abstractmethod
    def protocol(self) -> str:
        """The protocol used (e.g., TCP, UDP)."""

    @property
    @abstractmethod
    def first_seen(self) -> datetime.datetime:
        """Datetime of when the vulnerability was first seen."""

    @property
    @abstractmethod
    def last_seen(self) -> datetime.datetime:
        """Timestamp of when the vulnerability was last seen."""

    @property
    @abstractmethod
    def exploit_available(self) -> bool:
        """Indicates if an exploit is available."""

    @property
    @abstractmethod
    def exploit_ease(self) -> Optional[str]:
        """Describes the ease of exploiting the vulnerability (optional)."""

    @property
    @abstractmethod
    def exploit_frameworks(self) -> Optional[list[str]]:
        """List of exploit frameworks available (optional)."""

    @property
    @abstractmethod
    def synopsis(self) -> Optional[str]:
        """Brief summary of the vulnerability (optional)."""

    @property
    @abstractmethod
    def description(self) -> Optional[str]:
        """Detailed description of the vulnerability (optional)."""

    @property
    @abstractmethod
    def solution(self) -> Optional[str]:
        """Recommended solution to address the vulnerability (optional)."""

    @property
    @abstractmethod
    def see_also(self) -> Optional[list[str]]:
        """Links to additional information about the vulnerability (optional)."""

    @property
    @abstractmethod
    def risk_factor(self) -> Optional[str]:
        """The risk factor associated with the vulnerability (optional)."""

    @property
    @abstractmethod
    def stig_severity(self) -> Optional[str]:
        """Severity rating according to STIG (optional)."""

    @property
    @abstractmethod
    def tenable_severity(self) -> str:
        """Severity rating according to Tenable."""

    @property
    @abstractmethod
    def vpr_score(self) -> Optional[float]:
        """Vulnerability Priority Rating (VPR) score (optional)."""

    @property
    @abstractmethod
    def vpr_context(self) -> Optional[list[str]]:
        """Context information related to the VPR (optional)."""

    @property
    @abstractmethod
    def base_score(self) -> Optional[float]:
        """Base score of the vulnerability according to CVSS (optional)."""

    @property
    @abstractmethod
    def temporal_score(self) -> Optional[float]:
        """Temporal score of the vulnerability (optional)."""

    @property
    @abstractmethod
    def cvss_vector(self) -> Optional[str]:
        """CVSS vector string representing the vulnerability's characteristics (optional)."""

    @property
    @abstractmethod
    def cvss_v3_base_score(self) -> Optional[float]:
        """CVSS v3 base score of the vulnerability (optional)."""

    @property
    @abstractmethod
    def cvss_v3_temporal_score(self) -> Optional[float]:
        """CVSS v3 temporal score of the vulnerability (optional)."""

    @property
    @abstractmethod
    def cvss_v3_vector(self) -> Optional[str]:
        """CVSS v3 vector string representing the vulnerability's characteristics (optional)."""

    @property
    @abstractmethod
    def vuln_pub_date(self) -> Optional[datetime.datetime]:
        """Publication date of the vulnerability (optional)."""

    @property
    @abstractmethod
    def patch_pub_date(self) -> Optional[datetime.datetime]:
        """Publication date of the patch for the vulnerability (optional)."""

    @property
    @abstractmethod
    def plugin_pub_date(self) -> Optional[datetime.datetime]:
        """Publication date of the plugin that discovered the vulnerability (optional)."""

    @property
    @abstractmethod
    def plugin_mod_date(self) -> Optional[datetime.datetime]:
        """Modification date of the plugin that discovered the vulnerability (optional)."""

    @property
    @abstractmethod
    def check_type(self) -> Optional[str]:
        """Type of check performed (local, remote, combined) (optional)."""

    @property
    @abstractmethod
    def version(self) -> Optional[str]:
        """Version of the plugin (optional)."""

    @property
    @abstractmethod
    def bid(self) -> Optional[list[str]]:
        """List of Bugtraq IDs associated with the vulnerability (optional)."""

    @property
    @abstractmethod
    def xref(self) -> Optional[list[str]]:
        """Cross-reference information related to the vulnerability (optional)."""

    @property
    @abstractmethod
    def seol_date(self) -> datetime.datetime:
        """SEO publication date (not optional)."""

    @property
    @abstractmethod
    def plugin_text(self) -> Optional[str]:
        """Text output from the plugin (optional)."""

    @property
    @abstractmethod
    def dns_name(self) -> Optional[str]:
        """DNS name associated with the vulnerability (optional)."""

    @property
    @abstractmethod
    def mac_address(self) -> Optional[str]:
        """MAC address associated with the vulnerability (optional)."""

    @property
    @abstractmethod
    def netbios_name(self) -> Optional[str]:
        """NetBIOS name associated with the vulnerability (optional)."""

    @property
    @abstractmethod
    def operating_system(self) -> Optional[str]:
        """Operating system details associated with the vulnerability (optional)."""

    @property
    @abstractmethod
    def recast_risk_rule_comment(self) -> Optional[list[str]]:
        """Comments regarding the recast risk rule (optional)."""

    @property
    @abstractmethod
    def accept_risk_rule_comment(self) -> Optional[list[str]]:
        """Comments regarding the accept risk rule (optional)."""

    @property
    @abstractmethod
    def host_uniqueness(self) -> list[str]:
        """Host uniqueness information for the vulnerability."""

    @property
    @abstractmethod
    def host_uuid(self) -> Optional[str]:
        """UUID of the host associated with the vulnerability (optional)."""

    @property
    @abstractmethod
    def acr_score(self) -> Optional[float]:
        """Access Control Risk score associated with the vulnerability (optional)."""

    @property
    @abstractmethod
    def asset_exposure_score(self) -> float:
        """Score representing the exposure of the asset."""

    @property
    @abstractmethod
    def vuln_uniqueness(self) -> list[str]:
        """Uniqueness information for the vulnerability."""

    @property
    @abstractmethod
    def vuln_uuid(self) -> Optional[str]:
        """UUID of the vulnerability (optional)."""

    @property
    @abstractmethod
    def uniqueness(self) -> list[str]:
        """Overall uniqueness of the vulnerability."""


class AssetPort(ABC):
    """Port to represent an asset."""

    @property
    @abstractmethod
    def id(self) -> str:
        """Unique identifier for the asset port."""

    @property
    @abstractmethod
    def uuid(self) -> str:
        """UUID of the asset port."""

    @property
    @abstractmethod
    def tenable_uuid(self) -> Optional[str]:
        """Tenable UUID associated with the asset."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the asset port."""

    @property
    @abstractmethod
    def operating_systems(self) -> Optional[list[str]]:
        """Operating systems installed of the asset port."""

    @property
    @abstractmethod
    def first_seen(self) -> datetime.datetime:
        """Datetime of when the asset was first seen."""

    @property
    @abstractmethod
    def last_seen(self) -> datetime.datetime:
        """Datetime of when the asset was last seen."""

    @property
    @abstractmethod
    def mac_address(self) -> Optional[str]:
        """MAC address associated with the asset port."""

    @property
    @abstractmethod
    def created_time(self) -> datetime.datetime:
        """Datetime of when the asset was created."""

    @property
    @abstractmethod
    def modified_time(self) -> datetime.datetime:
        """Datetime of the last modification of the asset."""

    @property
    @abstractmethod
    def ip_address(self) -> str:
        """IP address of the asset port."""

    @property
    @abstractmethod
    def repository_id(self) -> str:
        """Repository ID associated with the asset."""

    @property
    @abstractmethod
    def findings(
        self,
    ) -> Iterable[FindingPort]:
        """Related found vulnerabilities."""


class AssetsChunkPort(ABC):
    """Interface for assets chunk."""

    @property
    @abstractmethod
    def assets(self) -> Iterable[AssetPort]:
        """Assets in chunk."""


class AssetsPort(ABC):
    """Interface for assets retrivela by chunks."""

    @property
    @abstractmethod
    def chunks(self) -> Iterable[AssetsChunkPort]:
        """Chunks of Asset."""

    @property
    @abstractmethod
    def since_datetime(self) -> datetime.datetime:
        """Datetime since the time range."""

    @since_datetime.setter
    @abstractmethod
    def since_datetime(self, since_datetime: datetime.datetime) -> None:
        """Datetime since the time range."""
