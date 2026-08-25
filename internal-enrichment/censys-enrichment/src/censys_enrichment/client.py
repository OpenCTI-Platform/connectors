import time
from dataclasses import dataclass, field
from typing import Generator
from urllib.parse import urlparse

import requests
from censys_platform import (
    SDK,
    Certificate,
    Host,
    SearchQueryInputBody,
    V3GlobaldataSearchQueryResponse,
)

_NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class NVDReference:
    """A single reference entry from the NVD CVE API."""

    url: str
    source_name: str


@dataclass
class NVDAffectedSoftware:
    """Affected software entry parsed from NVD CPE 2.3 configurations.

    Populated for application-type (``cpe:2.3:a:``) CPE match entries where
    ``vulnerable`` is ``True``.  At most 10 unique vendor+product pairs are
    stored per CVE to avoid flooding OpenCTI with low-signal entries.
    """

    vendor: str
    product: str
    cpe: str
    version_info: str | None = None  # exact version or human-readable range


@dataclass
class NVDData:
    """Enrichment data for a single CVE fetched from the NVD CVE 2.0 API."""

    description: str | None = None
    # NVD-provided severity label (uppercase: CRITICAL / HIGH / MEDIUM / LOW)
    cvss_v3_base_severity: str | None = None
    cvss_v2_base_score: float | None = None
    cvss_v2_vector_string: str | None = None
    cvss_v2_access_vector: str | None = None
    cvss_v2_access_complexity: str | None = None
    cvss_v2_authentication: str | None = None
    cvss_v2_confidentiality_impact: str | None = None
    cvss_v2_integrity_impact: str | None = None
    cvss_v2_availability_impact: str | None = None
    references: list[NVDReference] = field(default_factory=list)
    affected_software: list[NVDAffectedSoftware] = field(default_factory=list)


class EntityHasNoUsableHashError(Exception):
    """Custom exception for entity having no usable hash"""


class Client:
    def __init__(self, organisation_id: str, token: str, nvd_api_key: str | None = None):
        self.organisation_id = organisation_id
        self.token = token
        self._nvd_api_key = nvd_api_key

    def fetch_ip(self, ip: str) -> Host:
        """Fetch host data for a given IP address from Censys.
        Args:
            ip (str): The IP address to fetch data for.
        Returns:
            Host: The host data retrieved from Censys.
        Raises:
            ValueError: If no data is found for the given IP address.
        """
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            res = sdk.global_data.get_host(host_id=ip)
            if host_asset := res.result.result:
                return host_asset.resource
            raise ValueError(f"No data found for IP {ip}")

    def fetch_certs(self, hashes: dict[str, str]) -> Generator[Certificate, None, None]:
        """Fetch certificates by their hashes

        Args:
            hashes (dict[str, str]): A dictionary containing one or more of the following keys
                with their corresponding hash values:
                    - "MD5"
                    - "SHA-1"
                    - "SHA-256"
        Yields:
            Certificate: Censys Certificate objects matching the provided hashes.
        Raises:
            EntityHasNoUsableHashError: If none of the required hashes are provided.
        """
        if not any(h in hashes for h in ("MD5", "SHA-1", "SHA-256")):
            raise EntityHasNoUsableHashError(
                "At least one hash (MD5, SHA1, SHA256) must be provided."
            )
        parts = []
        if "MD5" in hashes:
            parts.append(f'cert.fingerprint_md5 = "{hashes["MD5"]}"')
        if "SHA-1" in hashes:
            parts.append(f'cert.fingerprint_sha1 = "{hashes["SHA-1"]}"')
        if "SHA-256" in hashes:
            parts.append(f'cert.fingerprint_sha256 = "{hashes["SHA-256"]}"')
        query = " or ".join(parts)
        search_query = SearchQueryInputBody(query=query)
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            res: V3GlobaldataSearchQueryResponse = sdk.global_data.search(
                search_query_input_body=search_query
            )
            if res.result.result:
                for hit in res.result.result.hits if isinstance(res.result.result.hits, list) else []:
                    if hit.certificate_v1:
                        yield hit.certificate_v1.resource

    def fetch_hosts(self, hostname: str) -> Generator[Host, None, None]:
        """Fetch hosts by hostname
        Args:
            hostname (str): The hostname to search for.
        Yields:
            Generator[Host, None, None]: Yields Host objects matching the hostname.
        """
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            query = f"host.dns.names = '{hostname}'"
            search_query = SearchQueryInputBody(query=query)
            res: V3GlobaldataSearchQueryResponse = sdk.global_data.search(
                search_query_input_body=search_query
            )
            if res.result.result:
                for hit in res.result.result.hits if isinstance(res.result.result.hits, list) else []:
                    if hit.host_v1:
                        yield hit.host_v1.resource

    def fetch_certs_by_domain(self, domain: str) -> Generator[Certificate, None, None]:
        """Fetch certificates that reference a domain in their names

        Args:
            domain (str): The domain name to search for.

        Yields:
            Generator[Certificate, None, None]: Yields Certificate objects matching the domain.
        """
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            query = f"cert.names = '{domain}'"
            search_query = SearchQueryInputBody(query=query)
            res: V3GlobaldataSearchQueryResponse = sdk.global_data.search(
                search_query_input_body=search_query
            )
            if res.result.result:
                for hit in res.result.result.hits if isinstance(res.result.result.hits, list) else []:
                    if hit.certificate_v1:
                        yield hit.certificate_v1.resource

    def fetch_nvd_data(self, cve_id: str) -> NVDData | None:
        """Fetch enrichment data for a single CVE from the NVD CVE 2.0 API.
        Args:
            cve_id (str): A CVE identifier such as ``"CVE-2021-44228"``.
        Returns:
            NVDData | None: An NVDData instance populated with description, CVSS
            v2/v3 severity, and external references, or ``None`` if the CVE is
            not found, the API is unavailable, or the response contains no
            useful data.
        """
        try:
            headers = {"apiKey": self._nvd_api_key} if self._nvd_api_key else {}
            response = None
            for attempt in range(2):
                response = requests.get(
                    _NVD_CVE_API,
                    params={"cveId": cve_id},
                    headers=headers,
                    timeout=10,
                )
                if response.status_code == 403 and attempt == 0:
                    # NVD returns 403 when the rate limit is exhausted.
                    # Wait for the 30-second rolling window to reset and retry once.
                    time.sleep(30)
                    continue
                response.raise_for_status()
                break
            if response is None:
                return None
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            cve = vulns[0].get("cve", {})
            result = NVDData()

            # English description
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    result.description = desc.get("value") or None
                    break

            # CVSS severity — prefer v3.1 over v3.0
            metrics = cve.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30"):
                for entry in metrics.get(metric_key, []):
                    severity = entry.get("cvssData", {}).get("baseSeverity")
                    if severity:
                        result.cvss_v3_base_severity = severity.upper()
                        break
                if result.cvss_v3_base_severity:
                    break

            # CVSS v2 — take the first (primary) entry only
            for entry in metrics.get("cvssMetricV2", []):
                d = entry.get("cvssData", {})
                result.cvss_v2_base_score = d.get("baseScore")
                result.cvss_v2_vector_string = d.get("vectorString")
                result.cvss_v2_access_vector = d.get("accessVector")
                result.cvss_v2_access_complexity = d.get("accessComplexity")
                result.cvss_v2_authentication = d.get("authentication")
                result.cvss_v2_confidentiality_impact = d.get("confidentialityImpact")
                result.cvss_v2_integrity_impact = d.get("integrityImpact")
                result.cvss_v2_availability_impact = d.get("availabilityImpact")
                break

            # External references (capped at 20 to avoid flooding OpenCTI)
            for ref in cve.get("references", [])[:20]:
                url = ref.get("url", "")
                if not url:
                    continue
                tags = ref.get("tags", [])
                if tags:
                    source_name = ", ".join(tags[:3])
                else:
                    parsed = urlparse(url)
                    source_name = parsed.netloc or ref.get("source") or "NVD Reference"
                result.references.append(NVDReference(url=url, source_name=source_name))

            # Affected software from CPE 2.3 configurations.
            # Only application-type entries (cpe:2.3:a:...) where vulnerable=True
            # are included, deduplicated by vendor+product, capped at 10.
            seen_sw: dict[tuple[str, str], NVDAffectedSoftware] = {}
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable", False):
                            continue
                        criteria = match.get("criteria", "")
                        parts = criteria.split(":")
                        # cpe:2.3:<part>:<vendor>:<product>:<version>:...
                        if len(parts) < 6 or parts[2] != "a":
                            continue
                        vendor = parts[3].replace("_", " ").title()
                        product = parts[4].replace("_", " ").title()
                        if vendor in ("*", "") or product in ("*", ""):
                            continue
                        key = (vendor.lower(), product.lower())
                        if key in seen_sw or len(seen_sw) >= 10:
                            continue
                        # Build version info: prefer explicit range over exact CPE version
                        cpe_ver = parts[5] if len(parts) > 5 else "*"
                        vsi = match.get("versionStartIncluding")
                        vse = match.get("versionStartExcluding")
                        vei = match.get("versionEndIncluding")
                        vee = match.get("versionEndExcluding")
                        if vsi or vse or vei or vee:
                            range_parts: list[str] = []
                            if vsi:
                                range_parts.append(f">= {vsi}")
                            elif vse:
                                range_parts.append(f"> {vse}")
                            if vei:
                                range_parts.append(f"<= {vei}")
                            elif vee:
                                range_parts.append(f"< {vee}")
                            version_info: str | None = ", ".join(range_parts) or None
                        elif cpe_ver and cpe_ver != "*":
                            version_info = cpe_ver
                        else:
                            version_info = None
                        seen_sw[key] = NVDAffectedSoftware(
                            vendor=vendor,
                            product=product,
                            cpe=criteria,
                            version_info=version_info,
                        )
            result.affected_software = list(seen_sw.values())

            # Return None if the response contained nothing actionable
            if not any(
                [
                    result.description,
                    result.cvss_v3_base_severity,
                    result.cvss_v2_base_score is not None,
                    result.references,
                ]
            ):
                return None

            return result
        except Exception:
            pass
        return None
