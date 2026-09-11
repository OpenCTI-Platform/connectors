import datetime
import ipaddress
from typing import Any, Callable, Generator

from censys_platform import (
    Attribute,
    Certificate,
    CobaltStrike,
    CobaltStrikeConfig,
    Coordinates,
    Darkcomet,
    Darkgate,
    Dcerpc,
    Ftp,
    Host,
    HostDNS,
    Label,
    Ldap,
    Mongodb,
    Rdp,
    Redis,
    Redline,
    Risk,
    Smb,
    SMTP,
    Snmp,
    SSH,
    Service,
    Telnet,
    Threat,
    Vnc,
    Vuln,
    Winrm,
)
from connectors_sdk.models import (
    AdministrativeArea,
    AutonomousSystem,
    BaseObject,
    City,
    Country,
    DomainName,
    EmailAddress,
    ExternalReference,
    Hostname,
    IPV4Address,
    IPV6Address,
    Malware,
    Note,
    Organization,
    OrganizationAuthor,
    Reference,
    Region,
    Relationship,
    Software,
    TLPMarking,
    Vulnerability,
    X509Certificate,
)
from connectors_sdk.models.enums import (
    CvssSeverity,
    HashAlgorithm,
    RelationshipType,
    TLPLevel,
)

from censys_enrichment.client import NVDData

# Maps common lowercase severity strings (from Censys or NVD) to the SDK enum.
_SEVERITY_MAP: dict[str, CvssSeverity] = {
    "critical": CvssSeverity.CRITICAL,
    "high": CvssSeverity.HIGH,
    "medium": CvssSeverity.MEDIUM,
    "low": CvssSeverity.LOW,
}


def _cvss_component(obj: Any, attr: str) -> str | None:
    """Return a CVSS component enum value as an uppercase string, or None if absent."""
    if obj is None:
        return None
    val = getattr(obj, attr, None)
    if val is None:
        return None
    raw: str = getattr(val, "value", "")
    return raw.upper() if raw else None


class Converter:
    def __init__(self) -> None:
        self.author = OrganizationAuthor(name="Censys Enrichment Connector")  # type: ignore[call-arg]
        self.marking = TLPMarking(level=TLPLevel.CLEAR)
        self._common_props = {"author": self.author, "markings": [self.marking]}

    def _generate_city(
        self, observable: Reference, name: str | None
    ) -> Generator[BaseObject, None, None]:
        if not name:
            return

        city = City(
            name=name,
            **self._common_props,
        )
        yield from [
            city,
            Relationship(
                source=observable,
                target=city,
                type=RelationshipType.LOCATED_AT,
                **self._common_props,
            ),
        ]

    def _generate_country(
        self, observable: Reference, name: str | None
    ) -> Generator[BaseObject, None, Country | None]:
        if not name:
            return None

        country = Country(
            name=name,
            **self._common_props,
        )
        yield from [
            country,
            Relationship(
                source=observable,
                target=country,
                type=RelationshipType.LOCATED_AT,
                **self._common_props,
            ),
        ]
        return country

    def _generate_region(
        self, observable: Reference, name: str | None
    ) -> Generator[BaseObject, None, None]:
        if not name:
            return

        region = Region(
            name=name,
            **self._common_props,
        )
        yield from [
            region,
            Relationship(
                source=observable,
                target=region,
                type=RelationshipType.LOCATED_AT,
                **self._common_props,
            ),
        ]

    def _generate_administrative_area(
        self,
        observable: Reference,
        name: str | None,
        coordinates: Coordinates | None,
    ) -> Generator[BaseObject, None, None]:
        if not name:
            return

        administrative_area = (
            AdministrativeArea(
                name=name,
                latitude=coordinates.latitude,
                longitude=coordinates.longitude,
                **self._common_props,
            )
            if coordinates
            else AdministrativeArea(
                name=name,
                **self._common_props,
            )
        )

        yield from [
            administrative_area,
            Relationship(
                source=observable,
                target=administrative_area,
                type=RelationshipType.LOCATED_AT,
                **self._common_props,
            ),
        ]

    def _generate_hostnames(
        self, observable: Reference, dns: HostDNS | None
    ) -> Generator[BaseObject, None, None]:
        if not dns:
            return

        # Combine forward DNS names with reverse DNS PTR records, deduplicating
        # so a name that appears in both doesn't produce duplicate observables.
        seen: set[str] = set()
        all_names = list(dns.names if isinstance(dns.names, list) else [])
        if dns.reverse_dns:
            all_names.extend(
                dns.reverse_dns.names
                if isinstance(dns.reverse_dns.names, list)
                else []
            )

        for name in all_names:
            if name in seen:
                continue
            seen.add(name)
            host_name = Hostname(
                value=name,
                **self._common_props,
            )
            yield from [
                host_name,
                Relationship(
                    source=host_name,
                    target=observable,
                    type=RelationshipType.RESOLVES_TO,
                    **self._common_props,
                ),
            ]

    def _generate_organization(
        self,
        observable: Reference,
        name: str | None,
    ) -> Generator[BaseObject, None, Organization | None]:
        if not name:
            return None

        organization = Organization(
            name=name,
            **self._common_props,
        )
        yield from [
            organization,
            Relationship(
                source=observable,
                target=organization,
                type=RelationshipType.RELATED_TO,
                **self._common_props,
            ),
        ]
        return organization

    def _generate_autonomous_system(
        self,
        observable: Reference,
        number: int | None,
        name: str | None,
        description: str | None,
    ) -> Generator[BaseObject, None, AutonomousSystem | None]:
        if not number:
            return None

        autonomous_system = AutonomousSystem(
            name=name,
            description=description,
            number=number,
            **self._common_props,
        )
        yield from [
            autonomous_system,
            Relationship(
                source=observable,
                target=autonomous_system,
                type=RelationshipType.BELONGS_TO,
                **self._common_props,
            ),
        ]
        return autonomous_system

    def _generate_software(
        self,
        observable: Reference,
        name: str | None,
        vendor: str | None,
        cpe: str | None,
        version: str | None = None,
    ) -> Generator[BaseObject, None, Software | None]:
        if not name:
            return None

        software = Software(
            name=name,
            vendor=vendor,
            cpe=cpe,
            version=version,
            **self._common_props,
        )
        yield from [
            software,
            Relationship(
                source=observable,
                target=software,
                type=RelationshipType.RELATED_TO,
                **self._common_props,
            ),
        ]
        return software

    def _generate_vulnerability(
        self,
        observable: Reference,
        vuln: Vuln,
        nvd_data: NVDData | None = None,
    ) -> Generator[BaseObject, None, None]:
        # Use the CVE/Censys ID as the name; fall back to the human-readable name
        name = vuln.id or vuln.name
        if not name:
            return

        # Prefer CVSSv3.1 > v3.0 for v3 scoring; also pick up v4 if available
        cvss3 = None
        cvss4 = None
        if vuln.metrics:
            cvss3 = vuln.metrics.cvss_v31 or vuln.metrics.cvss_v30
            cvss4 = vuln.metrics.cvss_v40

        epss_score = None
        epss_percentile = None
        if vuln.metrics and vuln.metrics.epss:
            epss_score = vuln.metrics.epss.score
            epss_percentile = vuln.metrics.epss.percentile

        # True if any KEV entry is present (CISA Known Exploited Vulnerability)
        is_kev = isinstance(vuln.kev, list) and len(vuln.kev) > 0

        # OpenCTI's CVSS4 vector validator rejects non-base vectors (e.g. those
        # that include Censys supplemental/environmental metrics).  We drop the
        # vector string entirely and rely on the individual component fields and
        # base score, which OpenCTI accepts without validation.
        cvss4_score = cvss4.score if cvss4 else None

        # --- CVSS v3 components (from Censys) ---
        cvss3_comps = cvss3.components if cvss3 else None

        # --- CVSS v4 components (from Censys) ---
        cvss4_comps = cvss4.components if cvss4 else None

        # --- CVSS v3 severity: prefer NVD (authoritative) then Censys ---
        cvss3_severity: CvssSeverity | None = None
        if nvd_data and nvd_data.cvss_v3_base_severity:
            cvss3_severity = _SEVERITY_MAP.get(nvd_data.cvss_v3_base_severity.lower())
        if cvss3_severity is None and vuln.severity and vuln.severity.value:
            cvss3_severity = _SEVERITY_MAP.get(vuln.severity.value.lower())

        # --- CWE labels (from Censys) ---
        cwes: list[str] = [
            cwe.entry
            for cwe in (vuln.cwes if isinstance(vuln.cwes, list) else [])
            if cwe.entry
        ]

        # --- Description: prefer NVD then vuln.name fallback ---
        final_description = (nvd_data.description if nvd_data else None) or (
            vuln.name if vuln.name != name else None
        )

        # --- External references from NVD ---
        ext_refs: list[ExternalReference] = [
            ExternalReference(source_name=ref.source_name, url=ref.url)
            for ref in (nvd_data.references if nvd_data else [])
        ]

        # Build as a dict so a single type:ignore suppresses all inherited-field
        # false-positives from Pyright's incomplete Pydantic v2 multi-inheritance
        # synthesis (all fields are valid at runtime — 62 tests confirm this).
        vuln_kwargs: dict[str, Any] = {
            "name": name,
            "description": final_description,
            "labels": cwes or None,
            "external_references": ext_refs or None,
            # CVSS v3
            "cvss_v3_base_score": cvss3.score if cvss3 else None,
            "cvss_v3_vector_string": cvss3.vector if cvss3 else None,
            "cvss_v3_base_severity": cvss3_severity,
            "cvss_v3_attack_vector": _cvss_component(cvss3_comps, "attack_vector"),
            "cvss_v3_attack_complexity": _cvss_component(cvss3_comps, "attack_complexity"),
            "cvss_v3_privileges_required": _cvss_component(cvss3_comps, "privileges_required"),
            "cvss_v3_user_interaction": _cvss_component(cvss3_comps, "user_interaction"),
            "cvss_v3_scope": _cvss_component(cvss3_comps, "scope"),
            "cvss_v3_confidentiality_impact": _cvss_component(cvss3_comps, "confidentiality"),
            "cvss_v3_integrity_impact": _cvss_component(cvss3_comps, "integrity"),
            "cvss_v3_availability_impact": _cvss_component(cvss3_comps, "availability"),
            # CVSS v4
            "cvss_v4_base_score": cvss4_score,
            "cvss_v4_vector_string": None,
            "cvss_v4_attack_vector": _cvss_component(cvss4_comps, "attack_vector"),
            "cvss_v4_attack_complexity": _cvss_component(cvss4_comps, "attack_complexity"),
            "cvss_v4_attack_requirements": _cvss_component(cvss4_comps, "attack_requirements"),
            "cvss_v4_privileges_required": _cvss_component(cvss4_comps, "privileges_required"),
            "cvss_v4_user_interaction": _cvss_component(cvss4_comps, "user_interaction"),
            "cvss_v4_vs_confidentiality_impact": _cvss_component(cvss4_comps, "confidentiality"),
            "cvss_v4_vs_integrity_impact": _cvss_component(cvss4_comps, "integrity"),
            "cvss_v4_vs_availability_impact": _cvss_component(cvss4_comps, "availability"),
            # CVSS v2 (from NVD)
            "cvss_v2_base_score": nvd_data.cvss_v2_base_score if nvd_data else None,
            "cvss_v2_vector_string": nvd_data.cvss_v2_vector_string if nvd_data else None,
            "cvss_v2_access_vector": nvd_data.cvss_v2_access_vector if nvd_data else None,
            "cvss_v2_access_complexity": nvd_data.cvss_v2_access_complexity if nvd_data else None,
            "cvss_v2_authentication": nvd_data.cvss_v2_authentication if nvd_data else None,
            "cvss_v2_confidentiality_impact": nvd_data.cvss_v2_confidentiality_impact if nvd_data else None,
            "cvss_v2_integrity_impact": nvd_data.cvss_v2_integrity_impact if nvd_data else None,
            "cvss_v2_availability_impact": nvd_data.cvss_v2_availability_impact if nvd_data else None,
            # EPSS + CISA KEV
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "is_cisa_kev": True if is_kev else None,
            **self._common_props,
        }
        vulnerability = Vulnerability(**vuln_kwargs)  # type: ignore[call-arg]
        yield vulnerability
        yield Relationship(
            source=observable,
            target=vulnerability,
            type=RelationshipType.RELATED_TO,
            **self._common_props,
        )
        # Software observables for each NVD-listed affected package.
        # Linked via RELATED_TO rather than HAS: Software→HAS→Vulnerability is
        # not universally accepted across OpenCTI v7 builds, whereas RELATED_TO
        # is always valid between any two STIX objects.
        for sw_entry in nvd_data.affected_software if nvd_data else []:
            software = Software(
                name=sw_entry.product,
                vendor=sw_entry.vendor,
                cpe=sw_entry.cpe,
                version=sw_entry.version_info,
                **self._common_props,
            )
            yield software
            yield Relationship(
                source=software,
                target=vulnerability,
                type=RelationshipType.RELATED_TO,
                **self._common_props,
            )

    def _generate_malware(
        self,
        observable: Reference,
        threat: Threat,
    ) -> Generator[BaseObject, None, None]:
        # Prefer the malware family name; fall back to the generic threat name
        name = None
        if threat.malware:
            name = threat.malware.primary_name
        if not name:
            name = threat.name
        if not name:
            return

        # Collect all known names as aliases
        all_names = (
            list(threat.malware.all_names)
            if threat.malware and isinstance(threat.malware.all_names, list)
            else []
        )
        aliases = [n for n in all_names if n != name] or None

        # External reference to Malpedia if we have an ID
        ext_refs: list[ExternalReference] = []
        if threat.malware and threat.malware.malpedia_id:
            ext_refs.append(
                ExternalReference(
                    source_name="Malpedia",
                    url=f"https://malpedia.caad.fkie.fraunhofer.de/details/{threat.malware.malpedia_id}",
                    external_id=threat.malware.malpedia_id,
                )
            )

        # Build a brief description from threat metadata
        desc_parts: list[str] = []
        if threat.details and threat.details.campaign_id:
            desc_parts.append(f"Campaign: {threat.details.campaign_id}")
        if threat.details and threat.details.campaign_theme:
            desc_parts.append(f"Theme: {threat.details.campaign_theme}")
        if threat.details and isinstance(threat.details.control_servers, list):
            desc_parts.append(
                "C2 servers: " + ", ".join(threat.details.control_servers)
            )

        malware = Malware(
            name=name,
            is_family=True,
            aliases=aliases,
            description="\n".join(desc_parts) if desc_parts else None,
            external_references=ext_refs if ext_refs else None,  # type: ignore[call-arg]
            **self._common_props,
        )
        yield from [
            malware,
            Relationship(
                source=observable,
                target=malware,
                type=RelationshipType.RELATED_TO,
                **self._common_props,
            ),
        ]

    def _build_banner_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a Banner section with the raw service banner in a code block."""
        if not service.banner:
            return None
        return f"### Banner\n\n```\n{service.banner.strip()}\n```", []

    def _build_fingerprints_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a Fingerprints section with TLS/JARM/JA4TScan data."""
        sub_sections: list[str] = []
        if service.tls:
            tls_lines: list[str] = ["#### TLS"]
            if service.tls.version_selected:
                tls_lines.append(f"**Version:** {service.tls.version_selected}")
            if service.tls.cipher_selected:
                tls_lines.append(f"**Cipher:** {service.tls.cipher_selected}")
            if service.tls.ja3s:
                tls_lines.append(f"**JA3S:** `{service.tls.ja3s}`")
            if service.tls.ja4s:
                tls_lines.append(f"**JA4S:** `{service.tls.ja4s}`")
            if len(tls_lines) > 1:
                sub_sections.append("\n\n".join(tls_lines))
        if service.ja4tscan and service.ja4tscan.fingerprint:
            sub_sections.append(
                f"#### JA4TScan\n\n**Fingerprint:** `{service.ja4tscan.fingerprint}`"
            )
        if service.jarm and service.jarm.fingerprint:
            jarm_lines: list[str] = ["#### JARM"]
            jarm_lines.append(f"**Fingerprint:** `{service.jarm.fingerprint}`")
            if service.jarm.cipher_and_version_fingerprint:
                jarm_lines.append(
                    f"**Cipher/Version:** `{service.jarm.cipher_and_version_fingerprint}`"
                )
            if service.jarm.tls_extensions_sha256:
                jarm_lines.append(
                    f"**TLS Extensions SHA256:** `{service.jarm.tls_extensions_sha256}`"
                )
            sub_sections.append("\n\n".join(jarm_lines))
        if not sub_sections:
            return None
        return "### Fingerprints\n\n" + "\n\n".join(sub_sections), []

    def _generate_cobalt_strike_note(
        self,
        observable: Reference,
        service: Service,
    ) -> Generator[BaseObject, None, None]:
        """Yield a Note for each endpoint scan that contains Cobalt Strike beacon data.

        Cobalt Strike configuration lives on ``EndpointScanState`` objects within
        ``service.endpoints``, not on the ``Service`` directly.  Each architecture
        (x64 / x86) is rendered as a labelled section so analysts can immediately
        see the per-arch C2 settings extracted by Censys.
        """
        for endpoint in (
            service.endpoints if isinstance(service.endpoints, list) else []
        ):
            if not endpoint.cobalt_strike:
                continue

            port = endpoint.port or service.port
            scan_time = endpoint.scan_time or service.scan_time
            if not (port and scan_time):
                continue

            cs: CobaltStrike = endpoint.cobalt_strike

            def _escape_header(s: str) -> str:
                """Escape control/non-printable bytes as \\xNN so they survive markdown rendering."""
                return s.encode("unicode_escape").decode("ascii")

            def _format_arch(arch: str, cfg: CobaltStrikeConfig) -> list[str]:
                section: list[str] = [f"### Arch: {arch}"]
                if cfg.user_agent:
                    section.append(f"**User-Agent:** {cfg.user_agent}")
                if cfg.sleep_time is not None:
                    section.append(f"**Sleep Time:** {cfg.sleep_time} ms")
                if cfg.jitter is not None:
                    section.append(f"**Jitter:** {cfg.jitter}")
                if cfg.dns is not None:
                    section.append(f"**DNS Enabled:** {cfg.dns}")
                if cfg.ssl is not None:
                    section.append(f"**SSL:** {cfg.ssl}")
                if cfg.cookie_beacon is not None:
                    section.append(f"**Cookie Beacon:** {cfg.cookie_beacon}")
                if cfg.killdate is not None:
                    section.append(f"**Killdate:** {cfg.killdate}")
                if cfg.watermark is not None:
                    section.append(f"**Watermark:** {cfg.watermark}")
                if cfg.crypto_scheme is not None:
                    section.append(f"**Crypto Scheme:** {cfg.crypto_scheme}")
                if cfg.host_header:
                    section.append(f"**Host Header:** {cfg.host_header}")
                if cfg.http_get:
                    section.append(
                        f"**GET** `{cfg.http_get.verb or 'GET'} {cfg.http_get.uri or ''}`"
                    )
                    if cfg.http_get.client:
                        section.append(f"**Headers (bytes):** `{_escape_header(cfg.http_get.client)}`")
                if cfg.http_post:
                    section.append(
                        f"**POST** `{cfg.http_post.verb or 'POST'} {cfg.http_post.uri or ''}`"
                    )
                    if cfg.http_post.client:
                        section.append(f"**Headers (bytes):** `{_escape_header(cfg.http_post.client)}`")
                if cfg.post_ex:
                    if cfg.post_ex.x64:
                        section.append(f"**Post-Ex x64:** `{cfg.post_ex.x64}`")
                    if cfg.post_ex.x86:
                        section.append(f"**Post-Ex x86:** `{cfg.post_ex.x86}`")
                if cfg.public_key:
                    section.append(f"**Public Key:** `{cfg.public_key}`")
                return section

            blocks: list[str] = []
            if cs.x64:
                blocks.extend(_format_arch("x64", cs.x64))
            if cs.x86:
                if blocks:
                    blocks.append("")
                blocks.extend(_format_arch("x86", cs.x86))

            if not blocks:
                continue

            yield Note(
                abstract=f"Cobalt Strike beacon configuration on port {port}",
                content="\n\n".join(blocks),
                publication_date=datetime.datetime.fromisoformat(scan_time),
                authors=[self.author.name],
                objects=[observable],
                labels=["cobalt-strike", "malware", f"port:{port}"],
                **self._common_props,
            )

    def _build_dcerpc_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a DCERPC section listing RPC endpoint bindings."""
        if not service.dcerpc:
            return None
        dcerpc: Dcerpc = service.dcerpc
        endpoints = dcerpc.endpoints if isinstance(dcerpc.endpoints, list) else []
        if not endpoints:
            return None
        lines: list[str] = []
        if dcerpc.could_query_epm is not None:
            lines.append(f"**EPM Queryable:** {dcerpc.could_query_epm}")
        ep_lines: list[str] = []
        for ep in endpoints:
            exe = ep.executable or "unknown"
            proto = ep.protocol or ep.explained_uuid or ""
            ep_lines.append(f"- **{exe}** — {proto}" if proto else f"- **{exe}**")
        if ep_lines:
            lines.append("#### Endpoints\n\n" + "\n".join(ep_lines))
        if not lines:
            return None
        return "### DCERPC\n\n" + "\n\n".join(lines), ["dcerpc", "rpc"]

    def _build_rdp_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return an RDP section with protocol version and security details."""
        if not service.rdp:
            return None
        rdp: Rdp = service.rdp
        lines: list[str] = []
        if rdp.version:
            v = rdp.version
            version_str = v.raw or f"{v.major}.{v.minor}"
            lines.append(f"**Version:** {version_str}")
        if rdp.selected_security_protocol:
            lines.append(f"**Security Protocol:** {rdp.selected_security_protocol}")
        if rdp.certificate_info and rdp.certificate_info.proprietary_rsa_key:
            lines.append(f"**RSA Key:** `{rdp.certificate_info.proprietary_rsa_key}`")
        if not lines:
            return None
        return "### RDP\n\n" + "\n\n".join(lines), ["rdp", "remote-desktop"]

    def _build_ssh_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return an SSH section with banner, HASSH, host key, and algorithm info."""
        if not service.ssh:
            return None
        ssh: SSH = service.ssh
        lines: list[str] = []
        if ssh.endpoint_id:
            if ssh.endpoint_id.raw:
                lines.append(f"**Banner:** `{ssh.endpoint_id.raw}`")
            elif ssh.endpoint_id.software_version:
                lines.append(f"**Software:** `{ssh.endpoint_id.software_version}`")
        if ssh.hassh_fingerprint:
            lines.append(f"**HASSH:** `{ssh.hassh_fingerprint}`")
        if ssh.server_host_key and ssh.server_host_key.fingerprint_sha256:
            lines.append(f"**Host Key SHA256:** `{ssh.server_host_key.fingerprint_sha256}`")
        if ssh.algorithm_selection:
            if ssh.algorithm_selection.kex_algorithm:
                lines.append(f"**KEX Algorithm:** {ssh.algorithm_selection.kex_algorithm}")
            if ssh.algorithm_selection.host_key_algorithm:
                lines.append(f"**Host Key Algorithm:** {ssh.algorithm_selection.host_key_algorithm}")
        if not lines:
            return None
        return "### SSH\n\n" + "\n\n".join(lines), ["ssh"]

    def _build_smb_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return an SMB section with OS, workgroup/domain, dialect, and NTLM target."""
        if not service.smb:
            return None
        smb: Smb = service.smb
        lines: list[str] = []
        if smb.native_os:
            lines.append(f"**OS:** {smb.native_os}")
        if smb.group_name:
            lines.append(f"**Workgroup/Domain:** {smb.group_name}")
        if smb.smb_version and smb.smb_version.version_string:
            lines.append(f"**SMB Version:** {smb.smb_version.version_string}")
        if smb.smbv1_support is not None:
            lines.append(f"**SMBv1 Support:** {smb.smbv1_support}")
        if smb.negotiation_log:
            if smb.negotiation_log.dialect_revision:
                lines.append(f"**Dialect:** {smb.negotiation_log.dialect_revision}")
            if smb.negotiation_log.server_guid:
                lines.append(f"**Server GUID:** `{smb.negotiation_log.server_guid}`")
        if smb.session_setup_log and smb.session_setup_log.target_name:
            lines.append(f"**NTLM Target:** {smb.session_setup_log.target_name}")
        if not lines:
            return None
        return "### SMB\n\n" + "\n\n".join(lines), ["smb"]

    def _build_vnc_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a VNC section with version, desktop name, and security types."""
        if not service.vnc:
            return None
        vnc: Vnc = service.vnc
        lines: list[str] = []
        if vnc.version:
            lines.append(f"**Version:** {vnc.version}")
        if vnc.desktop_name:
            lines.append(f"**Desktop:** {vnc.desktop_name}")
        if vnc.connection_failed_reason:
            lines.append(f"**Connection Failed:** {vnc.connection_failed_reason}")
        security_types = vnc.security_types if isinstance(vnc.security_types, list) else []
        if security_types:
            types_str = ", ".join(f"{st.name}={st.value}" for st in security_types if st.name)
            if types_str:
                lines.append(f"**Security Types:** {types_str}")
        if vnc.screen_info:
            lines.append(f"**Screen:** {vnc.screen_info.width}x{vnc.screen_info.height}")
        if not lines:
            return None
        return "### VNC\n\n" + "\n\n".join(lines), ["vnc", "remote-desktop"]

    def _build_ldap_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return an LDAP section with anonymous bind status and base DSE attributes."""
        if not service.ldap:
            return None
        ldap: Ldap = service.ldap
        lines: list[str] = []
        if ldap.allows_anonymous_bind is not None:
            lines.append(f"**Anonymous Bind:** {ldap.allows_anonymous_bind}")
        if ldap.result_code is not None:
            lines.append(f"**Result Code:** {ldap.result_code}")
        _INTERESTING_ATTRS = {
            "defaultNamingContext", "rootDomainNamingContext", "dnsHostName",
            "ldapServiceName", "serverName", "supportedSASLMechanisms",
        }
        for attr in ldap.attributes or []:
            if attr.name in _INTERESTING_ATTRS:
                val = ", ".join(attr.values or [])
                lines.append(f"**{attr.name}:** {val}")
        if not lines:
            return None
        return "### LDAP\n\n" + "\n\n".join(lines), ["ldap"]

    def _build_winrm_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a WinRM section with NTLM domain, computer name, and OS version."""
        if not service.winrm:
            return None
        winrm: Winrm = service.winrm
        if not winrm.ntlm_info:
            return None
        ntlm = winrm.ntlm_info
        lines: list[str] = []
        if ntlm.dns_domain_name:
            lines.append(f"**DNS Domain:** {ntlm.dns_domain_name}")
        if ntlm.dns_tree_name:
            lines.append(f"**AD Forest:** {ntlm.dns_tree_name}")
        if ntlm.dns_server_name:
            lines.append(f"**DNS Server:** {ntlm.dns_server_name}")
        if ntlm.netbios_domain_name:
            lines.append(f"**NetBIOS Domain:** {ntlm.netbios_domain_name}")
        if ntlm.netbios_computer_name:
            lines.append(f"**NetBIOS Computer:** {ntlm.netbios_computer_name}")
        if ntlm.os_version:
            lines.append(f"**OS Version:** {ntlm.os_version}")
        if ntlm.target_name:
            lines.append(f"**Target:** {ntlm.target_name}")
        if not lines:
            return None
        return "### WinRM\n\n" + "\n\n".join(lines), ["winrm", "windows"]

    def _build_snmp_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return an SNMP section with system name, description, location, and contact."""
        if not service.snmp:
            return None
        snmp: Snmp = service.snmp
        if not snmp.oid_system:
            return None
        sys_info = snmp.oid_system
        lines: list[str] = []
        if sys_info.name:
            lines.append(f"**System Name:** {sys_info.name}")
        if sys_info.desc:
            lines.append(f"**Description:** {sys_info.desc}")
        if sys_info.location:
            lines.append(f"**Location:** {sys_info.location}")
        if sys_info.contact:
            lines.append(f"**Contact:** {sys_info.contact}")
        if not lines:
            return None
        return "### SNMP\n\n" + "\n\n".join(lines), ["snmp"]

    def _build_darkcomet_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a DarkComet section if this service shows RAT beacon activity."""
        if not service.darkcomet:
            return None
        dc: Darkcomet = service.darkcomet
        lines: list[str] = []
        if dc.version:
            lines.append(f"**Version:** {dc.version}")
        content = "\n\n".join(lines) if lines else "DarkComet RAT beacon detected."
        return f"### DarkComet\n\n{content}", ["darkcomet", "remote-access-trojan", "malware"]

    def _build_darkgate_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a DarkGate section if this service shows malware beacon activity."""
        if not service.darkgate:
            return None
        dg: Darkgate = service.darkgate
        files = dg.files if isinstance(dg.files, list) else []
        file_lines: list[str] = []
        for f in files:
            if f.name:
                size = f" ({f.length} bytes)" if f.length is not None else ""
                file_lines.append(f"- **{f.name}**{size}")
        content = (
            "#### Observed Files\n\n" + "\n".join(file_lines)
            if file_lines
            else "DarkGate beacon detected."
        )
        return f"### DarkGate\n\n{content}", ["darkgate", "malware"]

    def _build_redline_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a RedLine section if this service shows stealer beacon activity."""
        if not service.redline:
            return None
        rl: Redline = service.redline
        lines: list[str] = []
        if rl.transport:
            lines.append(f"**Transport:** {rl.transport}")
        if rl.action_response:
            lines.append(f"**Action Response:** {rl.action_response}")
        if rl.settings_response:
            lines.append(f"**Settings Response:** {rl.settings_response}")
        content = "\n\n".join(lines) if lines else "RedLine stealer beacon detected."
        return f"### RedLine\n\n{content}", ["redline", "information-stealer", "malware"]

    def _build_risks_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a Security Risks section summarising exposures, misconfigs, and compromises."""
        risk_groups: list[tuple[str, list[Risk]]] = []
        for section_name, field in [
            ("Compromises", service.compromises),
            ("Exposures", service.exposures),
            ("Misconfigurations", service.misconfigs),
        ]:
            risks: list[Risk] = field if isinstance(field, list) else []
            if risks:
                risk_groups.append((section_name, risks))
        if not risk_groups:
            return None
        extra_labels: list[str] = []
        if isinstance(service.compromises, list) and service.compromises:
            extra_labels.append("compromise")
        if isinstance(service.exposures, list) and service.exposures:
            extra_labels.append("exposure")
        if isinstance(service.misconfigs, list) and service.misconfigs:
            extra_labels.append("misconfiguration")
        sub_sections: list[str] = []
        for section_name, risks in risk_groups:
            items = "\n".join(
                f"- **{risk.name or risk.id or 'Unknown'}**"
                + (f" [{risk.severity.name}]" if risk.severity else "")
                for risk in risks
            )
            sub_sections.append(f"#### {section_name}\n\n{items}")
        return "### Security Risks\n\n" + "\n\n".join(sub_sections), extra_labels

    def _build_upnp_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a UPnP Devices section listing discovered IoT device info."""
        if not service.upnp:
            return None
        devices = service.upnp.devices if isinstance(service.upnp.devices, list) else []
        if not devices:
            return None
        device_blocks: list[str] = []
        for device in devices[:5]:
            lines: list[str] = []
            if device.friendly_name:
                lines.append(f"**Name:** {device.friendly_name}")
            if device.manufacturer:
                lines.append(f"**Manufacturer:** {device.manufacturer}")
            if device.model_name:
                lines.append(f"**Model:** {device.model_name}")
            if device.model_number:
                lines.append(f"**Model Number:** {device.model_number}")
            if device.device_type:
                lines.append(f"**Type:** {device.device_type}")
            if device.serial_number:
                lines.append(f"**Serial:** {device.serial_number}")
            if lines:
                device_blocks.append("\n\n".join(lines))
        if not device_blocks:
            return None
        return "### UPnP Devices\n\n" + "\n\n---\n\n".join(device_blocks), ["upnp", "iot"]

    def _generate_observable_update(
        self,
        ip: str,
        labels: list[str] | None,
        score: int | None = None,
    ) -> Generator[BaseObject, None, None]:
        """Re-emit the IP SCO with the Censys Platform pivot URL and host labels.

        Because STIX IDs for IPv4/IPv6 SCOs are deterministic (derived from the
        value), OpenCTI merges this into the existing entity, updating external
        references and labels without creating a duplicate observable.
        """
        ip_version = ipaddress.ip_network(ip, strict=False).version
        cls = IPV4Address if ip_version == 4 else IPV6Address
        yield cls(
            value=ip,
            score=score,
            external_references=[  # type: ignore[call-arg]
                ExternalReference(
                    source_name="Censys",
                    url=f"https://platform.censys.io/hosts/{ip}",
                    description=f"Censys host intelligence for {ip}",
                )
            ],
            labels=labels or None,
            **self._common_props,
        )

    def _generate_certificate(
        self, cert: Certificate | None
    ) -> Generator[BaseObject, None, X509Certificate | None]:
        if not cert or not (
            cert.fingerprint_sha256
            or cert.fingerprint_sha1
            or cert.fingerprint_md5
            or cert.parsed
        ):
            return None

        # Gather all fields up front so the object is constructed in one call.
        # Mutating a Pydantic model after construction re-triggers ID computation
        # on every assignment, causing spurious "id changed" warnings.
        kwargs: dict = {
            "hashes": {
                HashAlgorithm.SHA1: cert.fingerprint_sha1,
                HashAlgorithm.SHA256: cert.fingerprint_sha256,
                HashAlgorithm.MD5: cert.fingerprint_md5,
            },
        }

        if cert.parsed:
            kwargs["serial_number"] = cert.parsed.serial_number
            kwargs["issuer"] = cert.parsed.issuer_dn
            kwargs["subject"] = cert.parsed.subject_dn

            if cert.parsed.signature and cert.parsed.signature.signature_algorithm:
                kwargs["signature_algorithm"] = (
                    cert.parsed.signature.signature_algorithm.name
                )
            if cert.parsed.validity_period:
                kwargs["validity_not_before"] = cert.parsed.validity_period.not_before
                kwargs["validity_not_after"] = cert.parsed.validity_period.not_after
            if cert.parsed.subject_key_info and cert.parsed.subject_key_info.key_algorithm:
                kwargs["subject_public_key_algorithm"] = (
                    cert.parsed.subject_key_info.key_algorithm.name
                )
                if cert.parsed.subject_key_info.rsa:
                    kwargs["subject_public_key_modulus"] = (
                        cert.parsed.subject_key_info.rsa.modulus
                    )
                    kwargs["subject_public_key_exponent"] = (
                        cert.parsed.subject_key_info.rsa.exponent
                    )
            if cert.parsed.extensions:
                if cert.parsed.extensions.key_usage:
                    kwargs["key_usage"] = (
                        cert.parsed.extensions.key_usage.model_dump_json()
                    )
                if cert.parsed.extensions.basic_constraints:
                    kwargs["basic_constraints"] = (
                        cert.parsed.extensions.basic_constraints.model_dump_json()
                    )
                kwargs["crl_distribution_points"] = str(
                    cert.parsed.extensions.crl_distribution_points
                )
                kwargs["authority_key_identifier"] = (
                    cert.parsed.extensions.authority_key_id
                )
                if cert.parsed.extensions.extended_key_usage:
                    kwargs["extended_key_usage"] = (
                        cert.parsed.extensions.extended_key_usage.model_dump_json()
                    )
                kwargs["certificate_policies"] = str(
                    cert.parsed.extensions.certificate_policies
                )

        # is_self_signed: issuer DN matches subject DN
        if cert.parsed and cert.parsed.issuer_dn and cert.parsed.subject_dn:
            kwargs["is_self_signed"] = cert.parsed.issuer_dn == cert.parsed.subject_dn

        # subject_alternative_name: join SAN DNS names into a comma-separated string
        if (
            cert.parsed
            and cert.parsed.extensions
            and cert.parsed.extensions.subject_alt_name
        ):
            san = cert.parsed.extensions.subject_alt_name
            dns_names = san.dns_names if isinstance(san.dns_names, list) else []
            if dns_names:
                kwargs["subject_alternative_name"] = ", ".join(dns_names)

        # labels: validation level (DV/OV/EV), revocation, browser trust
        cert_labels: list[str] = []
        if cert.validation_level and cert.validation_level.value:
            cert_labels.append(cert.validation_level.value.upper())
        if cert.revoked is True:
            cert_labels.append("revoked")
        if cert.validation:
            stores = [
                cert.validation.apple,
                cert.validation.chrome,
                cert.validation.microsoft,
                cert.validation.nss,
            ]
            if any(s is not None and getattr(s, "is_valid", False) for s in stores):
                cert_labels.append("browser-trusted")
        if cert_labels:
            kwargs["labels"] = cert_labels

        # Add a Censys portal link so the cert observable gets an external reference.
        if cert.fingerprint_sha256:
            kwargs["external_references"] = [  # type: ignore[call-arg]
                ExternalReference(
                    source_name="Censys",
                    url=f"https://platform.censys.io/certificates/{cert.fingerprint_sha256}",
                    description=f"Censys certificate intelligence for {cert.fingerprint_sha256}",
                )
            ]

        certificate = X509Certificate(**kwargs, **self._common_props)
        yield certificate

        # Emit Hostname observables for each domain name covered by this cert.
        # Wildcards are skipped — OpenCTI rejects them as Hostname values.
        # IP addresses (IPv4 and IPv6) are skipped — cert SANs can include IPs
        # but they must be typed as IP observables, not Hostnames.  Passing an
        # IP string as a Hostname value causes FUNCTIONAL_ERROR in OpenCTI which
        # then cascades into MISSING_REFERENCE_ERROR for the relationship.
        for name in (cert.names if isinstance(cert.names, list) else [])[:20]:
            if not name or "*" in name:
                continue
            try:
                ipaddress.ip_address(name)
                continue  # SAN is an IP address — skip, not a Hostname
            except ValueError:
                pass
            hostname_obs = Hostname(value=name, **self._common_props)
            yield hostname_obs
            yield Relationship(
                source=certificate,
                target=hostname_obs,
                type=RelationshipType.RELATED_TO,
                **self._common_props,
            )

        return certificate

    def _build_smtp_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return an SMTP section with EHLO banner and STARTTLS response."""
        if not service.smtp:
            return None
        smtp: SMTP = service.smtp
        lines: list[str] = []
        if smtp.ehlo:
            lines.append(f"**EHLO Response:**\n```\n{smtp.ehlo.strip()}\n```")
        if smtp.start_tls:
            lines.append(f"**STARTTLS Response:** {smtp.start_tls.strip()}")
        if not lines:
            return None
        return "### SMTP\n\n" + "\n\n".join(lines), ["smtp"]

    def _build_ftp_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return an FTP section with status code and TLS support details."""
        if not service.ftp:
            return None
        ftp: Ftp = service.ftp
        lines: list[str] = []
        if ftp.status_code is not None:
            meaning = f" — {ftp.status_meaning}" if ftp.status_meaning else ""
            lines.append(f"**Status:** {ftp.status_code}{meaning}")
        if ftp.implicit_tls is not None:
            lines.append(f"**Implicit TLS:** {ftp.implicit_tls}")
        if ftp.auth_tls_response:
            lines.append(f"**AUTH TLS:** {ftp.auth_tls_response.strip()}")
        if ftp.auth_ssl_response:
            lines.append(f"**AUTH SSL:** {ftp.auth_ssl_response.strip()}")
        if not lines:
            return None
        return "### FTP\n\n" + "\n\n".join(lines), ["ftp"]

    def _build_telnet_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a Telnet section flagging the plaintext protocol and capabilities."""
        if not service.telnet:
            return None
        telnet: Telnet = service.telnet
        lines: list[str] = ["Telnet service detected — transmits data in plaintext."]
        will_caps = [name for name in (telnet.will or {}).keys() if name]
        if will_caps:
            lines.append(f"**WILL capabilities:** {', '.join(sorted(will_caps))}")
        do_caps = [name for name in (telnet.do or {}).keys() if name]
        if do_caps:
            lines.append(f"**DO capabilities:** {', '.join(sorted(do_caps))}")
        return "### Telnet\n\n" + "\n\n".join(lines), ["telnet"]

    def _build_redis_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a Redis section with version, mode, OS, and authentication status."""
        if not service.redis:
            return None
        redis: Redis = service.redis
        lines: list[str] = []
        parts = [p for p in [redis.major, redis.minor, redis.patch_level] if p is not None]
        if parts:
            lines.append(f"**Version:** {'.'.join(str(p) for p in parts)}")
        if redis.mode:
            lines.append(f"**Mode:** {redis.mode}")
        if redis.os:
            lines.append(f"**OS:** {redis.os}")
        if redis.ping_response:
            auth_status = (
                "Disabled (unauthenticated)"
                if redis.ping_response.strip().upper() == "PONG"
                else "Enabled"
            )
            lines.append(f"**Authentication:** {auth_status}")
        if redis.uptime is not None:
            lines.append(f"**Uptime:** {redis.uptime} seconds")
        if not lines:
            return None
        return "### Redis\n\n" + "\n\n".join(lines), ["redis"]

    def _build_mongodb_section(self, service: Service) -> tuple[str, list[str]] | None:
        """Return a MongoDB section with version and server role."""
        if not service.mongodb:
            return None
        mongo: Mongodb = service.mongodb
        lines: list[str] = []
        if mongo.build_info and mongo.build_info.version:
            lines.append(f"**Version:** {mongo.build_info.version}")
        if mongo.is_master:
            im = mongo.is_master
            if im.is_master is not None:
                lines.append(f"**Is Primary:** {im.is_master}")
            if im.read_only is not None:
                lines.append(f"**Read Only:** {im.read_only}")
            if im.max_wire_version is not None:
                lines.append(f"**Max Wire Version:** {im.max_wire_version}")
        if not lines:
            return None
        return "### MongoDB\n\n" + "\n\n".join(lines), ["mongodb"]

    def _generate_service_note(
        self,
        observable: Reference,
        service: Service,
    ) -> Generator[BaseObject, None, None]:
        """Yield a single combined Note covering all protocol data for a service port.

        Calls every section builder in turn; non-None results are joined with
        double newlines so markdown renders each field on its own line.  All
        section labels are merged so analysts can filter by protocol or risk type.
        """
        if not (service.port and service.scan_time):
            return

        section_results = [
            self._build_banner_section(service),
            self._build_fingerprints_section(service),
            self._build_ssh_section(service),
            self._build_rdp_section(service),
            self._build_smb_section(service),
            self._build_vnc_section(service),
            self._build_ldap_section(service),
            self._build_winrm_section(service),
            self._build_snmp_section(service),
            self._build_dcerpc_section(service),
            self._build_smtp_section(service),
            self._build_ftp_section(service),
            self._build_telnet_section(service),
            self._build_redis_section(service),
            self._build_mongodb_section(service),
            self._build_darkcomet_section(service),
            self._build_darkgate_section(service),
            self._build_redline_section(service),
            self._build_risks_section(service),
            self._build_upnp_section(service),
        ]

        all_sections: list[str] = []
        extra_labels: list[str] = []
        for result in section_results:
            if result is not None:
                section_text, section_labels = result
                all_sections.append(section_text)
                for lbl in section_labels:
                    if lbl not in extra_labels:
                        extra_labels.append(lbl)

        # Censys-assigned per-service labels (e.g. protocol type, software family)
        for svc_label in service.labels if isinstance(service.labels, list) else []:
            if svc_label.value and svc_label.value not in extra_labels:
                extra_labels.append(svc_label.value)

        if not all_sections:
            return

        _secondary = {
            "malware", "remote-access-trojan", "information-stealer",
            "compromise", "exposure", "misconfiguration", "windows",
            "remote-desktop", "rpc",
        }
        protocol_labels = [lbl for lbl in extra_labels if lbl not in _secondary]
        abstract = (
            f"Port {service.port} — {protocol_labels[0].upper()}"
            if protocol_labels
            else f"Service on port {service.port}"
        )

        yield Note(
            abstract=abstract,
            content="\n\n".join(all_sections),
            publication_date=datetime.datetime.fromisoformat(service.scan_time),
            authors=[self.author.name],
            objects=[observable],
            labels=[f"port:{service.port}"] + extra_labels,
            **self._common_props,
        )

    def _generate_services(
        self,
        observable: Reference,
        services: list[Service] | None,
        nvd_data_map: dict[str, NVDData] | None = None,
    ) -> Generator[BaseObject, None, None]:
        for service in services or []:
            for software in service.software or []:
                yield from self._generate_software(
                    observable=observable,
                    name=software.product,
                    vendor=software.vendor,
                    cpe=software.cpe,
                    version=software.version,
                )
            if service.cert:
                certificate = yield from self._generate_certificate(
                    cert=service.cert,
                )
                if certificate:
                    yield Relationship(
                        source=observable,
                        target=certificate,
                        type=RelationshipType.RELATED_TO,
                        **self._common_props,
                    )
            for vuln in service.vulns or []:
                yield from self._generate_vulnerability(
                    observable=observable,
                    vuln=vuln,
                    nvd_data=(
                        nvd_data_map.get(vuln.id or "") if nvd_data_map else None
                    ),
                )
            for threat in service.threats or []:
                yield from self._generate_malware(
                    observable=observable,
                    threat=threat,
                )
            yield from self._generate_service_note(
                observable=observable,
                service=service,
            )
            yield from self._generate_cobalt_strike_note(
                observable=observable,
                service=service,
            )

    def _generate_ip(
        self, observable: Reference, ip: str
    ) -> Generator[BaseObject, None, None | IPV4Address | IPV6Address]:
        ip_version = ipaddress.ip_network(ip, strict=False).version
        if ip_version == 4:
            ip_address = IPV4Address(value=ip, **self._common_props)
        else:
            ip_address = IPV6Address(value=ip, **self._common_props)
        yield from [
            ip_address,
            Relationship(
                source=observable,
                target=ip_address,
                type=RelationshipType.RELATED_TO,
                **self._common_props,
            ),
        ]
        return ip_address

    def generate_octi_objects(
        self,
        stix_entity: dict[str, Any],
        data: Host,
        nvd_data_map: dict[str, NVDData] | None = None,
    ) -> Generator[BaseObject, None, None]:
        observable = Reference(id=stix_entity["id"])

        yield from [
            self.author,
            self.marking,
        ]
        yield from self._generate_city(
            observable=observable,
            name=data.location.city if data.location else None,
        )
        yield from self._generate_region(
            observable=observable,
            name=data.location.continent if data.location else None,
        )
        yield from self._generate_administrative_area(
            observable=observable,
            name=data.location.province if data.location else None,
            coordinates=data.location.coordinates if data.location else None,
        )
        yield from self._generate_hostnames(
            observable=observable,
            dns=data.dns,
        )
        yield from self._generate_services(
            observable=observable,
            # Normalise OptionalNullable: treat the Unset sentinel the same as None
            services=data.services if isinstance(data.services, list) else None,
            nvd_data_map=nvd_data_map,
        )
        country = yield from self._generate_country(
            observable=observable,
            name=data.location.country if data.location else None,
        )
        organization = yield from self._generate_organization(
            observable=observable,
            name=data.autonomous_system.name if data.autonomous_system else None,
        )
        autonomous_system = yield from self._generate_autonomous_system(
            observable=observable,
            name=data.autonomous_system.name if data.autonomous_system else None,
            description=(
                data.autonomous_system.description if data.autonomous_system else None
            ),
            number=data.autonomous_system.asn if data.autonomous_system else None,
        )
        if autonomous_system:
            if organization:
                yield Relationship(
                    source=autonomous_system,
                    target=organization,
                    type=RelationshipType.RELATED_TO,
                    **self._common_props,
                )
            if country:
                yield Relationship(
                    source=autonomous_system,
                    target=country,
                    type=RelationshipType.RELATED_TO,
                    **self._common_props,
                )
        # Map host-level OS to a Software observable (product, vendor, CPE, version)
        if data.operating_system:
            os_attr: Attribute = data.operating_system
            yield from self._generate_software(
                observable=observable,
                name=os_attr.product,
                vendor=os_attr.vendor,
                cpe=os_attr.cpe,
                version=os_attr.version,
            )
        # VPN / anonymisation service provider organisations (e.g. "NordVPN", "Mullvad").
        # Each provider name is emitted as an Organisation linked to the IP so analysts
        # can pivot from the IP to the service in OpenCTI's graph view.
        for priv in data.privacy if isinstance(data.privacy, list) else []:
            for provider_name in (
                priv.service_provider if isinstance(priv.service_provider, list) else []
            ):
                if provider_name:
                    yield from self._generate_organization(
                        observable=observable,
                        name=provider_name,
                    )
        # WHOIS abuse contact emails — useful for reporting malicious activity upstream.
        # Guard: WHOIS entries often contain non-email values ("N/A", handles,
        # phone numbers, or truncated addresses like "abuse@" with no domain).
        # OpenCTI enforces RFC 5321 on the email-addr SCO; invalid values cause
        # a FUNCTIONAL_ERROR which then cascades into a MISSING_REFERENCE_ERROR
        # for the relationship that follows.
        if data.whois and data.whois.organization:
            for contact in (
                data.whois.organization.abuse_contacts
                if isinstance(data.whois.organization.abuse_contacts, list)
                else []
            ):
                if not contact.email:
                    continue
                _local, _sep, _domain = contact.email.strip().partition("@")
                if not (_sep and _local and _domain and "." in _domain):
                    continue
                email_obs = EmailAddress(value=contact.email.strip(), **self._common_props)
                yield email_obs
                yield Relationship(
                    source=observable,
                    target=email_obs,
                    type=RelationshipType.RELATED_TO,
                    **self._common_props,
                )

        # Re-emit the IP with the Censys Platform pivot URL and enriched labels/score;
        # OpenCTI merges this into the existing observable (same deterministic ID).
        if data.ip:
            host_label_list: list[Label] = (
                data.labels if isinstance(data.labels, list) else []
            )
            all_labels = [lbl.value for lbl in host_label_list if lbl.value]

            # Privacy / anonymisation flags and service provider labels
            for priv in data.privacy if isinstance(data.privacy, list) else []:
                if priv.tor:
                    all_labels.append("tor")
                if priv.vpn:
                    all_labels.append("vpn")
                if priv.proxy:
                    all_labels.append("proxy")
                if priv.anonymous:
                    all_labels.append("anonymous")
                for provider_name in (
                    priv.service_provider if isinstance(priv.service_provider, list) else []
                ):
                    if provider_name:
                        all_labels.append(
                            f"vpn-provider:{provider_name.lower().replace(' ', '-')}"
                        )

            # GreyNoise threat classification and behavioural tags
            if data.greynoise:
                if data.greynoise.classification:
                    all_labels.append(f"gn-{data.greynoise.classification}")
                for gn_tag in (
                    data.greynoise.tags if isinstance(data.greynoise.tags, list) else []
                )[:10]:
                    if gn_tag.name:
                        all_labels.append(
                            f"gn-{gn_tag.name.lower().replace(' ', '-')}"
                        )

            # Network type (hosting provider, mobile, satellite)
            for nc in data.network if isinstance(data.network, list) else []:
                if nc.hosting:
                    all_labels.append("hosting-provider")
                if nc.mobile:
                    all_labels.append("mobile")
                if nc.satellite:
                    all_labels.append("satellite-internet")

            # Hardware / device type for IoT and embedded-device detection
            if data.hardware and data.hardware.product:
                hw_parts = [p for p in [data.hardware.vendor, data.hardware.product] if p]
                all_labels.append(f"device:{' '.join(hw_parts).lower()}")

            # Threat type labels from reputation evidence (e.g. threat:c2, threat:botnet)
            if data.reputation and isinstance(data.reputation.evidence, list):
                for evidence in data.reputation.evidence:
                    for ev_threat in (
                        evidence.threats if isinstance(evidence.threats, list) else []
                    ):
                        for threat_type in (
                            ev_threat.threat_types
                            if isinstance(ev_threat.threat_types, list)
                            else []
                        ):
                            if threat_type:
                                all_labels.append(
                                    f"threat:{threat_type.lower().replace(' ', '-')}"
                                )

            # Censys reputation risk score (0–100, higher = riskier) and level label
            _score_label_map = {
                "low_risk": "risk-low",
                "medium_risk": "risk-medium",
                "high_risk": "risk-high",
                "malicious": "risk-malicious",
            }
            reputation_score: int | None = None
            if data.reputation and data.reputation.score is not None:
                reputation_score = int(round(data.reputation.score))
                if data.reputation.score_level and data.reputation.score_level.value:
                    risk_label = _score_label_map.get(data.reputation.score_level.value)
                    if risk_label:
                        all_labels.append(risk_label)

            yield from self._generate_observable_update(
                ip=data.ip,
                # dict.fromkeys preserves insertion order while deduplicating
                labels=list(dict.fromkeys(all_labels)) or None,
                score=reputation_score,
            )

    def generate_octi_objects_from_certs(
        self, certs: list[Certificate]
    ) -> Generator[BaseObject, None, None]:
        yield from [
            self.author,
            self.marking,
        ]

        for cert in certs:
            yield from self._generate_certificate(
                cert=cert,
            )

    def generate_octi_objects_from_hosts(
        self,
        stix_entity: dict[str, Any],
        hosts: list[Host],
        nvd_data_provider: Callable[[Host], dict[str, NVDData]] | None = None,
    ) -> Generator[BaseObject, None, None]:
        yield from [
            self.author,
            self.marking,
        ]
        ip_refs: list[IPV4Address | IPV6Address] = []
        for host in hosts:
            if not host.ip:
                continue
            ip_stix = yield from self._generate_ip(
                observable=Reference(id=stix_entity["id"]),
                ip=host.ip,
            )
            if ip_stix:
                ip_refs.append(ip_stix)
                nvd_data_map = (
                    nvd_data_provider(host) if nvd_data_provider else None
                )
                yield from self.generate_octi_objects(
                    stix_entity=ip_stix.to_stix2_object(),
                    data=host,
                    nvd_data_map=nvd_data_map,
                )
        # Re-emit the domain observable with the Censys pivot link and
        # references to every IP it resolved to (found via Censys host search).
        domain_value = stix_entity.get("value", "")
        if domain_value:
            yield DomainName(  # type: ignore[call-arg]
                value=domain_value,
                resolves_to=[Reference(id=ip.id) for ip in ip_refs] or None,
                external_references=[
                    ExternalReference(
                        source_name="Censys",
                        url=f"https://platform.censys.io/search?resource=hosts&q=dns.names%3D{domain_value}",
                        description=f"Censys host intelligence for {domain_value}",
                    )
                ],
                **self._common_props,
            )

    def generate_octi_objects_from_domain_certs(
        self, stix_entity: dict[str, Any], certs: list[Certificate]
    ) -> Generator[BaseObject, None, None]:
        """Generate OpenCTI objects from certificates associated with a domain

        Args:
            stix_entity: The domain STIX entity
            certs: List of Certificate objects from Censys

        Yields:
            BaseObject: STIX objects representing certificates and their relationships
        """
        observable = Reference(id=stix_entity["id"])

        yield from [
            self.author,
            self.marking,
        ]

        for cert in certs:
            certificate = yield from self._generate_certificate(cert=cert)
            if certificate:
                yield Relationship(
                    source=certificate,
                    target=observable,
                    type=RelationshipType.RELATED_TO,
                    **self._common_props,
                )
