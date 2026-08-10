import re
from typing import Any

from modat_client.models import ModatHost, Service


class ModatUtils:
    def __init__(self, helper):
        self.helper = helper

    @staticmethod
    def flatten_distinguished_name(name_data: Any) -> str | None:
        if not isinstance(name_data, dict):
            return None
        mapping = [
            ("common_name", "CN"),
            ("organization", "O"),
            ("organizational_unit", "OU"),
            ("locality", "L"),
            ("province", "ST"),
            ("country", "C"),
            ("email_address", "E"),
        ]
        parts: list[str] = []
        for source_key, label in mapping:
            values = name_data.get(source_key)
            if not isinstance(values, list):
                continue
            for value in values:
                if value not in (None, ""):
                    parts.append(f"{label}={value}")
        return ", ".join(parts) if parts else None

    @staticmethod
    def name_field(name_data: Any, key: str) -> str | None:
        if not isinstance(name_data, dict):
            return None
        values = name_data.get(key)
        if not isinstance(values, list):
            return None
        cleaned = [str(value) for value in values if value not in (None, "")]
        if not cleaned:
            return None
        return ", ".join(cleaned)

    @staticmethod
    def extract_alt_name_values(alt_name_data: Any, key: str) -> list[str]:
        if not isinstance(alt_name_data, dict):
            return []
        values = alt_name_data.get(key)
        if not isinstance(values, list):
            return []
        return [str(value) for value in values if value not in (None, "")]

    @staticmethod
    def is_valid_domain_name(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        candidate = value.strip().rstrip(".")
        if not candidate or "." not in candidate or len(candidate) > 253:
            return False
        label_pattern = re.compile(r"^[A-Za-z0-9-]{1,63}$")
        labels = candidate.split(".")
        return all(
            label
            and not label.startswith("-")
            and not label.endswith("-")
            and label_pattern.match(label)
            for label in labels
        )

    @staticmethod
    def parse_tls_raw_certificate(raw_text: Any) -> dict[str, Any]:
        """Extract a few useful fields (signature_algorithm, subject_public_key_algorithm)
        from the OpenSSL-style text dump in tls.raw. Modat's structured tls object
        does not expose these directly."""
        if not isinstance(raw_text, str) or not raw_text.strip():
            return {}

        parsed: dict[str, Any] = {}
        signature_algorithms = re.findall(r"Signature Algorithm:\s*([^\n]+)", raw_text)
        if signature_algorithms:
            parsed["signature_algorithm"] = signature_algorithms[0].strip()

        public_key_algorithm = re.search(r"Public Key Algorithm:\s*([^\n]+)", raw_text)
        if public_key_algorithm:
            parsed["subject_public_key_algorithm"] = public_key_algorithm.group(
                1
            ).strip()

        return parsed

    @staticmethod
    def _format_fingerprint_entry(entry: Any) -> str | None:
        if entry in (None, "", [], {}):
            return None
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            name = entry.get("name") or entry.get("product")
            version = entry.get("version")
            if name and version:
                return f"{name} {version}"
            return str(name) if name else None
        if isinstance(entry, list):
            parts = [ModatUtils._format_fingerprint_entry(item) for item in entry]
            parts = [p for p in parts if p]
            return ", ".join(parts) if parts else None
        return str(entry)

    @staticmethod
    def _date_only(value: Any) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        return value.split("T", 1)[0]

    @staticmethod
    def _service_port_label(svc: Service) -> str:
        last = svc.last_scanned_port
        ports = svc.ports
        if last is not None and len(ports) > 1:
            others = [str(p) for p in ports if p != last]
            return f"{last} (also: {', '.join(others)})"
        if last is not None:
            return str(last)
        if ports:
            return ", ".join(str(p) for p in ports)
        return "-"

    def build_summary(
        self,
        observable_value: str,
        host: ModatHost,
        include_cves: bool = False,
        max_services: int = 25,
    ) -> str:
        def normalize_multiline(value: Any) -> str:
            if not isinstance(value, str):
                return ""
            text = (
                value.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n")
            )
            return text.strip()

        lines: list[str] = ["## Modat Results", ""]
        lines.append("### Host Overview")

        geo = host.geo
        asn = host.asn
        location = f"{geo.city_name or '-'}, {geo.country_name or '-'}"
        services = host.services
        fqdns = host.fqdns
        cves = host.cves
        tags = host.tags

        lines.append(f"IP: `{observable_value}`")
        lines.append("")
        lines.append(
            f"Magnify platform: https://magnify.modat.io/hosts/{observable_value}"
        )
        lines.append("")
        lines.append(
            f"Overview: **{asn.org or '-'}** | "
            f"ASN `{asn.number or '-'}` | {location} | "
            f"Services `{len(services)}` | Domains `{len(fqdns)}`"
            + (" | Anycast" if host.is_anycast else "")
        )
        if tags:
            lines.append("")
            lines.append(f"Tags: {', '.join(str(t) for t in tags[:12])}")

        lines.extend(["", "---", "", "### Services"])
        if not services:
            lines.append("No services returned.")
        else:
            shown = services[: max(0, int(max_services))]
            for index, svc in enumerate(shown):
                if index > 0:
                    lines.extend(["", "---", ""])
                else:
                    lines.append("")
                self._render_service(lines, svc, include_cves, normalize_multiline)
            if len(services) > len(shown):
                lines.append("")
                lines.append(
                    f"_…{len(services) - len(shown)} additional service(s) omitted._"
                )

        lines.extend(["", "---", "", "### Domains"])
        if fqdns:
            lines.append(f"**Total domains:** {len(fqdns)}")
            for fqdn in fqdns[:20]:
                lines.append(f"- {fqdn}")
            if len(fqdns) > 20:
                lines.append(f"_…{len(fqdns) - 20} more omitted._")
        else:
            lines.append("No domains returned.")

        if include_cves and cves:
            lines.extend(["", "---", "", "### CVEs (host-level, unvalidated)"])
            lines.append(f"**Total CVEs:** {len(cves)}")
            for cve in cves[:25]:
                pieces = [f"`{cve.id}`"]
                if cve.cvss is not None:
                    pieces.append(f"CVSS {cve.cvss}")
                if cve.is_kev:
                    pieces.append("**KEV**")
                lines.append(f"- {' | '.join(pieces)}")
            if len(cves) > 25:
                lines.append(f"_…{len(cves) - 25} more omitted._")

        return "\n".join(lines)

    def _render_service(
        self,
        lines: list[str],
        svc: Service,
        include_cves: bool,
        normalize_multiline,
    ) -> None:
        transport = svc.transport or "tcp"
        protocol = (svc.protocol or "").lower()
        port_label = self._service_port_label(svc)
        scanned_at = svc.scanned_at

        fingerprints = svc.fingerprints
        product = self._format_fingerprint_entry(
            fingerprints.service
        ) or self._format_fingerprint_entry(fingerprints.os)

        heading_parts = [f"{transport}/{port_label}"]
        if protocol and protocol != "unknown":
            heading_parts.append(f"({protocol})")
        if product:
            heading_parts.append(f": {product}")
        heading = "#### " + " ".join(heading_parts)
        if scanned_at:
            heading += f"  _(scanned {scanned_at})_"
        lines.append(heading)
        lines.append("")

        technologies = fingerprints.technologies
        if technologies:
            tech_names = [self._format_fingerprint_entry(t) for t in technologies[:10]]
            tech_names = [t for t in tech_names if t]
            if tech_names:
                lines.append(f"Technologies: {', '.join(tech_names)}")

        banner = normalize_multiline(svc.banner)

        if protocol == "ssh":
            ssh = svc.ssh
            if ssh:
                if ssh.hassh:
                    lines.append(f"hassh: `{ssh.hassh}`")
                if ssh.server_id:
                    lines.append(f"Server ID: `{ssh.server_id}`")
            if banner:
                lines.append("Banner:")
                lines.append("```text")
                lines.append(banner[:1200])
                lines.append("```")
        elif protocol == "http":
            http = svc.http
            if http:
                if http.title:
                    lines.append(f"Title: {http.title}")
                if http.status_code is not None:
                    lines.append(f"Status: `{http.status_code}`")
                headers = http.headers
                interesting = ["server", "x-powered-by", "content-type", "location"]
                picked = [(k, headers.get(k)) for k in interesting if headers.get(k)]
                if picked:
                    lines.append("")
                    lines.append("Headers:")
                    lines.append("```text")
                    for k, v in picked:
                        lines.append(f"{k}: {v}")
                    lines.append("```")
        else:
            if banner:
                lines.append("Banner:")
                lines.append("```text")
                lines.append(banner[:800])
                lines.append("```")

        tls = svc.tls
        if tls:
            cn = self.name_field(tls.subject, "common_name")
            issuer_cn = self.name_field(tls.issuer, "common_name")
            lines.append("")
            tls_bits = []
            if cn:
                tls_bits.append(f"CN={cn}")
            if issuer_cn:
                tls_bits.append(f"Issuer={issuer_cn}")
            versions = tls.supported_versions
            if versions:
                tls_bits.append(f"Versions: {', '.join(str(v) for v in versions)}")
            valid_from = self._date_only(tls.valid_from)
            expires_at = self._date_only(tls.expires_at)
            if valid_from or expires_at:
                tls_bits.append(f"Valid: {valid_from or '?'} → {expires_at or '?'}")
            if tls.is_self_signed:
                tls_bits.append("self-signed")
            if tls_bits:
                lines.append("TLS: " + " | ".join(tls_bits))
            if tls.fingerprint_sha256:
                lines.append(f"sha256: `{tls.fingerprint_sha256}`")

        svc_cves = svc.cves
        if include_cves and svc_cves:
            lines.append("")
            top = svc_cves[:10]
            rendered = []
            for c in top:
                bit = f"`{c.id}`"
                if c.cvss is not None:
                    bit += f" ({c.cvss})"
                if c.is_kev:
                    bit += " **KEV**"
                rendered.append(bit)
            lines.append(f"CVEs ({len(svc_cves)}): {', '.join(rendered)}")
            if len(svc_cves) > len(top):
                lines.append(f"_…{len(svc_cves) - len(top)} more on this service._")
