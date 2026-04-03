"""
SandboxProcessor - Processes raw PolySwarm sandbox results from Cape and Triage providers
Extracts scores, families, TTPs, IOCs, signatures, extracted configs, and network data
"""

from typing import Any


class SandboxProcessor:
    """Processes raw PolySwarm sandbox results into structured data for STIX mapping."""

    @staticmethod
    def _safe_num(val, default: float = 0.0) -> float:
        """Safely convert API value to float. Returns default on failure."""
        if val is None:
            return default
        try:
            return float(val)
        except (TypeError, ValueError):
            return default

    # Domains to filter out (benign/noise)
    BENIGN_DOMAINS = {
        "microsoft.com",
        "windowsupdate.com",
        "windows.com",
        "msftconnecttest.com",
        "bing.com",
        "live.com",
        "office.com",
        "office365.com",
        "outlook.com",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "youtube.com",
        "ocsp.",
        "crl.",
        ".arpa",
        "akadns.net",
        "akamai.net",
        "akamaiedge.net",
        "trafficmanager.net",
        "edgesuite.net",
        "msedge.net",
        "digicert.com",
        "verisign.com",
        "symantec.com",
        "globalsign.com",
        "godaddy.com",
        "officeapps.live.com",
        "ctldl.windowsupdate.com",
    }

    # IPs to filter out (internal/benign)
    BENIGN_IPS = {
        "127.0.0.1",
        "0.0.0.0",  # noqa: S104  # nosec B104 — data constant, not a bind address
        "255.255.255.255",
        "8.8.8.8",
        "8.8.4.4",  # Google DNS
        "1.1.1.1",
        "1.0.0.1",  # Cloudflare DNS
    }

    @staticmethod
    def process(result: dict) -> dict[str, Any] | None:
        """
        Process raw sandbox result from either Cape or Triage provider.
        Auto-detects provider based on result structure.
        """
        if not result or not isinstance(result, dict):
            return None

        # Detect provider
        provider = SandboxProcessor._detect_provider(result)

        if provider == "triage":
            return SandboxProcessor._process_triage(result)
        if provider == "cape":
            return SandboxProcessor._process_cape(result)
        # Try generic processing
        return SandboxProcessor._process_generic(result)

    @staticmethod
    def _detect_provider(result: dict) -> str:
        """Detect sandbox provider from result structure."""
        # Check explicit sandbox field
        sandbox = result.get("sandbox", "").lower()
        if sandbox in ["triage", "cape"]:
            return sandbox

        # Check config provider
        config = result.get("config", {})
        provider = config.get("provider", {})
        if isinstance(provider, dict):
            slug = provider.get("slug", "").lower()
            if slug in ["triage", "cape"]:
                return slug

        # Check for Triage-specific fields
        if (
            config.get("triage_static_score") is not None
            or config.get("traige_analysis_score") is not None
        ):
            return "triage"

        # Check for Cape-specific fields
        if config.get("cape_malscore") is not None:
            return "cape"

        # Check report structure
        report = result.get("report", {})
        if report.get("targets"):
            return "triage"
        if report.get("signature_names"):
            return "cape"

        return "unknown"

    @staticmethod
    def _process_triage(result: dict) -> dict[str, Any]:
        """Process Triage sandbox results."""
        config = result.get("config", {})
        if not isinstance(config, dict):
            config = {}
        report = result.get("report", {})
        if not isinstance(report, dict):
            report = {}
        targets = report.get("targets", [])
        if not isinstance(targets, list):
            targets = []

        # === SCORES ===
        # Behavioral score from config (note: typo in API - "traige_analysis_score")
        triage_behavioral_score = int(
            SandboxProcessor._safe_num(config.get("traige_analysis_score"))
        )
        # Static score from config
        triage_static_score = int(
            SandboxProcessor._safe_num(config.get("triage_static_score"))
        )
        # Sandbox score from report.targets[].score
        triage_sandbox_score = 0
        if targets and isinstance(targets[0], dict):
            triage_sandbox_score = int(
                SandboxProcessor._safe_num(targets[0].get("score"))
            )

        # Use highest score (convert to 0-100 scale if needed)
        score = max(triage_behavioral_score, triage_static_score, triage_sandbox_score)
        score = int(score * 10) if score <= 10 else int(score)
        score = max(0, min(100, score))  # Clamp to valid range

        # === FAMILY from report.malware_family ===
        family = None
        family_list = report.get("malware_family", [])
        if family_list and isinstance(family_list, list) and len(family_list) > 0:
            family = family_list[0]

        # === EXTRACTED CONFIG ===
        extracted_configs = []
        extracted_list = report.get("extracted", []) or []
        for ext in extracted_list:
            ext_config = ext.get("config", {})
            if ext_config:
                extracted_configs.append(
                    {
                        "family": ext_config.get("family"),
                        "version": ext_config.get("version"),
                        "c2": ext_config.get("c2", []),
                        "botnet": ext_config.get("botnet"),
                        "mutex": ext_config.get("mutex", []),
                        "keys": ext_config.get("keys", []),
                        "rule": ext_config.get("rule"),
                        "attr": ext_config.get("attr", {}),
                    }
                )

        # === SIGNATURES (names only) ===
        signature_names = []
        # From targets[].signatures
        for target in targets:
            for sig in target.get("signatures", []):
                name = sig.get("name")
                if name and name not in signature_names:
                    signature_names.append(name)

        # From static.signatures
        static = report.get("static", {})
        for sig in static.get("signatures", []):
            name = sig.get("name")
            if name and name not in signature_names:
                signature_names.append(name)

        # === LABELS/TAGS from report.targets[].tags ===
        labels = set()
        for target in targets:
            for tag in target.get("tags", []):
                labels.add(tag)

        # === IOCs from report.targets[].iocs ===
        ioc_domains = set()
        ioc_ips = set()

        for target in targets:
            if not isinstance(target, dict):
                continue
            iocs = target.get("iocs", {})
            if not isinstance(iocs, dict):
                continue
            # Domains from targets[].iocs.domains
            for domain in iocs.get("domains", []) or []:
                if isinstance(domain, str) and not SandboxProcessor._is_benign_domain(
                    domain
                ):
                    ioc_domains.add(domain)
            # IPs from targets[].iocs.ips
            for ip in iocs.get("ips", []) or []:
                if isinstance(ip, str) and not SandboxProcessor._is_benign_ip(ip):
                    ioc_ips.add(ip)

        # === TTPs from report.ttp ===
        ttps = list(set(report.get("ttp", [])))  # Deduplicate

        # === BUILD SUMMARY ===
        summary = SandboxProcessor._build_triage_summary(
            triage_behavioral_score,
            triage_static_score,
            triage_sandbox_score,
            family,
            extracted_configs,
            signature_names,
        )

        # Get permalink from result or construct it
        permalink = result.get("permalink")
        sandbox_id = result.get("id")
        sha256 = result.get("sha256")

        # Try to construct permalink if not provided
        if not permalink and sha256 and sandbox_id:
            permalink = f"https://polyswarm.network/sandbox/detail/file/{sha256}?sandboxId={sandbox_id}"

        return {
            "provider": "triage",
            "score": score,
            "triage_behavioral_score": int(triage_behavioral_score),
            "triage_static_score": int(triage_static_score),
            "triage_sandbox_score": int(triage_sandbox_score),
            "family": family,
            "malscore": score,
            "ttps": ttps,
            "labels": list(labels),
            "signatures": signature_names,
            "extracted_configs": extracted_configs,
            "domains": [{"domain": d} for d in ioc_domains],
            "ips": list(ioc_ips),
            "c2_candidates": SandboxProcessor._extract_c2_from_extracted(
                extracted_configs
            ),
            "summary": summary,
            "permalink": permalink,
            "sandbox_id": sandbox_id,
            "sha256": sha256,
        }

    @staticmethod
    def _process_cape(result: dict) -> dict[str, Any]:
        """Process Cape sandbox results."""
        config = result.get("config", {})
        report = result.get("report", {})

        # === SCORES ===
        cape_malscore = int(SandboxProcessor._safe_num(config.get("cape_malscore")))
        report_malscore = SandboxProcessor._safe_num(report.get("malscore"))

        # Use highest score (convert to 0-100 scale if needed)
        score = max(cape_malscore, report_malscore)
        score = int(score * 10) if score <= 10 else int(score)
        score = max(0, min(100, score))  # Clamp to valid range

        # === FAMILY ===
        family = None
        # Try report.malware_family
        family_data = report.get("malware_family")
        if family_data:
            if isinstance(family_data, list) and len(family_data) > 0:
                family = family_data[0]
            elif isinstance(family_data, str):
                family = family_data

        # Try detections
        if not family:
            detections = report.get("detections", {})
            if isinstance(detections, dict):
                family = detections.get("family")

        # === SIGNATURES (names only from signature_names) ===
        signature_names = report.get("signature_names", [])

        # === LABELS from signatures categories ===
        labels = set()
        signatures = report.get("signatures", [])
        for sig in signatures:
            for cat in sig.get("categories", []):
                labels.add(cat)

        # === TTPs from report.ttp ===
        ttps = list(set(report.get("ttp", [])))  # Deduplicate

        # === NETWORK IOCs - Fixed extraction from network.hosts ===
        ioc_domains = set()
        ioc_ips = set()

        network = report.get("network", {})

        # Extract from hosts (this is where Cape puts most IPs)
        for host in network.get("hosts", []):
            if isinstance(host, dict):
                ip = host.get("ip", "")
                hostname = host.get("hostname", "")
                if ip and not SandboxProcessor._is_benign_ip(ip):
                    ioc_ips.add(ip)
                if hostname and not SandboxProcessor._is_benign_domain(hostname):
                    ioc_domains.add(hostname)
            elif isinstance(host, str):
                if not SandboxProcessor._is_benign_ip(host):
                    ioc_ips.add(host)

        # DNS
        for dns in network.get("dns", []):
            domain = dns.get("request", "") or dns.get("hostname", "")
            if domain and not SandboxProcessor._is_benign_domain(domain):
                ioc_domains.add(domain)
            for answer in dns.get("answers", []):
                ip = answer.get("data", "")
                if (
                    ip
                    and SandboxProcessor._is_valid_ip(ip)
                    and not SandboxProcessor._is_benign_ip(ip)
                ):
                    ioc_ips.add(ip)

        # Domains list
        for domain in network.get("domains", []):
            d = domain.get("domain", "") if isinstance(domain, dict) else domain
            if d and not SandboxProcessor._is_benign_domain(d):
                ioc_domains.add(d)

        # TCP connections
        for conn in network.get("tcp", []):
            dst = conn.get("dst", "")
            if dst and not SandboxProcessor._is_benign_ip(dst):
                ioc_ips.add(dst)

        # UDP connections
        for conn in network.get("udp", []):
            dst = conn.get("dst", "")
            if dst and not SandboxProcessor._is_benign_ip(dst):
                ioc_ips.add(dst)

        # === C2 CANDIDATES from Suricata ===
        c2_candidates = []
        suricata_alerts = report.get("suricata_alerts", [])
        for alert in suricata_alerts:
            category = alert.get("category", "").lower()
            if "malware" in category or "trojan" in category:
                c2_candidates.append(
                    {
                        "ip": alert.get("srcip") or alert.get("dstip"),
                        "port": alert.get("srcport") or alert.get("dstport"),
                        "reason": alert.get("signature", "Suricata alert"),
                    }
                )

        # From TLS with suspicious certs
        suricata = report.get("suricata", {})
        for tls in suricata.get("tls", []):
            subject = tls.get("subject", "")
            if subject and any(
                x in subject.lower() for x in ["rat", "malware", "dcrat"]
            ):
                c2_candidates.append(
                    {
                        "ip": tls.get("dstip"),
                        "port": tls.get("dstport"),
                        "reason": f"Suspicious TLS cert: {subject}",
                    }
                )

        # === BUILD SUMMARY - Only Cape Malscore, no Report Malscore ===
        summary = SandboxProcessor._build_cape_summary(
            cape_malscore, family, signature_names
        )

        # Get permalink or construct it
        permalink = result.get("permalink")
        sandbox_id = result.get("id")
        sha256 = result.get("sha256")

        # Try to construct permalink if not provided
        if not permalink and sha256 and sandbox_id:
            permalink = f"https://polyswarm.network/sandbox/detail/file/{sha256}?sandboxId={sandbox_id}"

        return {
            "provider": "cape",
            "score": score,
            "cape_malscore": cape_malscore,
            "family": family,
            "malscore": score,
            "ttps": ttps,
            "labels": list(labels),
            "signatures": signature_names,
            "extracted_configs": [],  # Cape handles config extraction differently
            "domains": [{"domain": d} for d in ioc_domains],
            "ips": list(ioc_ips),
            "c2_candidates": c2_candidates,
            "summary": summary,
            "permalink": permalink,
            "sandbox_id": sandbox_id,
            "sha256": sha256,
        }

    @staticmethod
    def _process_generic(result: dict) -> dict[str, Any]:
        """Fallback generic processor."""
        report = result.get("report", {})
        config = result.get("config", {})

        score = SandboxProcessor._safe_num(
            report.get("score")
        ) or SandboxProcessor._safe_num(config.get("score"))

        sha256 = result.get("sha256")
        sandbox_id = result.get("id")
        permalink = result.get("permalink")
        if not permalink and sha256 and sandbox_id:
            permalink = f"https://polyswarm.network/sandbox/detail/file/{sha256}?sandboxId={sandbox_id}"

        return {
            "provider": "unknown",
            "score": max(0, min(100, int(score * 10) if score <= 10 else int(score))),
            "family": report.get("malware_family"),
            "malscore": score,
            "ttps": report.get("ttp", []),
            "labels": [],
            "signatures": [],
            "extracted_configs": [],
            "domains": [],
            "ips": [],
            "c2_candidates": [],
            "summary": "Sandbox analysis completed.",
            "permalink": permalink,
            "sandbox_id": result.get("id"),
            "sha256": sha256,
        }

    @staticmethod
    def _build_triage_summary(
        triage_behavioral: int,
        triage_static: int,
        triage_sandbox: int,
        family: str | None,
        extracted_configs: list,
        signatures: list,
    ) -> str:
        """Build analysis summary for Triage results."""
        lines = []

        # Scores
        lines.append(f"- **Triage Behavioral Score:** {triage_behavioral}/10")
        lines.append(f"- **Triage Static Score:** {triage_static}/10")
        lines.append(f"- **Triage Sandbox Score:** {triage_sandbox}/10")

        # Family
        if family:
            lines.append(f"\n### Malware Family\n- **Triage:** {family}")

        # Extracted configs (full data)
        if extracted_configs:
            lines.append("\n### Extracted Configuration")
            for cfg in extracted_configs:
                if cfg.get("family"):
                    lines.append(f"- **Family:** {cfg['family']}")
                if cfg.get("version"):
                    lines.append(f"- **Version:** {cfg['version']}")
                if cfg.get("rule"):
                    lines.append(f"- **Rule:** {cfg['rule']}")
                if cfg.get("botnet"):
                    lines.append(f"- **Botnet:** {cfg['botnet']}")
                if cfg.get("c2"):
                    lines.append(f"- **C2 Servers:** {', '.join(cfg['c2'])}")
                if cfg.get("mutex"):
                    lines.append(f"- **Mutex:** {', '.join(cfg['mutex'])}")
                if cfg.get("keys"):
                    for key in cfg["keys"]:
                        key_name = key.get("key", "Key")
                        key_kind = key.get("kind", "")
                        key_value = key.get("value", "N/A")
                        if key_kind:
                            lines.append(
                                f"- **{key_name}** ({key_kind}): `{key_value}`"
                            )
                        else:
                            lines.append(f"- **{key_name}:** `{key_value}`")
                if cfg.get("attr"):
                    attr = cfg["attr"]
                    if attr.get("install_folder"):
                        lines.append(f"- **Install Folder:** {attr['install_folder']}")
                    if attr.get("delay"):
                        lines.append(f"- **Delay:** {attr['delay']}")
                    if "install" in attr:
                        lines.append(f"- **Install:** {attr['install']}")

        # Signatures (names only)
        if signatures:
            lines.append("\n### Triggered Signatures")
            for sig in signatures[:20]:  # Limit to 20
                lines.append(f"- {sig}")

        return "\n".join(lines)

    @staticmethod
    def _build_cape_summary(
        cape_malscore: int, family: str | None, signatures: list
    ) -> str:
        """Build analysis summary for Cape results - Only Cape Malscore."""
        lines = []

        # Only Cape Malscore (removed Report Malscore per user request)
        lines.append(f"- **Cape Malscore:** {cape_malscore}/10")

        # Family
        if family:
            lines.append(f"\n### Malware Family\n- **Cape:** {family}")

        # Signatures (names only)
        if signatures:
            lines.append("\n### Triggered Signatures")
            for sig in signatures[:20]:  # Limit to 20
                lines.append(f"- {sig}")

        return "\n".join(lines)

    @staticmethod
    def _extract_c2_from_extracted(extracted_configs: list) -> list:
        """Extract C2 candidates from extracted configs."""
        c2_candidates = []

        for cfg in extracted_configs:
            c2_list = cfg.get("c2", [])
            for c2 in c2_list:
                # Parse host:port format
                if ":" in c2:
                    parts = c2.rsplit(":", 1)
                    host = parts[0]
                    port = parts[1] if len(parts) > 1 else None

                    c2_candidates.append(
                        {
                            "ip": host,
                            "port": int(port) if port and port.isdigit() else None,
                            "reason": f"Extracted C2 from {cfg.get('family', 'config')}",
                        }
                    )
                else:
                    c2_candidates.append(
                        {
                            "ip": c2,
                            "port": None,
                            "reason": f"Extracted C2 from {cfg.get('family', 'config')}",
                        }
                    )

        return c2_candidates

    @staticmethod
    def _is_benign_domain(domain: str) -> bool:
        """Check if domain is benign/noise."""
        if not domain or not isinstance(domain, str):
            return True
        domain_lower = domain.lower()
        return any(benign in domain_lower for benign in SandboxProcessor.BENIGN_DOMAINS)

    @staticmethod
    def _is_benign_ip(ip: str) -> bool:
        """Check if IP is benign/internal."""
        if not ip:
            return True
        if ip in SandboxProcessor.BENIGN_IPS:
            return True
        # Check for internal ranges (RFC 1918)
        if ip.startswith(("10.", "192.168.")):
            return True
        # RFC 1918: 172.16.0.0/12 = 172.16.x.x through 172.31.x.x only
        if ip.startswith("172."):
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return True
            except (IndexError, ValueError):
                pass
        return ip.startswith("169.254.")  # Link-local

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        """Check if string is a valid IPv4 address."""
        if not value:
            return False
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
