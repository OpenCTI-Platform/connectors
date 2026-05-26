"""Unit tests for SandboxProcessor."""

from connector.sandbox_processor import SandboxProcessor

# ── fixtures ──────────────────────────────────────────────────────────────────


def _triage_result(
    score=80,
    family="Emotet",
    ttps=None,
    domains=None,
    ips=None,
    signatures=None,
):
    """Build a synthetic Triage sandbox result with configurable fields."""
    ttps = ttps or ["T1055", "T1082"]
    domains = domains or ["evil.example.com", "c2.badactor.net"]
    ips = ips or ["192.0.2.100", "198.51.100.55"]
    signatures = signatures or ["creates_hidden_file", "modifies_registry"]
    return {
        "sandbox": "triage",
        "sha256": "a" * 64,
        "config": {
            "traige_analysis_score": score / 10,
            "triage_static_score": 5,
        },
        "report": {
            "targets": [
                {
                    "score": score / 10,
                    "tags": ["banker"],
                    "signatures": [{"name": sig} for sig in signatures],
                    "iocs": {
                        "domains": domains,
                        "ips": ips,
                    },
                }
            ],
            "malware_family": [family],
            "ttp": ttps,
            "extracted": [],
        },
    }


def _cape_result(
    score=85,
    family="Trickbot",
    ttps=None,
    domains=None,
    ips=None,
    signatures=None,
):
    """Build a synthetic Cape sandbox result with configurable fields."""
    ttps = ttps or ["T1059.003", "T1071.001"]
    domains = domains or ["payload.badactor.org"]
    ips = ips or ["203.0.113.10"]
    signatures = signatures or ["injects_into_explorer"]
    return {
        "sandbox": "cape",
        "sha256": "b" * 64,
        "config": {
            "cape_malscore": score / 10,
        },
        "report": {
            "malscore": score / 10,
            "malware_family": family,
            "signature_names": signatures,
            "ttp": ttps,
            "signatures": [],
            "suricata_alerts": [],
            "suricata": {},
            "network": {
                "hosts": [
                    {"ip": ips[0], "hostname": domains[0]},
                ],
                "dns": [],
                "tcp": [],
                "udp": [],
                "domains": [],
            },
        },
    }


# ── provider detection ────────────────────────────────────────────────────────


class TestSandboxDetection:
    """Verify the processor auto-detects Cape vs Triage from result shape."""

    def test_detects_triage(self):
        result = SandboxProcessor.process(_triage_result())
        assert result["provider"] == "triage"

    def test_detects_cape(self):
        result = SandboxProcessor.process(_cape_result())
        assert result["provider"] == "cape"

    def test_returns_none_for_empty(self):
        assert SandboxProcessor.process(None) is None
        assert SandboxProcessor.process({}) is None


# ── triage processing ─────────────────────────────────────────────────────────


class TestTriageProcessing:
    """Verify Triage-specific field extraction: score normalisation, IOCs, benign filtering."""

    def test_score_0_to_100(self):
        result = SandboxProcessor.process(_triage_result(score=75))
        assert 0 <= result["score"] <= 100

    def test_family_extracted(self):
        result = SandboxProcessor.process(_triage_result(family="Rhadamanthys"))
        assert result["family"] == "Rhadamanthys"

    def test_ttps_extracted(self):
        result = SandboxProcessor.process(
            _triage_result(ttps=["T1486", "T1490", "T1082"])
        )
        assert "T1486" in result["ttps"]
        assert "T1490" in result["ttps"]

    def test_domains_extracted(self):
        result = SandboxProcessor.process(
            _triage_result(domains=["evil.com", "bad.net"])
        )
        domain_values = [
            d.get("domain") if isinstance(d, dict) else d for d in result["domains"]
        ]
        assert "evil.com" in domain_values

    def test_signatures_extracted(self):
        result = SandboxProcessor.process(
            _triage_result(signatures=["process_injection", "registry_modification"])
        )
        assert "process_injection" in result["signatures"]

    def test_benign_domain_filtered(self):
        result = SandboxProcessor.process(
            _triage_result(domains=["microsoft.com", "windowsupdate.com", "evil.c2.io"])
        )
        domain_values = [
            d.get("domain") if isinstance(d, dict) else d for d in result["domains"]
        ]
        assert "microsoft.com" not in domain_values
        assert "evil.c2.io" in domain_values

    def test_benign_ip_filtered(self):
        result = SandboxProcessor.process(
            _triage_result(ips=["192.168.1.1", "10.0.0.1", "203.0.113.5"])
        )
        assert "192.168.1.1" not in result["ips"]
        assert "10.0.0.1" not in result["ips"]
        assert "203.0.113.5" in result["ips"]


# ── cape processing ────────────────────────────────────────────────────────────


class TestCapeProcessing:
    """Verify Cape-specific field extraction: malscore, network hosts, signatures."""

    def test_score_0_to_100(self):
        result = SandboxProcessor.process(_cape_result(score=90))
        assert 0 <= result["score"] <= 100

    def test_family_extracted(self):
        result = SandboxProcessor.process(_cape_result(family="DarkGate"))
        assert result["family"] == "DarkGate"

    def test_ttps_extracted(self):
        result = SandboxProcessor.process(_cape_result(ttps=["T1059.001", "T1071"]))
        assert "T1059.001" in result["ttps"]

    def test_signatures_extracted(self):
        result = SandboxProcessor.process(
            _cape_result(signatures=["process_hollowing", "antiav"])
        )
        assert "process_hollowing" in result["signatures"]

    def test_cape_malscore_field_present(self):
        result = SandboxProcessor.process(_cape_result(score=70))
        assert "cape_malscore" in result

    def test_network_ips_extracted(self):
        result = SandboxProcessor.process(_cape_result(ips=["203.0.113.20"]))
        # IPs come through hosts or c2_candidates
        all_ips = result.get("ips", []) + [
            c.get("ip") for c in result.get("c2_candidates", []) if isinstance(c, dict)
        ]
        assert "203.0.113.20" in all_ips


# ── benign filtering ──────────────────────────────────────────────────────────


class TestBenignFiltering:
    """Verify RFC 1918 IPs, loopback, and known-benign domains are excluded from IOCs."""

    def test_internal_rfc1918_filtered(self):
        for ip in ("10.0.0.1", "172.16.1.1", "192.168.100.100"):
            assert SandboxProcessor._is_benign_ip(ip), f"{ip} should be filtered"

    def test_loopback_filtered(self):
        assert SandboxProcessor._is_benign_ip("127.0.0.1")

    def test_public_ip_not_filtered(self):
        # 203.0.113.0/24 is TEST-NET-3 (RFC 5737, documentation range)
        # so it's a real public IP that the benign filter MUST let
        # through. Previously this test also half-asserted on 8.8.8.8
        # via ``not _is_benign_ip("8.8.8.8") or True`` which always
        # passed regardless of the filter behaviour and was therefore
        # a no-op; that case belongs in a dedicated DNS-pinning test
        # if it ever needs to be asserted in either direction.
        assert not SandboxProcessor._is_benign_ip("203.0.113.1")

    def test_benign_domain_filtered(self):
        for d in ("microsoft.com", "windowsupdate.com", "ocsp.digicert.com"):
            assert SandboxProcessor._is_benign_domain(d), f"{d} should be filtered"

    def test_malicious_domain_not_filtered(self):
        assert not SandboxProcessor._is_benign_domain("evil-c2.badactor.io")
        assert not SandboxProcessor._is_benign_domain("malware.example.net")
