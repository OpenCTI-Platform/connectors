"""Unit tests for ModatUtils.build_summary rendering (typed-model path).

These exercise the per-service rendering branches (SSH, HTTP headers,
plain banner, TLS, technologies, per-service and host-level CVEs) plus the
empty and cap-omitted paths, on a ModatHost parsed from a representative record.
"""

from connector.utils import ModatUtils
from modat_client.models import ModatHost

RICH = {
    "asn": {"number": 64500, "org": "Example Net"},
    "geo": {"country_name": "Germany", "city_name": "Berlin", "country_iso_code": "DE"},
    "is_anycast": True,
    "tags": ["open-directory", "iot device"],
    "fqdns": ["a.example", "b.example"],
    "services": [
        {
            "transport": "tcp",
            "protocol": "ssh",
            "last_scanned_port": 22,
            "ports": [22, 2222],
            "scanned_at": "2026-05-01T00:00:00Z",
            "banner": "SSH-2.0-OpenSSH_9.6\r\nfoo",
            "ssh": {"hassh": "abc123hassh", "server_id": "OpenSSH_9.6"},
            "fingerprints": {
                "service": {"name": "OpenSSH", "version": "9.6"},
                "technologies": [{"name": "libssl", "version": "3"}, "zlib"],
            },
            "cves": [{"id": "CVE-2026-2", "cvss": 9.0, "is_kev": True}],
        },
        {
            "transport": "tcp",
            "protocol": "http",
            "last_scanned_port": 80,
            "ports": [80],
            "http": {
                "title": "Welcome",
                "status_code": 200,
                "headers": {
                    "server": "nginx/1.25",
                    "content-type": "text/html",
                    "location": "/home",
                    "x-powered-by": "PHP/8",
                    "x-other": "ignored",
                },
            },
        },
        {
            "transport": "udp",
            "protocol": "unknown",
            "last_scanned_port": 161,
            "ports": [161],
            "banner": "snmp-banner-data",
        },
        {
            "transport": "tcp",
            "protocol": "https",
            "last_scanned_port": 443,
            "ports": [443],
            "tls": {
                "fingerprint_sha256": "f" * 64,
                "subject": {"common_name": ["secure.example"]},
                "issuer": {"common_name": ["Example CA"]},
                "supported_versions": ["TLSv1.2", "TLSv1.3"],
                "valid_from": "2026-01-01T00:00:00Z",
                "expires_at": "2027-01-01T00:00:00Z",
                "is_self_signed": True,
            },
        },
    ],
    "cves": [{"id": "CVE-2026-1", "cvss": 7.1, "is_kev": False}],
}


def _summary(record, **kwargs):
    return ModatUtils(helper=None).build_summary(
        "203.0.113.5", ModatHost.model_validate(record), **kwargs
    )


def test_build_summary_renders_all_service_kinds():
    s = _summary(RICH, include_cves=True, max_services=25)

    # Host overview
    assert "Example Net" in s and "ASN `64500`" in s
    assert "Berlin, Germany" in s
    assert "Anycast" in s
    assert "Tags: open-directory, iot device" in s

    # Multi-port label + fingerprint product + technologies
    assert "(also: 2222)" in s
    assert "OpenSSH 9.6" in s
    assert "Technologies:" in s and "libssl 3" in s and "zlib" in s

    # SSH branch
    assert "hassh: `abc123hassh`" in s
    assert "Server ID: `OpenSSH_9.6`" in s
    assert "SSH-2.0-OpenSSH_9.6" in s  # banner (CRLF normalised)

    # HTTP branch: title/status/picked headers, and x-other excluded
    assert "Title: Welcome" in s
    assert "Status: `200`" in s
    assert "server: nginx/1.25" in s
    assert "content-type: text/html" in s
    assert "location: /home" in s
    assert "x-powered-by: PHP/8" in s
    assert "x-other" not in s

    # Plain (else) banner branch
    assert "snmp-banner-data" in s

    # TLS block
    assert "CN=secure.example" in s
    assert "Issuer=Example CA" in s
    assert "Versions: TLSv1.2, TLSv1.3" in s
    assert "Valid: 2026-01-01 → 2027-01-01" in s
    assert "self-signed" in s
    assert "sha256: `" + "f" * 64 + "`" in s

    # Per-service CVEs + host-level CVEs
    assert "CVE-2026-2" in s and "KEV" in s
    assert "### CVEs (host-level, unvalidated)" in s
    assert "CVE-2026-1" in s


def test_build_summary_cves_hidden_when_disabled():
    s = _summary(RICH, include_cves=False)
    assert "### CVEs (host-level, unvalidated)" not in s
    assert "CVE-2026-1" not in s


def test_build_summary_empty_record():
    s = _summary({}, include_cves=True)
    assert "No services returned." in s
    assert "No domains returned." in s


def test_build_summary_caps_are_reported():
    record = {
        "services": [{"transport": "tcp", "last_scanned_port": p} for p in range(30)],
        "fqdns": [f"d{i}.example" for i in range(30)],
        "cves": [{"id": f"CVE-2026-{i}"} for i in range(30)],
    }
    s = _summary(record, include_cves=True, max_services=5)
    assert "additional service(s) omitted" in s  # services > max_services
    assert "more omitted" in s  # domains > 20 and host CVEs > 25
