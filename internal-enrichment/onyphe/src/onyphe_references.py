from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Callable, Dict, List, Optional, Tuple

# ─── Shared ───────────────────────────────────────────────────────────────────

HASH_KEY_MAP = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA-512": "sha512",  # not yet supported by Ctiscan
}

ANALYTICAL_PIVOTS = [
    # HTTP header hash (HHHash)
    ("hhhash.fingerprint.sha256", "hhhash-sha256"),
    ("hhhash.fingerprint.md5", "hhhash-md5"),
    # JA4T TCP fingerprint — only md5 exists in the data model
    ("ja4t.fingerprint.md5", "ja4t-md5"),
    # JA3S / JA4S TLS fingerprints — only md5 exists in the data model
    ("ja3s.fingerprint.md5", "ja3s-md5"),
    ("ja4s.fingerprint.md5", "ja4s-md5"),
    # HASSH SSH client fingerprint — only md5 exists in the data model
    ("hassh.fingerprint.md5", "hassh-md5"),
    # Favicon
    ("favicon.data.sha256", "favicon-sha256"),
    ("favicon.data.md5", "favicon-md5"),
    ("favicon.data.mmh3", "favicon-mmh3"),
    # TCP fingerprint — only md5 exists in the data model
    ("tcp.fingerprint.md5", "tcp-fingerprint-md5"),
    # Raw application-layer payload hash
    ("app.data.sha256", "app-data-sha256"),
    ("app.data.md5", "app-data-md5"),
    ("app.data.mmh3", "app-data-mmh3"),
    # HTTP header block hash
    ("http.header.data.sha256", "http-header-data-sha256"),
    ("http.header.data.md5", "http-header-data-md5"),
    ("http.header.data.mmh3", "http-header-data-mmh3"),
    # HTTP body hash
    ("http.body.data.sha256", "http-body-data-sha256"),
    ("http.body.data.md5", "http-body-data-md5"),
    ("http.body.data.mmh3", "http-body-data-mmh3"),
    # SSH host-key fingerprint
    ("ssh.fingerprint.sha256", "ssh-fingerprint-sha256"),
    ("ssh.fingerprint.md5", "ssh-fingerprint-md5"),
]

# Default active pivot labels: prefer sha256; fall back to md5 for pivot families
# where sha256 is absent from the ctiscan data model.
DEFAULT_PIVOT_LABELS: List[str] = [
    "hhhash-sha256",
    "ja4t-md5",  # no sha256 in data model
    "ja3s-md5",  # no sha256 in data model
    "ja4s-md5",  # no sha256 in data model
    "hassh-md5",  # no sha256 in data model
    "favicon-sha256",
    "tcp-fingerprint-md5",  # no sha256 in data model
    "app-data-sha256",
    "http-header-data-sha256",
    "http-body-data-sha256",
    "ssh-fingerprint-sha256",
]

PIVOT_MAP = dict(ANALYTICAL_PIVOTS)

REVERSE_PIVOT_MAP = {v: k for k, v in PIVOT_MAP.items()}

# Maps each generator function name to the OpenCTI observable type(s) it produces.
# Generators absent from this map are infrastructure (always run regardless of filter):
#   _generate_stix_identity, _upsert_stix_observable
# The relationships generator is handled separately: it runs only when both
# Hostname and Domain-Name are in the enabled types.
GENERATOR_TYPE_MAP: Dict[str, List[str]] = {
    "_generate_stix_domain": ["Domain-Name"],
    "_generate_stix_ip": ["IPv4-Address", "IPv6-Address"],
    "_generate_stix_hostname": ["Hostname"],
    "_generate_stix_text": ["Text"],
    "_generate_stix_asn": ["Autonomous-System"],
    "_generate_stix_x509": ["X509-Certificate"],
    "_generate_stix_vulnerability": ["Vulnerability"],
}


# ─── Ctiscan ──────────────────────────────────────────────────────────────────

_CTISCAN_SUMMARYS: List[Tuple[str, int]] = [
    ("ip.dest", 20),
    ("ip.organization", 20),
    ("ip.asn", 20),
    ("ip.country", 20),
    ("cert.hostname", 20),
    ("cert.domain", 20),
    ("dns.hostname", 20),
    ("tcp.dest", 20),
    ("app.protocol", 20),
    ("component.text", 20),
]

_CTISCAN_SUMMARY_TITLES: Dict[str, str] = {
    "ip.dest": "Top 20 IP addresses identified",
    "ip.organization": "Top 20 Organizations",
    "ip.asn": "Top 20 Autonomous Systems",
    "ip.country": "Top 20 Countries",
    "cert.hostname": "Top 20 TLS Cert Hostnames",
    "cert.domain": "Top 20 TLS Cert Domains",
    "dns.hostname": "Top 20 DNS Hostnames",
    "tcp.dest": "Top 20 TCP Ports",
    "app.protocol": "Top 20 Protocols",
    "component.text": "Top 20 Technologies",
}

_CTISCAN_TYPE_HANDLERS: Dict = {
    "ipv4-addr": (
        lambda v: f"https://search.onyphe.io/search?q=category%3Actiscan+ip.dest%3A{v}",
        "ONYPHE search for IP address {value}",
        lambda v: v,
    ),
    "ipv6-addr": (
        lambda v: f"https://search.onyphe.io/search?q=category%3Actiscan+ip.dest%3A{v}",
        "ONYPHE search for IP address {value}",
        lambda v: v,
    ),
    "hostname": (
        lambda v: (
            f"https://search.onyphe.io/search?q=category%3Actiscan+"
            f"%3Fdns.hostname%3A{v}+%3Fcert.hostname%3A{v}"
        ),
        "ONYPHE search for hostname {value}",
        lambda v: v,
    ),
    "domain-name": (
        lambda v: (
            f"https://search.onyphe.io/search?q=category%3Actiscan+"
            f"%3Fcert.domain%3A{v}+%3Fdns.domain%3A{v}"
        ),
        "ONYPHE search for domain {value}",
        lambda v: v,
    ),
    "x509-certificate": (
        lambda h: (
            (
                f"https://search.onyphe.io/search?q=category%3Actiscan+"
                f"cert.fingerprint.{HASH_KEY_MAP[next(iter(h.keys())).upper()]}%3A{next(iter(h.values()))}"
            )
            if isinstance(h, dict) and h
            else None
        ),
        "ONYPHE search for certificate fingerprint ({algo})",
        lambda h: next(iter(h.values())) if isinstance(h, dict) and h else None,
    ),
    "text": (
        lambda v, lp: (
            f"https://search.onyphe.io/search?q=category%3Actiscan+{REVERSE_PIVOT_MAP.get(next((l for l in lp if l in REVERSE_PIVOT_MAP), None))}%3A{v}"
            if (lp and any(l in REVERSE_PIVOT_MAP for l in lp))
            else None
        ),
        "ONYPHE search for analytical pivot {pivot_label} = {value}",
        lambda v: v,
    ),
    "organization": (
        lambda v: f'https://search.onyphe.io/search?q=category%3Actiscan+ip.organization%3A"{v}"',
        "ONYPHE search for organization {value}",
        lambda v: v,
    ),
    "asn": (
        lambda v: f"https://search.onyphe.io/search?q=category%3Actiscan+ip.asn%3A{v}",
        "ONYPHE search for ASN {value}",
        lambda v: str(v),
    ),
}

# Paths in the ctiscan (layered) data model.
# List values mean "check each path and merge all results".
# cert_root: path to the sub-dict containing all cert fields.
# cert_sha256: path to the cert SHA-256 fingerprint used as a dedup key.
# ip_version: integer field returning 4 or 6.
_CTISCAN_FIELD_MAP: Dict[str, Optional[object]] = {
    "ip_dest": "ip.dest",
    "ip_version": "ip.version",  # integer: 4 or 6
    "ip_asn": "ip.asn",
    "ip_org": "ip.organization",
    "dns_domain": ["dns.domain", "cert.domain"],
    "dns_hostname": ["dns.hostname", "cert.hostname"],
    # Per-field relationship type for hostnames.
    # dns.hostname comes from the DNS layer → resolves-to is accurate.
    # cert.hostname comes from certificate SANs → related-to is more honest.
    "dns_hostname_rel": {"dns.hostname": "resolves-to", "cert.hostname": "related-to"},
    "cert_root": "cert",  # cert data lives under ojson["cert"]
    "cert_sha256": "cert.fingerprint.sha256",
    "cve": "component.cve",
}

_CTISCAN_OQL_FILTERS: Dict[str, Optional[Callable]] = {
    "ipv4-addr": lambda v: f"ip.dest:{v}",
    "ipv6-addr": lambda v: f"ip.dest:{v}",
    "hostname": lambda v: f"( ?dns.hostname:{v} ?cert.hostname:{v})",
    "domain-name": lambda v: f"( ?dns.domain:{v} ?cert.domain:{v} ?extract.domain:{v})",
    # x509-certificate and text are handled with special logic in _process_message
}

_CTISCAN_STIX_GENERATORS: Dict[str, List[str]] = {
    "ipv4-addr": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_x509",
        "_generate_stix_text",
        "_upsert_stix_observable",
    ],
    "ipv6-addr": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_x509",
        "_generate_stix_text",
        "_upsert_stix_observable",
    ],
    "hostname": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_ip",
        "_generate_stix_text",
        "_upsert_stix_observable",
    ],
    "domain-name": [
        "_generate_stix_identity",
        "_generate_stix_asn",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_ip",
        "_generate_stix_x509",
        "_generate_stix_text",
        "_upsert_stix_observable",
    ],
    "x509-certificate": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_ip",
        "_generate_stix_text",
        "_upsert_stix_observable",
    ],
    "text": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_ip",
        "_generate_stix_x509",
        "_upsert_stix_observable",
    ],
    "indicator": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_ip",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_x509",
    ],
}


# ─── Riskscan ─────────────────────────────────────────────────────────────────
# Riskscan uses the old flat datascan data model, not the ctiscan layered model.
# Key structural differences:
#   - ip_version: boolean field "ipv6" (True = IPv6) instead of integer "ip.version"
#   - hostname: single merged list containing reverse DNS, forward DNS, and
#     FQDNs from cert subject.commonname / subject.altname — no separate split
#   - cert data: at the top level of the document (not nested under "cert")
#   - cert field names: "commonname"/"altname" vs "cn"/"an"; "serial" is a
#     plain string vs {"hex": "..."}
#   - fingerprint.md5/sha1/sha256 at top level (not under "cert")
#   - cve: flat "cve" field vs "component.cve"

# For riskscan the summary style is "findings_table", not frequency counts.
# This list is used only to build the -fields: OQL parameter so the API returns
# exactly the fields needed to render the findings table.
_RISKSCAN_SUMMARYS: List[Tuple[str, int]] = [
    ("tag", 0),  # risk tags, e.g. risk::opendatabase
    ("cve", 0),
    ("ip", 0),
    ("port", 0),
    ("transport", 0),
    ("protocol", 0),
    ("tls", 0),
    ("hostname", 0),
    ("organization", 0),
]


_RISKSCAN_TYPE_HANDLERS: Dict = {
    "ipv4-addr": (
        lambda v: f"https://search.onyphe.io/search?q=category%3Ariskscan+ip%3A{v}",
        "ONYPHE riskscan search for IP address {value}",
        lambda v: v,
    ),
    "ipv6-addr": (
        lambda v: f"https://search.onyphe.io/search?q=category%3Ariskscan+ip%3A{v}",
        "ONYPHE riskscan search for IP address {value}",
        lambda v: v,
    ),
    "hostname": (
        lambda v: f"https://search.onyphe.io/search?q=category%3Ariskscan+hostname%3A{v}",
        "ONYPHE riskscan search for hostname {value}",
        lambda v: v,
    ),
    "domain-name": (
        lambda v: f"https://search.onyphe.io/search?q=category%3Ariskscan+domain%3A{v}",
        "ONYPHE riskscan search for domain {value}",
        lambda v: v,
    ),
    "x509-certificate": (
        lambda h: (
            (
                f"https://search.onyphe.io/search?q=category%3Ariskscan+"
                f"fingerprint.{HASH_KEY_MAP[next(iter(h.keys())).upper()]}%3A{next(iter(h.values()))}"
            )
            if isinstance(h, dict) and h
            else None
        ),
        "ONYPHE riskscan search for certificate fingerprint ({algo})",
        lambda h: next(iter(h.values())) if isinstance(h, dict) and h else None,
    ),
    "organization": (
        lambda v: f'https://search.onyphe.io/search?q=category%3Ariskscan+organization%3A"{v}"',
        "ONYPHE riskscan search for organization {value}",
        lambda v: v,
    ),
    "asn": (
        lambda v: f"https://search.onyphe.io/search?q=category%3Ariskscan+asn%3A{v}",
        "ONYPHE riskscan search for ASN {value}",
        lambda v: str(v),
    ),
}

# Paths in the riskscan (flat datascan) data model.
# cert_root: None means cert fields live at the document top level (not nested).
# cert_sha256: path to the cert SHA-256 fingerprint used as a dedup key.
# ip_version: "ipv6" is a boolean (True = IPv6, False/absent = IPv4).
# dns_hostname: "hostname" alone — this field already merges reverse DNS,
#   forward DNS, and cert FQDNs; no need to query "reverse" separately.
_RISKSCAN_FIELD_MAP: Dict[str, Optional[object]] = {
    "ip_dest": "ip",
    "ip_version": "ipv6",  # boolean: True = IPv6, False/absent = IPv4
    "ip_asn": "asn",
    "ip_org": "organization",
    "dns_domain": ["domain"],
    "dns_hostname": ["hostname"],
    "cert_root": None,  # cert fields are at the document top level
    "cert_sha256": "fingerprint.sha256",
    "cve": "cve",
}

_RISKSCAN_OQL_FILTERS: Dict[str, Optional[Callable]] = {
    "ipv4-addr": lambda v: f"ip:{v}",
    "ipv6-addr": lambda v: f"ip:{v}",
    "hostname": lambda v: f"hostname:{v}",
    "domain-name": lambda v: f"domain:{v}",
    # x509-certificate is handled with special logic in _process_message
}

_RISKSCAN_STIX_GENERATORS: Dict[str, List[str]] = {
    "ipv4-addr": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_x509",
        "_generate_stix_vulnerability",
        "_upsert_stix_observable",
    ],
    "ipv6-addr": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_x509",
        "_generate_stix_vulnerability",
        "_upsert_stix_observable",
    ],
    "hostname": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_ip",
        "_generate_stix_x509",
        "_generate_stix_vulnerability",
        "_upsert_stix_observable",
    ],
    "domain-name": [
        "_generate_stix_identity",
        "_generate_stix_asn",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_ip",
        "_generate_stix_x509",
        "_generate_stix_vulnerability",
        "_upsert_stix_observable",
    ],
    "x509-certificate": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_ip",
        "_generate_stix_vulnerability",
        "_upsert_stix_observable",
    ],
    "indicator": [
        "_generate_stix_identity",
        "_generate_stix_domain",
        "_generate_stix_asn",
        "_generate_stix_ip",
        "_generate_stix_hostname",
        "_generate_stix_hostname_domain_relationships",
        "_generate_stix_x509",
        "_generate_stix_vulnerability",
    ],
}


# ─── Profile registry ─────────────────────────────────────────────────────────


@dataclass
class CategoryProfile:
    category: str
    summarys: List[Tuple[str, int]]
    summary_titles: Dict[str, str]
    type_handlers: Dict
    field_map: Dict[str, Optional[object]]
    oql_filters: Dict[str, Optional[Callable]]
    stix_generators: Dict[str, List[str]]
    summary_style: str = dc_field(default="frequency")
    # "frequency": top-N value counts per field (ctiscan default)
    # "findings_table": structured | Risk/CVE | IP:Port | Service | Hostname | Org | table


CATEGORY_PROFILES: Dict[str, CategoryProfile] = {
    "ctiscan": CategoryProfile(
        category="ctiscan",
        summarys=_CTISCAN_SUMMARYS,
        summary_titles=_CTISCAN_SUMMARY_TITLES,
        type_handlers=_CTISCAN_TYPE_HANDLERS,
        field_map=_CTISCAN_FIELD_MAP,
        oql_filters=_CTISCAN_OQL_FILTERS,
        stix_generators=_CTISCAN_STIX_GENERATORS,
    ),
    "riskscan": CategoryProfile(
        category="riskscan",
        summarys=_RISKSCAN_SUMMARYS,
        summary_titles={},
        type_handlers=_RISKSCAN_TYPE_HANDLERS,
        field_map=_RISKSCAN_FIELD_MAP,
        oql_filters=_RISKSCAN_OQL_FILTERS,
        stix_generators=_RISKSCAN_STIX_GENERATORS,
        summary_style="findings_table",
    ),
}
