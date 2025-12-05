SUMMARYS = [
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

SUMMARY_TITLES = {
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

HASH_KEY_MAP = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA-512": "sha512",  # not yet supported by Ctiscan
}

ANALYTICAL_PIVOTS = [
    ("hhhash.fingerprint.sha256", "hhhash-sha256"),
    ("hhhash.fingerprint.md5", "hhhash-md5"),
    ("ja4t.fingerprint.sha256", "ja4t-sha256"),
    ("ja4t.fingerprint.md5", "ja4t-md5"),
    ("ja3s.fingerprint.md5", "ja3s-md5"),
    ("ja4s.fingerprint.md5", "ja4s-md5"),
    ("hassh.fingerprint.md5", "hassh-md5"),
    ("favicon.data.md5", "favicon-md5"),
    ("favicon.data.sha256", "favicon-sha256"),
    ("favicon.data.mmh3", "favicon-mmh3"),
]

PIVOT_MAP = dict(ANALYTICAL_PIVOTS)

REVERSE_PIVOT_MAP = {v: k for k, v in PIVOT_MAP.items()}

TYPE_HANDLERS = {
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
            f"https://search.onyphe.io/search?q=category%3Actiscan+"
            f"cert.fingerprint.{HASH_KEY_MAP[next(iter(h.keys())).upper()]}%3A{next(iter(h.values()))}"
        ) if isinstance(h, dict) and h else None,
        "ONYPHE search for certificate fingerprint ({algo})",
        lambda h: next(iter(h.values())) if isinstance(h, dict) and h else None,
    ),
    "text": (
        lambda v, lp: (
            f"https://search.onyphe.io/search?q=category%3Actiscan+{REVERSE_PIVOT_MAP.get(next((l for l in lp if l in REVERSE_PIVOT_MAP), None))}%3A{v}"
            if (lp and any(l in REVERSE_PIVOT_MAP for l in lp)) else None
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
