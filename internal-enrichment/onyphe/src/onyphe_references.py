import re

SUMMARYS = [
    ("ip.dest", 20),
    ("ip.organization", 20),
    ("cert.hostname", 20),
    ("cert.fingerprint.sha256", 20),
    ("dns.hostname", 20),
    ("tcp.dest", 20),
    ("app.protocol", 20),
    ("ip.asn", 20),
    ("ip.country", 20),
    ("component.text", 20),
]

SUMMARY_TITLES = {
    "ip.dest": "Top 20 IP addresses identified",
    "ip.organization": "Top 20 Organizations",
    "cert.hostname": "Top 20 TLS Cert Hostnames",
    "cert.fingerprint.sha256": "Top 20 TLS Cert Fingerprints",
    "dns.hostname": "Top 20 DNS Hostnames",
    "tcp.dest": "Top 20 TCP Ports",
    "app.protocol": "Top 20 Protocols",
    "ip.asn": "Top 20 Autonomous Systems",
    "ip.country": "Top 20 Countries",
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
    ("hassh.fingerprint.md5", "hassh-md5"),
    ("favicon.data.md5", "favicon-md5"),
    ("favicon.data.sha256", "favicon-sha256"),
    ("favicon.data.mmh3", "favicon-mmh3"),
]

PIVOT_MAP = dict(ANALYTICAL_PIVOTS)