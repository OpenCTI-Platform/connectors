import re

SUMMARYS = [
    ("ip.organization", 20),
    ("cert.domain", 20),
    ("dns.domain", 20),
    ("tcp.dest", 20),
    ("app.protocol", 20),
    ("ip.asn", 20),
    ("ip.country", 20),
    ("component.text", 20),
]

SUMMARY_TITLES = {
    "ip.organization": "Top 20 Organizations",
    "cert.domain": "Top 20 TLS Cert Domains",
    "dns.domain": "Top 20 DNS Domains",
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


def extract_observables_from_pattern(pattern, pattern_type="stix"):
    observables = {}

    if pattern_type == "stix":
        regexes = {
            "ipv4-addr": r"\[?ipv4-addr:value\s*=\s*'([^']+)'",
            "ipv6-addr": r"\[?ipv6-addr:value\s*=\s*'([^']+)'",
            "hostname": r"\[?hostname:value\s*=\s*'([^']+)'",
            "x509-certificate": r"\[?x509-certificate:hashes\.'[^']+'\s*=\s*'([^']+)'",
            "text": r"\[?text:value\s*=\s*'([^']+)'",
        }
    elif pattern_type == "shodan":
        regexes = {
            "ipv4-addr": r"\bip\s*:\s*([\d\.]+)",
            "hostname": r"\b(hostname|dns|http\.host)\s*:\s*\"?([\w\.-]+)\"?",
            "x509-certificate": r"\bssl\.cert\.fingerprint\s*:\s*([A-Fa-f0-9:]+)",
            "organization": r"\borg\s*:\s*\"?([\w\s\.-]+)\"?",
            "asn": r"\basn\s*:\s*(AS\d+)",
            "text": r"\b(ja4t|hassh|hhhash|favicon)\S*:\s*(\S+)",
        }

    for obs_type, regex in regexes.items():
        matches = re.findall(regex, pattern)
        for match in matches:
            # Normalize match for multi-capture groups
            if isinstance(match, tuple):
                value = next((m for m in match if m), None)
            else:
                value = match
            if value:
                observables[value] = obs_type

    return observables
