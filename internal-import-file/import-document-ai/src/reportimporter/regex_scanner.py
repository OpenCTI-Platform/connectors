"""
Regex-based IOC scanner with deterministic span IDs.

Scans free text for common structured indicators:
- IPs (IPv4/IPv6), CIDR, IPv4 ranges
- Domains, URLs (with/without scheme)
- Emails, phone numbers, ASNs, MAC addresses
- CVEs, MITRE ATT&CK IDs, intrusion-set numeric handles
- Windows registry keys
- X.509 issuer/subject/serial and fingerprints
- File hashes (MD5, SHA-1, SHA-256, SHA-512)

Outputs `Span` records with raw/normalized values and offsets suitable for
downstream STIX object creation and LLM hinting.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import phonenumbers
import tldextract
from email_validator import EmailNotValidError, validate_email

# ----------------------------- Data Structures ----------------------------- #


@dataclass(frozen=True, slots=True)
class Span:
    """A structured indicator occurrence in text."""

    id: str
    type: str
    normalized_value: str
    raw_value: str
    start: int
    end: int
    start_raw: Optional[int] = None
    end_raw: Optional[int] = None


# ----------------------------- Small Utilities ----------------------------- #


def _short_hash(value: str, size: int = 16) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:size]


def _make_id(stix_type: str, normalized_value: str) -> str:
    return f"t={stix_type.split('.', 1)[0].lower()};h={_short_hash(normalized_value)}"


def _emit(stix_type: str, value: str, start: int, end: int) -> Span:
    """Create a Span for a found IOC with normalized value and deterministic ID."""
    norm = normalize_stix_value(stix_type, value)
    return Span(
        id=_make_id(stix_type, norm),
        type=stix_type,
        normalized_value=norm,
        raw_value=value,
        start=start,
        end=end,
    )


def _trim_trailing(text: str, start: int, end: int, chars: str) -> tuple[int, int]:
    while end > start and text[end - 1] in chars:
        end -= 1
    return start, end


def _overlaps(a: int, b: int, ranges: list[tuple[int, int]]) -> bool:
    return any(a < rend and b > rstart for rstart, rend in ranges)


def _mark(ranges: list[tuple[int, int]], start: int, end: int) -> None:
    ranges.append((start, end))


# ----------------------------- Normalization ------------------------------- #


def _hostname_has_public_suffix(hostname: str) -> bool:
    """
    Validate that 'hostname' has a recognized public suffix using PSL via tldextract.
    Accept IDNs; reject bare labels, filenames, or handles (e.g., 'index.php').
    """
    if not hostname:
        return False
    hostname = hostname.rstrip(".")
    try:
        ext = tldextract.extract(hostname)
    except (LookupError, UnicodeError, ValueError):
        return False
    return bool(ext.domain and ext.suffix)


def _normalize_email_address(email: str) -> Optional[str]:
    """Normalize email to a canonical lowercase form using email_validator."""
    try:
        raw = email.rstrip(_TRAIL_DOMAIN).lower()
        v = validate_email(raw, allow_smtputf8=True, check_deliverability=False)
        return v.normalized
    except EmailNotValidError:
        return None


def _normalize_phone_number(phone: str, default_region: str = "US") -> Optional[str]:
    """Normalize phone to E.164 using phonenumbers, with conservative fallbacks."""
    try:
        pn = phonenumbers.parse(
            phone, None if phone.strip().startswith("+") else default_region
        )
        if phonenumbers.is_possible_number(pn) and phonenumbers.is_valid_number(pn):
            return phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
    except phonenumbers.NumberParseException:
        pass

    digits = re.sub(r"\D", "", phone)
    if digits.startswith("0") and 8 <= len(digits) <= 13:
        for region in ("GB", "AU", "FR", "DE", "IT", "ES"):
            try:
                pn = phonenumbers.parse(digits, region)
                if phonenumbers.is_possible_number(pn) and phonenumbers.is_valid_number(
                    pn
                ):
                    return phonenumbers.format_number(
                        pn, phonenumbers.PhoneNumberFormat.E164
                    )
            except phonenumbers.NumberParseException:
                continue
    return None


_DN_ORDER = ["C", "ST", "L", "O", "OU", "CN", "EMAILADDRESS"]
_DN_ALIAS = {
    "S": "ST",
    "STATE": "ST",
    "E": "EMAILADDRESS",
    "EMAIL": "EMAILADDRESS",
}


def _split_dn_components(dn: str) -> list[str]:
    s = dn.strip().strip("/")
    if "/" in s and "," not in s:
        return [p for p in s.split("/") if p]

    parts: list[str] = []
    buf: list[str] = []
    esc = False
    for ch in s:
        if esc:
            buf.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ",":
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def _parse_rdn(component: str) -> tuple[str, str]:
    """Parse one DN component 'key=value', normalize aliases, strip quotes."""
    if "=" not in component:
        return ("CN", component.strip())
    k, v = component.split("=", 1)
    k = _DN_ALIAS.get(k.strip().upper(), k.strip().upper())
    v = re.sub(r"\s+", " ", v.strip().strip('"'))
    return (k, v)


def _normalize_x509_dn(dn: str) -> str:
    """Normalize X.509 DN to a deterministic canonical form.

    Output format:
        'C=.., ST=.., L=.., O=.., OU=.., CN=.., EmailAddress=..'
    Unknown or unrecognized attributes are appended alphabetically.
    Returns the original DN stripped if parsing fails.
    """
    if not dn:
        return ""

    try:
        components = _split_dn_components(dn)
        parsed = [_parse_rdn(c) for c in components if c.strip()]
    except Exception:
        # Graceful fallback: return the raw DN on any parse error
        return dn.strip()

    known = [p for p in parsed if p[0] in _DN_ORDER]
    unknown = [p for p in parsed if p[0] not in _DN_ORDER]

    # Deterministic sorting for canonicalization
    known.sort(key=lambda kv: _DN_ORDER.index(kv[0]))
    unknown.sort(key=lambda kv: kv[0])

    return ", ".join(f"{k}={v}" for k, v in (known + unknown))


def normalize_stix_value(stix_type: str, value: str) -> str:
    """Normalization per STIX property type to ensure stable dedupe & ID generation."""
    v = value.strip()
    t = stix_type.lower()

    # X.509 fingerprints: drop colons, lowercase

    if t.startswith("x509-certificate.sha"):
        return v.replace(":", "").lower()
    if t.startswith("x509-certificate.serial"):
        return v.replace(":", "").replace(" ", "").lower()
    if t.startswith(("x509-certificate")):
        return _normalize_x509_dn(v)

    # File hashes -> lowercase

    if t.startswith("file.hashes."):
        return v.lower()

    # Domain/URL/email
    if t.startswith("domain-name.value"):
        return v.rstrip(".").lower()
    if t.startswith("url.value"):
        return v
    if t.startswith("email-addr.value"):
        return _normalize_email_address(v) or v.lower()

    # IPs / ranges
    if t.startswith("ipv4-addr.value") or t.startswith("ipv6-addr.value"):
        return v
    if t.startswith(("ipv4-cidr.value", "ipv4-range.value")):
        return v.replace(" ", "")

    # ASN
    if t.startswith("autonomous-system.number"):
        m = re.sub(r"(?i)^as", "", v)
        return str(int(m)) if m.isdigit() else v

    # MAC
    if t.startswith("mac-addr.value"):
        return v.lower()

    # CVE
    if t.startswith("vulnerability.name"):
        return v.upper()

    # Phone
    if t.startswith("phone-number"):
        return _normalize_phone_number(v) or v

    return v


# ----------------------------- Patterns ------------------------------------ #

# IPs and ranges
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_IPV6 = re.compile(
    r"\b("
    r"(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})|"
    r"(?:(?:[0-9a-fA-F]{1,4}:){1,7}:)|"
    r"(?:::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})|"
    r"(?:(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|"
    r"(?:(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2})|"
    r"(?:(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3})|"
    r"(?:(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4})|"
    r"(?:(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5})|"
    r"(?:[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6})|"
    r"(?:::(?:[fF]{4}:)?(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})"
    r")\b"
)
_CIDR = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:[0-9]|[12][0-9]|3[0-2])\b"
)
_IPV4_RANGE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\s*-\s*"
    r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# URLs (scheme or schemeless)
#
# Match:
#   - Full URLs with http(s)/ftp scheme and domain or IPv4 host
#   - Schemeless host/path URLs (e.g. example.com/path)
#   - Avoid email addresses, trailing punctuation, or ref/footnote links
_TRAIL_URL = ".,;:]\"\\'>"
_URL = re.compile(
    r"""
    (?:
        (?:(?:https?|ftp)://)
        (?:
            (?:[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+)
            |
            (?:\d{1,3}(?:\.\d{1,3}){3})
        )
        (?:[:/][^\s"'<>)]*)?
        |
        (?:(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}/[A-Za-z0-9][^\s"'<>)]*)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Strict RFC-ish email pattern (prevent overlap with URLs)
_EMAIL = re.compile(r"\b[a-zA-Z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
# Domain (bare hostname only) — validated later by PSL
_TRAIL_DOMAIN = ".,);:]\"\\'<>"
_DOMAIN = re.compile(
    r"\b(?=.{1,253}\b)(?!-)(?:[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z0-9-]{2,63}\b"
)

# Registry keys
_REGKEY = re.compile(
    r"\b(?:(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG))|"
    r"(?:HKLM|HKCU|HKCR|HKU|HKCC))\\(?:[^\\\/:\*\?\"<>\|\r\n]+\\)*[^\\\/:\*\?\"<>\|\r\n]+(?=$|\s|[\.,;:\)\]])",
    re.IGNORECASE,
)

# X.509 snippets & fingerprints
_X509_ISSUER = re.compile(r"\bIssuer:\s*([^\n\r]+)", re.IGNORECASE)
_X509_SUBJECT = re.compile(r"\bSubject:\s*([^\n\r]+)", re.IGNORECASE)
_X509_SERIAL = re.compile(r"\bSerial\s+Number:\s*([0-9A-Fa-f: \-]{4,})", re.IGNORECASE)
_FP_SHA1 = re.compile(
    r"(?:SHA1|SHA-1)\s*Fingerprint\s*[:=]?\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){19})",
    re.IGNORECASE,
)
_FP_SHA256 = re.compile(
    r"(?:SHA256|SHA-256)\s*Fingerprint\s*[:=]?\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){31})",
    re.IGNORECASE,
)

# Hashes
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA512 = re.compile(r"\b[a-fA-F0-9]{128}\b")

# Misc observables / entities
_ASN = re.compile(r"\bAS\s*(\d{1,10})\b", re.IGNORECASE)
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_MITRE_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_INTRUSION_NUMERIC = re.compile(
    r"\b(?:APT\d{1,3}|TA\d{1,4}|FIN\d{1,4}|UNC\d{1,5}|STORM-\d{2,4}|DEV-\d{2,4})\b",
    re.IGNORECASE,
)

# Phone numbers:
# - International (+xx)
# - Common local patterns with separators
# - Dotted forms 123.456.7890
# - Contiguous national numbers (8–13 digits) with lookarounds to avoid long runs
_PHONE = re.compile(
    r"""
    (?<!\d)
    (?:
        \+?\d{1,3}(?:[ \-\.()]*\d){5,14} |
        (?:\d{3,4}(?:\.\d{3,4}){1,4})   |
        \d{8,13}
    )
    (?!\d)
    """,
    re.VERBOSE,
)


# ----------------------------- Scanning ------------------------------------ #


def scan_structured_iocs(text: str) -> list[Span]:
    spans: list[Span] = []
    occupied: list[tuple[int, int]] = []

    # URLs first
    for m in _URL.finditer(text):
        a, b = _trim_trailing(text, m.start(), m.end(), _TRAIL_URL)
        raw = text[a:b]
        if not raw:
            continue

        # Normalize host for validation
        host = raw.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if not (_hostname_has_public_suffix(host) or _IPV4.fullmatch(host)):
            continue
        if _overlaps(a, b, occupied):
            continue

        spans.append(_emit("Url.value", raw, a, b))
        _mark(occupied, a, b)

    # Emails next (avoid overlap with URLs)
    for m in _EMAIL.finditer(text):
        if _overlaps(m.start(), m.end(), occupied):
            continue
        raw = text[m.start() : m.end()]
        if not _normalize_email_address(raw):
            continue
        spans.append(_emit("Email-Addr.value", raw, m.start(), m.end()))
        _mark(occupied, m.start(), m.end())

    # IP/CIDR/range (avoid clashes with URLs already marked)
    for m in _CIDR.finditer(text):
        if _overlaps(m.start(), m.end(), occupied):
            continue
        spans.append(
            _emit("IPv4-CIDR.value", text[m.start() : m.end()], m.start(), m.end())
        )
        _mark(occupied, m.start(), m.end())

    for m in _IPV4_RANGE.finditer(text):
        if _overlaps(m.start(), m.end(), occupied):
            continue
        spans.append(
            _emit("IPv4-Range.value", text[m.start() : m.end()], m.start(), m.end())
        )
        _mark(occupied, m.start(), m.end())

    for m in _IPV4.finditer(text):
        if _overlaps(m.start(), m.end(), occupied):
            continue
        spans.append(
            _emit("IPv4-Addr.value", text[m.start() : m.end()], m.start(), m.end())
        )
        _mark(occupied, m.start(), m.end())

    for m in _IPV6.finditer(text):
        if _overlaps(m.start(), m.end(), occupied):
            continue
        spans.append(
            _emit("IPv6-Addr.value", text[m.start() : m.end()], m.start(), m.end())
        )
        _mark(occupied, m.start(), m.end())

    # X.509 details
    for m in _X509_ISSUER.finditer(text):
        spans.append(
            _emit(
                "X509-Certificate.issuer",
                text[m.start(1) : m.end(1)].strip(),
                m.start(1),
                m.end(1),
            )
        )
        _mark(occupied, m.start(1), m.end(1))
    for m in _X509_SUBJECT.finditer(text):
        spans.append(
            _emit(
                "X509-Certificate.subject",
                text[m.start(1) : m.end(1)].strip(),
                m.start(1),
                m.end(1),
            )
        )
        _mark(occupied, m.start(1), m.end(1))
    for m in _X509_SERIAL.finditer(text):
        spans.append(
            _emit(
                "X509-Certificate.serial",
                text[m.start(1) : m.end(1)].strip(),
                m.start(1),
                m.end(1),
            )
        )
        _mark(occupied, m.start(1), m.end(1))
    for m in _FP_SHA1.finditer(text):
        spans.append(
            _emit(
                "X509-Certificate.sha1_fingerprint",
                text[m.start(1) : m.end(1)],
                m.start(1),
                m.end(1),
            )
        )
        _mark(occupied, m.start(1), m.end(1))
    for m in _FP_SHA256.finditer(text):
        spans.append(
            _emit(
                "X509-Certificate.sha256_fingerprint",
                text[m.start(1) : m.end(1)],
                m.start(1),
                m.end(1),
            )
        )
        _mark(occupied, m.start(1), m.end(1))

    # Registry keys
    for m in _REGKEY.finditer(text):
        spans.append(
            _emit(
                "Windows-Registry-Key.key",
                text[m.start() : m.end()],
                m.start(),
                m.end(),
            )
        )
        _mark(occupied, m.start(), m.end())

    # Hashes
    for m in _MD5.finditer(text):
        spans.append(
            _emit("File.hashes.MD5", text[m.start() : m.end()], m.start(), m.end())
        )
    for m in _SHA1.finditer(text):
        spans.append(
            _emit("File.hashes.SHA-1", text[m.start() : m.end()], m.start(), m.end())
        )
    for m in _SHA256.finditer(text):
        spans.append(
            _emit(
                "File.hashes.SHA-256",
                text[m.start() : m.end()],
                m.start(),
                m.end(),
            )
        )
    for m in _SHA512.finditer(text):
        spans.append(
            _emit(
                "File.hashes.SHA-512",
                text[m.start() : m.end()],
                m.start(),
                m.end(),
            )
        )

    # ASN, MAC, CVE, MITRE ATT&CK, intrusion labels
    for m in _ASN.finditer(text):
        spans.append(
            _emit(
                "Autonomous-System.number",
                text[m.start() : m.end()],
                m.start(),
                m.end(),
            )
        )
    for m in _MAC.finditer(text):
        spans.append(
            _emit("Mac-Addr.value", text[m.start() : m.end()], m.start(), m.end())
        )
    for m in _CVE.finditer(text):
        spans.append(
            _emit(
                "Vulnerability.name",
                text[m.start() : m.end()].upper(),
                m.start(),
                m.end(),
            )
        )
    for m in _MITRE_ATTACK.finditer(text):
        spans.append(
            _emit(
                "Attack-Pattern.x_mitre_id",
                text[m.start() : m.end()].upper(),
                m.start(),
                m.end(),
            )
        )
    for m in _INTRUSION_NUMERIC.finditer(text):
        spans.append(
            _emit(
                "Intrusion-Set",
                text[m.start() : m.end()].upper(),
                m.start(),
                m.end(),
            )
        )

    # Domains after URLs to avoid duplicates
    for m in _DOMAIN.finditer(text):
        raw = text[m.start() : m.end()].rstrip(_TRAIL_DOMAIN)
        a, b = m.start(), m.start() + len(raw)
        if _overlaps(a, b, occupied):
            continue
        if not _hostname_has_public_suffix(raw):
            continue
        spans.append(_emit("Domain-Name.value", raw, a, b))
        _mark(occupied, a, b)

    # Phone numbers
    for m in _PHONE.finditer(text):
        if _overlaps(m.start(), m.end(), occupied):
            continue
        raw = text[m.start() : m.end()]
        if not _normalize_phone_number(raw):
            continue
        spans.append(_emit("Phone-Number", raw, m.start(), m.end()))
        _mark(occupied, m.start(), m.end())

    # Deduplicate by (type, normalized_value), prefer earliest occurrence
    seen: Set[Tuple[str, str]] = set()
    deduped: List[Span] = []
    for sp in sorted(spans, key=lambda s: s.start):
        key = (sp.type, sp.normalized_value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(sp)

    return deduped


# ----------------------------- Hints for LLMs ------------------------------- #

OBSERVABLE_LABELS: Set[str] = {
    "Autonomous-System.number",
    "Domain-Name.value",
    "Email-Addr.value",
    "Email-Message.value",
    "File.name",
    "File.hashes.MD5",
    "File.hashes.SHA-1",
    "File.hashes.SHA-256",
    "File.hashes.SHA-512",
    "IPv4-Range.value",
    "IPv4-Addr.value",
    "IPv4-CIDR.value",
    "IPv6-Addr.value",
    "Mac-Addr.value",
    "Windows-Registry-Key.key",
    "Url.value",
    "Directory",
    "X509-Certificate.issuer",
    "X509-Certificate.subject",
    "X509-Certificate.sha1_fingerprint",
    "X509-Certificate.sha256_fingerprint",
    "Mutex",
    "User-Account",
    "Process",
    "Artifact",
    "Phone-Number",
}

HINT_PRI: Dict[str, int] = {
    "Url.value": 100,
    "Email-Addr.value": 95,
    "IPv4-CIDR.value": 90,
    "IPv4-Range.value": 88,
    "IPv4-Addr.value": 86,
    "IPv6-Addr.value": 84,
    "X509-Certificate.issuer": 80,
    "X509-Certificate.subject": 79,
    "X509-Certificate.serial": 78,
    "X509-Certificate.sha1_fingerprint": 77,
    "X509-Certificate.sha256_fingerprint": 76,
    "Windows-Registry-Key.key": 70,
    "File.hashes.MD5": 65,
    "File.hashes.SHA-1": 64,
    "File.hashes.SHA-256": 63,
    "File.hashes.SHA-512": 62,
    "Autonomous-System.number": 60,
    "Mac-Addr.value": 58,
    "Vulnerability.name": 55,
    "Attack-Pattern.x_mitre_id": 54,
    "Intrusion-Set": 53,
    "Domain-Name.value": 50,
    "Phone-Number": 40,
}


def _hint_type(label: str) -> str:
    return "observable" if label in OBSERVABLE_LABELS else "entity"


def build_hints_from_spans(
    spans: List[Span], max_hints: Optional[int] = None
) -> Dict[str, List[dict]]:
    """
    Convert spans into concise hints for LLM prompting.

    - Merge duplicates by (category, normalized value)
    - Retain unique occurrence positions
    - Order primarily by first occurrence, secondarily by priority
    - Optionally cap by `max_hints` keeping highest-priority items

    Returns:
        dict: {"hints": [ {id, type, category, value, positions[]} ]}
    """
    merged: Dict[Tuple[str, str], dict] = {}

    for sp in sorted(spans, key=lambda s: s.start):
        key = (sp.type, sp.normalized_value)
        pos = {"start": sp.start, "end": sp.end}
        h = merged.get(key)
        if not h:
            merged[key] = {
                "id": sp.id,
                "type": _hint_type(sp.type),
                "category": sp.type,
                "value": sp.raw_value,
                "positions": [pos],
                "_pri": HINT_PRI.get(sp.type, 10),
                "_first": sp.start,  # first occurrence offset (used for stable ordering)
            }
        else:
            if h["positions"][-1] != pos:
                h["positions"].append(pos)

    items = list(merged.values())
    # Stable ordering by first occurrence, then priority (desc)
    items.sort(key=lambda h: (h["_first"], -h["_pri"]))

    if max_hints and len(items) > max_hints:
        # Pick top by priority (desc), then re-sort by first occurrence for readability
        items.sort(key=lambda h: (-h["_pri"], h["_first"]))
        items = items[:max_hints]
        items.sort(key=lambda h: (h["_first"], -h["_pri"]))

    for h in items:
        h.pop("_pri", None)
        h.pop("_first", None)

    return {"hints": items}
