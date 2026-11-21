"""Extract IOC values (IP, domain, URL, hash) from OpenCTI / STIX 2.1 indicators.

The value comes from the STIX pattern, not the indicator name:
    [ipv4-addr:value = '1.2.3.4']                  -> ip      1.2.3.4
    [domain-name:value = 'evil.com']               -> domain  evil.com
    [url:value = 'http://evil.com/a']              -> url     http://evil.com/a
    [file:hashes.'SHA-256' = 'ab...']              -> hash    ab...

Rules:
- Only pattern_type 'stix' is parsed.
- Comparisons joined by OR are all extracted (each one alone is malicious),
  e.g. a file indicator carrying MD5 OR SHA-256.
- Patterns with AND, FOLLOWEDBY, NOT, qualifiers (WITHIN, REPEATS, START/STOP)
  or non-equality operators (LIKE, MATCHES, IN, !=, <, >) are skipped:
  a single value from them is not a reliable IOC on its own.
- Every value is refanged, normalised and validated; invalid ones are dropped.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"

HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
_LENGTH_TO_ALGO = {length: algo for algo, length in HASH_LENGTHS.items()}

_QUOTED = re.compile(r"'(?:[^'\\]|\\.)*'")
_COMPARISON = re.compile(
    r"(?P<obj>[a-z0-9][a-z0-9-]*)"
    r":(?P<path>(?:[A-Za-z0-9_-]+|'[^']*')(?:\.(?:[A-Za-z0-9_-]+|'[^']*'))*)"
    r"\s*=\s*"
    r"'(?P<value>(?:[^'\\]|\\.)*)'"
)
_UNSUPPORTED_KEYWORDS = re.compile(
    r"\b(AND|FOLLOWEDBY|NOT|LIKE|MATCHES|IN|ISSUBSET|ISSUPERSET|WITHIN|REPEATS|START|STOP)\b"
)
_UNSUPPORTED_OPERATORS = re.compile(r"!=|<|>")
_UNESCAPE = re.compile(r"\\(.)")

_REFANG_RULES = (
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\[@\]"), "@"),
)
_DOMAIN = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_HEX = re.compile(r"^[0-9a-f]+$")

_MAIN_OBSERVABLE_TYPES = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "hostname": "domain",
    "url": "url",
    "stixfile": "hash",
    "file": "hash",
    "artifact": "hash",
}


# ---------------------------------------------------------------------------
# OpenCTI metadata
# ---------------------------------------------------------------------------
def opencti_extension(obj: dict) -> dict:
    """The OpenCTI extension of a STIX object, or {}."""
    ext = (obj.get("extensions") or {}).get(OPENCTI_EXTENSION_ID)
    return ext if isinstance(ext, dict) else {}


def indicator_key(obj: dict) -> str | None:
    """OpenCTI internal id: unlike the STIX id, it does not change when the pattern is edited."""
    return opencti_extension(obj).get("id") or obj.get("x_opencti_id") or obj.get("id")


def get_score(obj: dict) -> int | None:
    """The indicator's OpenCTI score as an int, or None."""
    score = obj.get("x_opencti_score")
    if score is None:
        score = opencti_extension(obj).get("score")
    try:
        return int(score) if score is not None else None
    except (TypeError, ValueError):
        return None


def get_main_observable_type(obj: dict) -> str | None:
    """The indicator's main observable type, or None."""
    return opencti_extension(obj).get("main_observable_type") or obj.get(
        "x_opencti_main_observable_type"
    )


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def refang(value: str) -> str:
    """Undo common defanging (hxxp, [.], [:], ...)."""
    text = str(value).strip()
    for rule, replacement in _REFANG_RULES:
        text = rule.sub(replacement, text)
    return text


def normalize_ip(value: str) -> tuple[str, str] | None:
    """Returns (sub_type, value) or None. Single addresses lose the /32 or /128."""
    try:
        net = ipaddress.ip_network(refang(value), strict=False)
    except ValueError:
        return None
    sub_type = f"ipv{net.version}"
    if net.prefixlen == net.max_prefixlen:
        return sub_type, str(net.network_address)
    return sub_type, str(net)


def normalize_domain(value: str) -> str | None:
    """Lower-case, IDNA-encoded domain, or None when invalid."""
    text = refang(value).lower().rstrip(".")
    if not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if len(text) > 253 or not _DOMAIN.match(text):
        return None
    if text.rsplit(".", 1)[-1].isdigit():  # an IP address is not a domain
        return None
    return text


def normalize_url(value: str) -> str | None:
    """URL with a lower-case scheme and host, or None when invalid."""
    text = refang(value)
    if not text or any(ch.isspace() for ch in text):
        return None
    has_scheme = "://" in text
    try:
        parts = urlsplit(text if has_scheme else "http://" + text)
        host = parts.hostname
    except ValueError:
        return None
    if not parts.netloc or not host:
        return None
    normalized = urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path,
            parts.query,
            parts.fragment,
        )
    )
    if not has_scheme:
        normalized = normalized.split("://", 1)[1]
    return normalized


def normalize_hash(value: str, algo: str | None = None) -> tuple[str, str] | None:
    """Returns (algorithm, lower-case hex) or None."""
    text = refang(value).lower()
    if not _HEX.match(text):
        return None
    if algo not in HASH_LENGTHS:
        algo = _LENGTH_TO_ALGO.get(len(text))
        if algo is None:
            return None
    if len(text) != HASH_LENGTHS[algo]:
        return None
    return algo, text


def _normalize(
    ioc_type: str, algo: str | None, raw: str
) -> tuple[str, str, str] | None:
    """Returns (ioc_type, sub_type, value) or None."""
    if ioc_type == "ip":
        result = normalize_ip(raw)
        return ("ip", result[0], result[1]) if result else None
    if ioc_type == "domain":
        value = normalize_domain(raw)
        return ("domain", "domain", value) if value else None
    if ioc_type == "url":
        value = normalize_url(raw)
        return ("url", "url", value) if value else None
    if ioc_type == "hash":
        result = normalize_hash(raw, algo)
        return ("hash", result[0], result[1]) if result else None
    return None


def _classify(obj: str, path: str) -> tuple[str, str | None] | None:
    """Map a STIX object path to (ioc_type, hash algorithm or None)."""
    obj = obj.lower()
    path = path.replace("'", "").lower()
    if path == "value":
        if obj in ("ipv4-addr", "ipv6-addr"):
            return "ip", None
        if obj in ("domain-name", "hostname", "x-opencti-hostname"):
            return "domain", None
        if obj == "url":
            return "url", None
    if obj in ("file", "artifact") and path.startswith("hashes."):
        algo = path.split(".", 1)[1].replace("-", "").replace("_", "")
        return "hash", algo
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def extract_iocs(
    indicator: dict, name_fallback: bool = False
) -> tuple[list[tuple[str, str, str]], str | None]:
    """Returns ([(ioc_type, sub_type, value), ...], skip_reason or None)."""
    results: dict = {}
    reason = None
    pattern_type = (indicator.get("pattern_type") or "stix").lower()
    pattern = indicator.get("pattern") or ""

    if pattern_type != "stix":
        reason = f"pattern_type '{pattern_type}' is not supported"
    elif not pattern.strip():
        reason = "empty pattern"
    else:
        skeleton = _QUOTED.sub("''", pattern)
        if _UNSUPPORTED_KEYWORDS.search(skeleton) or _UNSUPPORTED_OPERATORS.search(
            skeleton
        ):
            reason = "pattern uses AND, qualifiers or non-equality operators"
        else:
            matches = list(_COMPARISON.finditer(pattern))
            if not matches or len(matches) != skeleton.count("="):
                reason = "pattern could not be fully parsed"
            else:
                for match in matches:
                    classified = _classify(match["obj"], match["path"])
                    if classified is None:
                        continue
                    raw = _UNESCAPE.sub(r"\1", match["value"])
                    ioc = _normalize(classified[0], classified[1], raw)
                    if ioc:
                        results[(ioc[0], ioc[2])] = ioc
                if not results:
                    reason = (
                        "no IP, domain, URL or hash with a valid value in the pattern"
                    )

    if not results and name_fallback:
        ioc_type = _MAIN_OBSERVABLE_TYPES.get(
            (get_main_observable_type(indicator) or "").lower()
        )
        name = indicator.get("name")
        if ioc_type and name:
            ioc = _normalize(ioc_type, None, name)
            if ioc:
                results[(ioc[0], ioc[2])] = ioc

    return list(results.values()), (None if results else reason)
