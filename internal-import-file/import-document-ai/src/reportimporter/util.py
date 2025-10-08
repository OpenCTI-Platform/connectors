# util.py
"""
Utility functions for STIX object creation and normalization.
Includes helpers for domain, URL, IP range, phone, hash normalization,
and STIX object mapping.
"""

import ipaddress
import json as _json
import os
import re
import urllib.parse
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Callable, Dict, List

import idna
import phonenumbers
import pycountry
import pycti
import stix2
import tldextract
from pycti import (
    AttackPattern,
    Channel,
    CourseOfAction,
    Identity,
    Incident,
    Infrastructure,
    IntrusionSet,
    Location,
    Malware,
    MalwareAnalysis,
    ThreatActor,
    ThreatActorGroup,
    Tool,
    Vulnerability,
)
from pycti.utils.constants import CustomObjectChannel, IdentityTypes
from stix2.exceptions import STIXError
from stix2.v21.vocab import INDUSTRY_SECTOR

from ._nulls import _NullHelper
from .regex_scanner import normalize_stix_value

# Precompiled regexes for performance
_MESSAGE_ID = re.compile(r"^<?[^>\s@]+@[^>\s@]+>?$")
_URL_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_SRV_HOSTNAME = re.compile(r"^(?!-)[A-Za-z0-9-_]{1,63}(?<!-)$")
_HOSTNAME = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_NETTRAFFIC = re.compile(
    r"^(?P<proto>[a-z]+)://(?P<src>[^:>]+):(?P<src_port>\d+)->(?P<dst>[^:>]+):(?P<dst_port>\d+)$",
    re.IGNORECASE,
)
_DASH_NORMALIZER = re.compile(r"\s*[\u2010-\u2015\-]\s*")  # any dash or hyphen variant


# Default to a null helper until set_helper() is called
_helper = _NullHelper()


def set_helper(helper):
    """Inject the real OpenCTI connector helper globally."""
    global _helper  # pylint: disable=global-statement
    if helper and hasattr(helper, "connector_logger"):
        _helper = helper
    else:
        _helper.connector_logger.warning(
            "Invalid helper passed to set_helper; using null helper."
        )


def _patval(s: str) -> str:
    """Escape string for use in STIX pattern literals."""
    return s.replace("\\", "\\\\").replace("'", "\\'").strip()


def _mk(object_markings: list[str] | None) -> dict:
    """Helper: add object_marking_refs when present."""
    return {"object_marking_refs": object_markings} if object_markings else {}


def _cp(cp: dict | None) -> dict:
    """Helper: add custom_properties when present."""
    return {"custom_properties": cp} if cp else {}


def _sco_cp(cp: dict | None) -> dict:
    """
    SCOs cannot use created_by_ref etc. Strip those fields while
    preserving other custom properties.
    """
    if not cp:
        return {}
    cp = dict(cp)
    cp.pop("created_by_ref", None)
    return {"custom_properties": cp} if cp else {}


def _normalize_path(value: str) -> str:
    """Normalize Windows-style escaped paths (collapse '\\\\' to '\\')."""
    return value.replace("\\\\", "\\") if value else value


def _normalize_domain(domain: str) -> str | None:
    """
    Normalize domain name:
    - Strip/trim, lowercase
    - Validate labels against hostname rules
    - Use tldextract for PSL extraction
    - Return IDNA ASCII form, or None if invalid
    """
    if not domain:
        return None

    host = domain.strip().rstrip(".").lower()
    labels = host.split(".")
    if len(host) > 253:
        return None

    labels = host.split(".")
    # Underscores allowed in non-TLD labels only
    for i, label in enumerate(labels):
        if not label:
            return None
        # For the last label (TLD), enforce strict RFC-1035 pattern
        if i == len(labels) - 1:
            if not _HOSTNAME.fullmatch(label):
                return None
        else:
            # Allow underscore in other labels
            if not _SRV_HOSTNAME.fullmatch(label):
                return None

    ext = tldextract.extract(host)
    if not (ext.domain and ext.suffix):
        return None

    try:
        return idna.encode(host).decode("ascii")
    except idna.IDNAError:
        return None


def _sanitize_url(value: str) -> str:
    """
    Normalize URL values for STIX url SCO:
    - Trim whitespace/quotes
    - Ensure scheme (default to http:// if missing)
    - Strip trailing punctuation common in prose
    """
    if not value:
        return value
    v = value.strip().strip('"').strip("'")
    if not _URL_SCHEME.match(v):
        v = f"http://{v}"
    try:
        parsed = urllib.parse.urlsplit(v)

        def strip_punct(s: str) -> str:
            return s.rstrip(".,);:'\"")

        path = strip_punct(parsed.path or "")
        query = strip_punct(parsed.query or "")
        fragment = strip_punct(parsed.fragment or "")
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, path, query, fragment)
        )
    except Exception:
        return v


def _lower_hex(s: str) -> str:
    """Lowercase and strip hex strings (hashes)."""
    return s.strip().lower()


def _as_number(value: str) -> int:
    """Normalize AS number by stripping AS/as prefix."""
    return int(re.sub(r"(?i)^as", "", value).strip())


def _normalize_phone_number(num: str, default_region="US") -> str | None:
    """
    Normalize phone numbers to E.164 format using phonenumbers.
    Assumes US if region not provided. Returns None if invalid.
    """
    if not num:
        return None
    try:
        parsed_number = phonenumbers.parse(num, default_region)
        if phonenumbers.is_valid_number(parsed_number):
            return phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.E164
            )
    except phonenumbers.NumberParseException:
        pass
    return None


def _make_stix_id(type_name: str, value: str) -> str:
    """Generate deterministic STIX ID from type and value."""
    return f"{type_name}--{uuid.uuid5(uuid.NAMESPACE_URL, f'{type_name}:{value}')}"


def range_to_cidrs(range_str: str) -> list[str]:
    """
    Convert an IPv4 address range to the minimal list of CIDR blocks.

    Example:
        >>> range_to_cidrs("223.166.0.0 - 223.167.255.255")
        ['223.166.0.0/15']

    The function:
      - Normalizes Unicode dashes (–, —, etc.)
      - Accepts optional whitespace around the dash
      - Returns [] if the input is invalid or not IPv4

    Args:
        range_str: IPv4 range like '223.166.0.0 - 223.167.255.255'

    Returns:
        List of CIDR strings, or [] if invalid.
    """
    if not range_str:
        return []

    # Normalize any dash/hyphen characters to a single ASCII dash
    s = _DASH_NORMALIZER.sub("-", range_str.strip())
    parts = [p.strip() for p in s.split("-", maxsplit=1)]
    if len(parts) != 2:
        return []

    start_ip, end_ip = parts
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
    except ipaddress.AddressValueError:
        return []

    if int(end) < int(start):
        return []

    return [str(c) for c in ipaddress.summarize_address_range(start, end)]


def _basename(p: str) -> str:
    """Normalize to basename (safe for mixed OS paths)."""
    return os.path.basename(p.replace("\\", "/"))


@lru_cache(maxsize=1024)
def _country_code(name: str) -> str:
    """
    Map a country name or ISO alpha-2/3 code to its ISO alpha-2 code.

    Uses pycountry for resolution and caches up to 1024 lookups.
    Returns 'XX' if the country cannot be resolved.

    Accepts:
        - Alpha-2 code (e.g. 'US')
        - Alpha-3 code (e.g. 'USA')
        - Common country names (e.g. 'United States', 'Belgium')
    """
    if not name:
        return "XX"

    key = name.strip()
    if not key:
        return "XX"

    # Direct alpha-2 code
    if len(key) == 2 and key.isalpha():
        return key.upper()

    # Alpha-3 code
    if len(key) == 3 and key.isalpha():
        try:
            country = pycountry.countries.get(alpha_3=key.upper())
            if country:
                return country.alpha_2
        except (LookupError, AttributeError):
            pass

    # Name lookup fallback
    try:
        country = pycountry.countries.lookup(key)
        return country.alpha_2
    except (LookupError, AttributeError):
        # Keep your warning level — but suppress repeated noise
        if key.upper() not in {"XX", "ZZ"}:
            _helper.connector_logger.warning(
                f"Could not map country '{name}' to ISO code, defaulting to 'XX'."
            )
        return "XX"


def _is_valid_hash(value: str, algo: str) -> bool:
    """Check if value matches expected hex length for given hash algorithm."""
    patterns = {
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA-1": r"^[a-fA-F0-9]{40}$",
        "SHA-256": r"^[a-fA-F0-9]{64}$",
        "SHA-512": r"^[a-fA-F0-9]{128}$",
    }
    regex = patterns.get(algo)
    return bool(regex and re.fullmatch(regex, value.strip()))


def _create_file_hash(
    value: str,
    object_markings: list[str] | None,
    custom_properties: dict | None,
    algo: str,
) -> stix2.File | None:
    """
    Create a File SCO with a single hash.
    Returns None if value is invalid.
    """
    v = value.strip().lower()
    if _is_valid_hash(v, algo):
        return stix2.File(
            hashes={algo: v},
            allow_custom=True,
            **_mk(object_markings),
            **_sco_cp(custom_properties),
        )
    _helper.connector_logger.warning(f"Ignoring invalid {algo} hash value: {value!r}")
    return None


def create_stix_object(
    category: str, value: str, object_markings: List[str], custom_properties: Dict
) -> List[Dict]:
    """
    Create a STIX object given its category and raw value.
    Always returns a list (possibly empty) of serialized dicts.
    """
    value = value.strip().rstrip(",")
    try:
        normalized_value = normalize_stix_value(category, value)
    except Exception:
        normalized_value = value
    stix_create_func = stix_object_mapping.get(category)
    if stix_create_func is None:
        _helper.connector_logger.debug(
            f"No STIX mapping for category '{category}', skipping {value!r}."
        )
        return []
    try:
        obj = stix_create_func(
            normalized_value, object_markings or [], custom_properties or {}
        )
        if obj is None:
            _helper.connector_logger.warning(
                f"STIX mapping for '{category}' returned None (invalid: {value!r})."
            )
            return []
        if not isinstance(obj, (list, tuple, set)):
            obj = [obj]
        result: List[Dict] = []
        for o in obj:
            if hasattr(o, "serialize"):
                try:
                    o = o.serialize()
                except (ValueError, TypeError, STIXError) as e:
                    _helper.connector_logger.error(
                        f"Failed to serialize STIX object {o}: {e}"
                    )
                    continue
            if isinstance(o, str):
                try:
                    o = _json.loads(o)
                except (TypeError, _json.JSONDecodeError) as e:
                    _helper.connector_logger.error(
                        f"Failed to parse serialized STIX JSON: {e}"
                    )
                    continue
            if isinstance(o, dict):
                result.append(o)
            else:
                _helper.connector_logger.warning(
                    f"Unexpected non-dict STIX object: {o!r}"
                )
        return result
    except (ValueError, TypeError, STIXError) as e:
        _helper.connector_logger.error(
            f"Error creating STIX object for '{category}' with value {value!r}: {e}"
        )
        return []


def compose_indicators_from_observables(
    observables: list,
    object_markings: list | None = None,
    created_by_ref: str | None = None,
) -> list:
    """
    Create Indicator SDOs from observables.
    Supports: domains, URLs, IPv4s, emails, file hashes, X.509.
    Skips duplicates by pattern.
    """
    indicators = []
    existing_patterns = set()

    # Collect patterns from any existing indicators
    for o in observables:
        if hasattr(o, "serialize"):
            od = o.serialize()
        elif isinstance(o, dict):
            od = o
        else:
            continue
        if isinstance(od, dict) and od.get("type") == "indicator":
            if od.get("pattern"):
                existing_patterns.add(od["pattern"])

    def _add(name: str, pattern: str):
        """Helper to add new Indicator if pattern not already present."""
        if not pattern or pattern in existing_patterns:
            return
        ind = stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern),
            name=name,
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc),
            allow_custom=True,
            **_mk(object_markings),
            **(_cp({"created_by_ref": created_by_ref}) if created_by_ref else {}),
        )
        indicators.append(ind)
        existing_patterns.add(pattern)

    # Generate indicators for each observable
    for o in observables:
        if hasattr(o, "serialize"):
            od = o.serialize()
        elif isinstance(o, dict):
            od = o
        else:
            continue
        if not isinstance(od, dict):
            continue

        t = od.get("type")
        v = od.get("value")

        if t == "domain-name" and v:
            v_norm = _normalize_domain(v)
            if v_norm:
                _add(f"Domain {v_norm}", f"[domain-name:value = '{_patval(v_norm)}']")

        elif t == "url" and v:
            v2 = v if _URL_SCHEME.match(v) else f"http://{v}"
            _add(f"URL {v}", f"[url:value = '{_patval(v2)}']")

        elif t == "ipv4-addr" and v and "/" not in v:
            _add(f"IPv4 {v}", f"[ipv4-addr:value = '{_patval(v)}']")

        elif t == "email-addr" and v:
            local, _, domain = v.partition("@")
            d_norm = _normalize_domain(domain)
            if d_norm:
                v_norm = f"{local.lower()}@{d_norm}"
                _add(f"Email {v_norm}", f"[email-addr:value = '{_patval(v_norm)}']")

        elif t == "file":
            hashes = (
                (od.get("hashes") or {}) if isinstance(od.get("hashes"), dict) else {}
            )
            md5 = hashes.get("MD5")
            sha1 = hashes.get("SHA-1") or hashes.get("SHA1")
            sha256 = hashes.get("SHA-256") or hashes.get("SHA256")
            sha512 = hashes.get("SHA-512") or hashes.get("SHA512")
            if md5:
                _add(f"MD5 {md5}", f"[file:hashes.MD5 = '{_patval(md5.lower())}']")
            if sha1:
                _add(
                    f"SHA-1 {sha1}",
                    f"[file:hashes.'SHA-1' = '{_patval(sha1.lower())}']",
                )
            if sha256:
                _add(
                    f"SHA-256 {sha256}",
                    f"[file:hashes.'SHA-256' = '{_patval(sha256.lower())}']",
                )
            if sha512:
                _add(
                    f"SHA-512 {sha512}",
                    f"[file:hashes.'SHA-512' = '{_patval(sha512.lower())}']",
                )

        elif t == "x509-certificate":
            sn = od.get("serial_number")
            issuer = od.get("issuer")
            if sn and issuer:
                pat = (
                    f"[x509-certificate:serial_number = '{_patval(sn)}' "
                    f"AND x509-certificate:issuer = '{_patval(issuer)}']"
                )
                _add(f"X509 serial {sn} + issuer", pat)
            else:
                if sn:
                    _add(
                        f"X509 serial {sn}",
                        f"[x509-certificate:serial_number = '{_patval(sn)}']",
                    )
                if issuer:
                    _add(
                        f"X509 issuer {issuer}",
                        f"[x509-certificate:issuer = '{_patval(issuer)}']",
                    )

    _helper.connector_logger.debug(
        f"Composed {len(indicators)} indicators from {len(observables)} observables"
    )
    return indicators


# ---------------------------------------------------------------------
# Mapping: extracted category -> STIX object factory
# ---------------------------------------------------------------------
stix_object_mapping: dict[str, Callable[[str, list[str], dict[str, Any]], Any]] = {
    # --- Observables (SCOs) ---
    "Artifact": lambda v, om, cp: stix2.Artifact(
        mime_type="application/octet-stream",
        payload_bin=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_sco_cp(cp),
    ),
    "Autonomous-System.number": lambda v, om, cp: stix2.AutonomousSystem(
        number=_as_number(v), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "Directory": lambda v, om, cp: stix2.Directory(
        path=_normalize_path(v), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "Domain-Name.value": lambda v, om, cp: (
        stix2.DomainName(
            value=d,
            allow_custom=True,
            **_mk(om),
            **_sco_cp(cp),
        )
        if (d := _normalize_domain(v))
        else (
            _helper.connector_logger.warning(f"Invalid domain skipped: {v!r}") or None
        )
    ),
    "Email-Addr.value": lambda v, om, cp: stix2.EmailAddress(
        value=v.strip().lower(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "Email-Message.value": lambda v, om, cp: stix2.EmailMessage(
        **(
            {"message_id": v.strip()}
            if _MESSAGE_ID.fullmatch(v.strip())
            else {"subject": v.strip()}
        ),
        allow_custom=True,
        **_mk(om),
        **_sco_cp({**(cp or {}), "x_legacy_category": "Email-Message.value"}),
    ),
    "File.hashes.MD5": lambda v, om, cp: _create_file_hash(
        _lower_hex(v), om, cp, "MD5"
    ),
    "File.hashes.SHA-1": lambda v, om, cp: _create_file_hash(
        _lower_hex(v), om, cp, "SHA-1"
    ),
    "File.hashes.SHA-256": lambda v, om, cp: _create_file_hash(
        _lower_hex(v), om, cp, "SHA-256"
    ),
    "File.hashes.SHA-512": lambda v, om, cp: _create_file_hash(
        _lower_hex(v), om, cp, "SHA-512"
    ),
    "File.name": lambda v, om, cp: stix2.File(
        name=_basename(v.strip()),
        allow_custom=True,
        **_mk(om),
        **_sco_cp({**(cp or {}), "x_original": v.strip()}),
    ),
    "IPv4-Addr.value": lambda v, om, cp: stix2.IPv4Address(
        value=v.strip(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "IPv4-CIDR.value": lambda v, om, cp: stix2.IPv4Address(
        value=v.strip(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "IPv4-Range.value": lambda v, om, cp: [
        stix2.IPv4Address(value=cidr, allow_custom=True, **_mk(om), **_sco_cp(cp))
        for cidr in range_to_cidrs(v)
    ],
    "IPv6-Addr.value": lambda v, om, cp: stix2.IPv6Address(
        value=v.strip().lower(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "Mac-Addr.value": lambda v, om, cp: stix2.MACAddress(
        value=v.strip().lower(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "Malware-Analysis": lambda v, om, cp: stix2.MalwareAnalysis(
        id=MalwareAnalysis.generate_id(
            result_name=v.strip(), product=cp.get("product", "")
        ),
        result_name=v.strip(),
        product=cp.get("product", ""),
        allow_custom=True,
        **_mk(om),
        **_sco_cp(cp),
    ),
    "Mutex": lambda v, om, cp: stix2.Mutex(
        name=v.strip(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "Network-Traffic": lambda v, om, cp: (
        stix2.NetworkTraffic(
            src_ref=cp.get("src_ref"),
            dst_ref=cp.get("dst_ref"),
            src_port=int(m.group("src_port")),
            dst_port=int(m.group("dst_port")),
            protocols=[m.group("proto").lower()],
            allow_custom=True,
            **_mk(om),
            **_sco_cp({**(cp or {}), "x_opencti_original_value": v}),
        )
        if (m := _NETTRAFFIC.match(v.strip()))
        else None
    ),
    "Phone-Number": lambda v, om, cp: (
        {
            "type": "phone-number",
            "spec_version": "2.1",
            "id": _make_stix_id("phone-number", norm),
            "value": norm,
            "object_marking_refs": om,
            **_sco_cp(cp),
        }
        if (norm := _normalize_phone_number(v.strip()))
        else None
    ),
    "Process": lambda v, om, cp: (
        stix2.Process(
            name=v.strip(),
            command_line=v.strip(),
            allow_custom=True,
            **_mk(om),
            **_sco_cp(cp),
        )
        if v.strip()
        else None
    ),
    "Url.value": lambda v, om, cp: stix2.URL(
        value=_sanitize_url(v), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "User-Account": lambda v, om, cp: stix2.UserAccount(
        user_id=v.strip(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "Windows-Registry-Key.key": lambda v, om, cp: stix2.WindowsRegistryKey(
        key=v.strip(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    # X.509
    "X509-Certificate.issuer": lambda v, om, cp: stix2.X509Certificate(
        issuer=v.strip(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "X509-Certificate.serial": lambda v, om, cp: stix2.X509Certificate(
        serial_number=v.strip(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "X509-Certificate.sha1_fingerprint": lambda v, om, cp: stix2.X509Certificate(
        hashes={"SHA-1": v.strip().lower()}, allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    "X509-Certificate.sha256_fingerprint": lambda v, om, cp: stix2.X509Certificate(
        hashes={"SHA-256": v.strip().lower()},
        allow_custom=True,
        **_mk(om),
        **_sco_cp(cp),
    ),
    "X509-Certificate.subject": lambda v, om, cp: stix2.X509Certificate(
        subject=v.strip(), allow_custom=True, **_mk(om), **_sco_cp(cp)
    ),
    # --- Entities (SDOs) ---
    "Attack-Pattern.x_mitre_id": lambda v, om, cp: stix2.AttackPattern(
        id=AttackPattern.generate_id(name=v, x_mitre_id=v),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp({**(cp or {}), "x_mitre_id": v.strip()}),
    ),
    "Campaign": lambda v, om, cp: stix2.Campaign(
        id=stix2.Campaign.generate_id(name=v.strip()),
        name=v.strip(),
        description=cp.get("description", f"Campaign: {v.strip()}"),
        objective=cp.get("objective", ""),
        aliases=cp.get("aliases", []),
        allow_custom=True,
        object_marking_refs=om,
        **_cp(cp),
    ),
    "Channel": lambda v, om, cp: CustomObjectChannel(
        id=Channel.generate_id(name=v),
        name=v,
        object_markings=om,
        custom_properties=cp,
        allow_custom=True,
    ),
    "City": lambda v, om, cp: stix2.Location(
        id=Location.generate_id(v.split(",", maxsplit=1)[0].strip(), "City"),
        name=v.split(",")[0].strip(),
        country=_country_code(v.split(",")[1].strip()) if "," in v else "XX",
        allow_custom=True,
        **_mk(om),
        **_cp(
            {
                **(cp or {}),
                "x_opencti_location_type": "City",
                "x_opencti_original_value": v,
            }
        ),
    ),
    "Country": lambda v, om, cp: stix2.Location(
        id=Location.generate_id(v.strip(), "Country"),
        name=v.strip(),
        country=_country_code(v),
        allow_custom=True,
        **_mk(om),
        **_cp({**(cp or {}), "x_opencti_location_type": "Country"}),
    ),
    "Course-Of-Action": lambda v, om, cp: stix2.CourseOfAction(
        id=CourseOfAction.generate_id(v),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp(cp),
    ),
    "Identity": lambda v, om, cp: stix2.Identity(
        id=Identity.generate_id(v, IdentityTypes.ORGANIZATION.value),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp(cp),
    ),
    "Incident": lambda v, om, cp: stix2.Incident(
        id=Incident.generate_id(
            name=v.strip(), created=datetime.now(timezone.utc).isoformat()
        ),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp(cp),
    ),
    "Individual": lambda v, om, cp: stix2.Identity(
        id=Identity.generate_id(v, IdentityTypes.INDIVIDUAL.value),
        name=v.strip(),
        identity_class="individual",
        allow_custom=True,
        **_mk(om),
        **_cp(cp),
    ),
    "Infrastructure": lambda v, om, cp: stix2.Infrastructure(
        id=Infrastructure.generate_id(name=v.strip()),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp(cp),
    ),
    "Intrusion-Set": lambda v, om, cp: stix2.IntrusionSet(
        id=IntrusionSet.generate_id(v),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp(cp),
    ),
    "Malware": lambda v, om, cp: stix2.Malware(
        id=Malware.generate_id(v),
        name=v.strip(),
        is_family=False,
        allow_custom=True,
        **_mk(om),
        **_cp(cp),
    ),
    "Organization": lambda v, om, cp: stix2.Identity(
        id=Identity.generate_id(v, IdentityTypes.ORGANIZATION.value),
        name=v.strip(),
        identity_class="organization",
        allow_custom=True,
        **_mk(om),
        **_cp(cp),
    ),
    "Region": lambda v, om, cp: stix2.Location(
        id=Location.generate_id(v, "Region"),
        name=v.strip(),
        region=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp({**(cp or {}), "x_opencti_location_type": "Region"}),
    ),
    "Sector": lambda v, om, cp: (
        stix2.Identity(
            id=Identity.generate_id(v, IdentityTypes.SECTOR.value),
            name=v.strip(),
            identity_class="class",
            allow_custom=True,
            **_mk(om),
            **_cp({**(cp or {}), "x_opencti_identity_type": "Sector"}),
        )
        if re.sub(r"\s+", "-", v.strip().lower()) in INDUSTRY_SECTOR
        else (
            _helper.connector_logger.warning(
                f"Dropping invalid Sector not in industry-sector-ov: {v!r}"
            )
            or None
        )
    ),
    "Software": lambda v, om, cp: stix2.Software(
        name=v.strip(), allow_custom=True, **_mk(om), **_cp(cp)
    ),
    "Threat-Actor": lambda v, om, cp: stix2.ThreatActor(
        id=ThreatActor.generate_id(v, "individual"),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp({**(cp or {}), "threat_actor_types": ["individual"]}),
    ),
    "Threat-Actor-Group": lambda v, om, cp: stix2.ThreatActor(
        id=ThreatActorGroup.generate_id(v),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp({**(cp or {}), "threat_actor_types": ["group"]}),
    ),
    "Threat-Actor-Individual": lambda v, om, cp: stix2.ThreatActor(
        id=ThreatActor.generate_id(v, "individual"),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp({**(cp or {}), "threat_actor_types": ["individual"]}),
    ),
    "Tool": lambda v, om, cp: stix2.Tool(
        id=Tool.generate_id(v.strip()),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp(cp),
    ),
    "Vulnerability.name": lambda v, om, cp: stix2.Vulnerability(
        id=Vulnerability.generate_id(v),
        name=v.strip(),
        allow_custom=True,
        **_mk(om),
        **_cp(cp),
    ),
}
