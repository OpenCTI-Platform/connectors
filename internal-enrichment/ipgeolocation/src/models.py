"""
IPGeolocation.io OpenCTI Connector — Typed Data Models
========================================================

Dataclasses that faithfully represent the IPGeolocation.io v3 API
response schemas.  Using ``from_dict`` factory methods so missing /
null fields degrade gracefully.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _g(d: dict, *keys, default=None):
    """Safe nested dict get."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d if d is not None else default


# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------


@dataclass
class LocationData:
    continent_code: str = ""
    continent_name: str = ""
    country_code2: str = ""
    country_code3: str = ""
    country_name: str = ""
    country_name_official: str = ""
    country_capital: str = ""
    state_prov: str = ""
    state_code: str = ""
    district: str = ""
    city: str = ""
    locality: str = ""
    zipcode: str = ""
    latitude: str = ""
    longitude: str = ""
    is_eu: bool = False
    geoname_id: str = ""
    accuracy_radius: str = ""
    confidence: str = ""
    country_flag: str = ""
    country_emoji: str = ""

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> LocationData:
        if not d:
            return cls()
        return cls(
            **{k: d.get(k, getattr(cls, k, "")) for k in cls.__dataclass_fields__}
        )


# ---------------------------------------------------------------------------
# ASN Peer / Upstream / Downstream entry
# ---------------------------------------------------------------------------


@dataclass
class ASNRelEntry:
    """A single peer, upstream, or downstream AS."""

    as_number: str = ""
    description: str = ""
    country: str = ""

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> ASNRelEntry:
        if not d or not isinstance(d, dict):
            return cls()
        return cls(
            as_number=str(d.get("as_number", "")),
            description=str(d.get("description", "")),
            country=str(d.get("country", "")),
        )


# ---------------------------------------------------------------------------
# ASN (from /v3/ipgeo default or /v3/asn)
#
# Free  /v3/ipgeo:  as_number, organization, country
# Paid  /v3/ipgeo:  + type, domain, date_allocated, rir
# Paid  /v3/asn:    + asn_name, allocation_status, num_of_ipv4_routes,
#                      num_of_ipv6_routes, routes[], peers[], upstreams[],
#                      downstreams[], whois_response
# ---------------------------------------------------------------------------


@dataclass
class ASNData:
    # Common (free + paid)
    as_number: str = ""
    organization: str = ""
    country: str = ""
    # Paid /v3/ipgeo extras
    type: str = ""  # ISP, hosting, business, education
    domain: str = ""
    date_allocated: str = ""
    rir: str = ""  # ARIN, RIPE, APNIC, etc.
    # Dedicated /v3/asn extras
    asn_name: str = ""
    allocation_status: str = ""
    num_of_ipv4_routes: str = ""
    num_of_ipv6_routes: str = ""
    # Routes: list of CIDR strings like ["1.0.0.0/24", "1.0.4.0/22"]
    routes: list[str] = field(default_factory=list)
    # Network relationships: arrays of {as_number, description, country}
    peers: list[ASNRelEntry] = field(default_factory=list)
    upstreams: list[ASNRelEntry] = field(default_factory=list)
    downstreams: list[ASNRelEntry] = field(default_factory=list)
    # WHOIS
    whois_response: str = ""

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> ASNData:
        if not d:
            return cls()
        obj = cls()
        # Simple string fields
        for k in (
            "as_number",
            "organization",
            "country",
            "type",
            "domain",
            "date_allocated",
            "rir",
            "asn_name",
            "allocation_status",
            "num_of_ipv4_routes",
            "num_of_ipv6_routes",
            "whois_response",
        ):
            if k in d:
                setattr(obj, k, str(d[k]) if d[k] is not None else "")
        # Routes: list of CIDR strings
        if "routes" in d and isinstance(d["routes"], list):
            obj.routes = [str(r) for r in d["routes"] if r]
        # Peers / upstreams / downstreams: list of objects
        for rel_key in ("peers", "upstreams", "downstreams"):
            if rel_key in d and isinstance(d[rel_key], list):
                entries = []
                for item in d[rel_key]:
                    if isinstance(item, dict):
                        entries.append(ASNRelEntry.from_dict(item))
                    elif isinstance(item, str):
                        # Fallback for unexpected plain strings
                        entries.append(ASNRelEntry(as_number=item))
                setattr(obj, rel_key, entries)
        return obj


# ---------------------------------------------------------------------------
# Company
# ---------------------------------------------------------------------------


@dataclass
class CompanyData:
    name: str = ""
    type: str = ""  # business, isp, hosting, education
    domain: str = ""

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> CompanyData:
        if not d:
            return cls()
        return cls(
            name=d.get("name", ""),
            type=d.get("type", ""),
            domain=d.get("domain", ""),
        )


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


@dataclass
class NetworkData:
    connection_type: str = ""
    route: str = ""
    is_anycast: bool = False

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> NetworkData:
        if not d:
            return cls()
        return cls(
            connection_type=d.get("connection_type", ""),
            route=d.get("route", ""),
            is_anycast=bool(d.get("is_anycast", False)),
        )


# ---------------------------------------------------------------------------
# Timezone
# ---------------------------------------------------------------------------


@dataclass
class TimezoneData:
    name: str = ""
    offset: float = 0.0
    offset_with_dst: float = 0.0
    current_time: str = ""
    is_dst: bool = False
    dst_savings: int = 0
    dst_exists: bool = False
    dst_start: str = ""
    dst_end: str = ""

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> TimezoneData:
        if not d:
            return cls()
        return cls(
            name=d.get("name", ""),
            offset=float(d.get("offset", 0)),
            offset_with_dst=float(d.get("offset_with_dst", 0)),
            current_time=d.get("current_time", ""),
            is_dst=bool(d.get("is_dst", False)),
            dst_savings=int(d.get("dst_savings", 0)),
            dst_exists=bool(d.get("dst_exists", False)),
            dst_start=d.get("dst_start", ""),
            dst_end=d.get("dst_end", ""),
        )


# ---------------------------------------------------------------------------
# Currency
# ---------------------------------------------------------------------------


@dataclass
class CurrencyData:
    code: str = ""
    name: str = ""
    symbol: str = ""

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> CurrencyData:
        if not d:
            return cls()
        return cls(
            code=d.get("code", ""),
            name=d.get("name", ""),
            symbol=d.get("symbol", ""),
        )


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


@dataclass
class SecurityData:
    threat_score: int = 0
    is_tor: bool = False
    is_proxy: bool = False
    proxy_provider_names: list[str] = field(default_factory=list)
    proxy_confidence_score: int = 0
    proxy_last_seen: str = ""
    is_residential_proxy: bool = False
    is_vpn: bool = False
    vpn_provider_names: list[str] = field(default_factory=list)
    vpn_confidence_score: int = 0
    vpn_last_seen: str = ""
    is_relay: bool = False
    relay_provider_name: str = ""
    is_anonymous: bool = False
    is_known_attacker: bool = False
    is_bot: bool = False
    is_spam: bool = False
    is_cloud_provider: bool = False
    cloud_provider_name: str = ""

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> SecurityData:
        if not d:
            return cls()
        obj = cls()
        for k in cls.__dataclass_fields__:
            if k in d:
                val = d[k]
                ann = cls.__dataclass_fields__[k].type
                if "list" in str(ann):
                    setattr(obj, k, val if isinstance(val, list) else [])
                elif "bool" in str(ann):
                    setattr(obj, k, bool(val))
                elif "int" in str(ann):
                    setattr(obj, k, int(val) if val else 0)
                else:
                    setattr(obj, k, str(val) if val is not None else "")
        return obj


# ---------------------------------------------------------------------------
# Abuse Contact
# ---------------------------------------------------------------------------


@dataclass
class AbuseData:
    route: str = ""
    country: str = ""
    name: str = ""
    organization: str = ""
    kind: str = ""
    address: str = ""
    emails: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> AbuseData:
        if not d:
            return cls()
        return cls(
            route=d.get("route", ""),
            country=d.get("country", ""),
            name=d.get("name", ""),
            organization=d.get("organization", ""),
            kind=d.get("kind", ""),
            address=d.get("address", ""),
            emails=d.get("emails", []) or [],
            phone_numbers=d.get("phone_numbers", []) or [],
        )


# ---------------------------------------------------------------------------
# Aggregate IP Intelligence
# ---------------------------------------------------------------------------


@dataclass
class IPIntelligence:
    """Full merged intelligence for a single IP address."""

    ip: str = ""
    hostname: str = ""
    domain: str = ""
    location: LocationData = field(default_factory=LocationData)
    asn: ASNData = field(default_factory=ASNData)
    company: CompanyData = field(default_factory=CompanyData)
    network: NetworkData = field(default_factory=NetworkData)
    timezone: TimezoneData = field(default_factory=TimezoneData)
    currency: CurrencyData = field(default_factory=CurrencyData)
    security: SecurityData = field(default_factory=SecurityData)
    abuse: AbuseData = field(default_factory=AbuseData)
    raw_responses: dict = field(default_factory=dict)

    @classmethod
    def from_ipgeo_response(cls, data: dict) -> IPIntelligence:
        """Build from /v3/ipgeo (possibly with include=security,abuse)."""
        return cls(
            ip=data.get("ip", ""),
            hostname=data.get("hostname", ""),
            domain=data.get("domain", ""),
            location=LocationData.from_dict(data.get("location")),
            asn=ASNData.from_dict(data.get("asn")),
            company=CompanyData.from_dict(data.get("company")),
            network=NetworkData.from_dict(data.get("network")),
            timezone=TimezoneData.from_dict(data.get("time_zone")),
            currency=CurrencyData.from_dict(data.get("currency")),
            security=SecurityData.from_dict(data.get("security")),
            abuse=AbuseData.from_dict(data.get("abuse")),
            raw_responses={"ipgeo": data},
        )

    def merge_security(self, data: dict) -> None:
        """Overlay dedicated /v3/security response."""
        sec = data.get("security", data)
        self.security = SecurityData.from_dict(sec)
        self.raw_responses["security"] = data

    def merge_asn(self, data: dict) -> None:
        """Overlay detailed /v3/asn response."""
        asn_block = data.get("asn", data)
        self.asn = ASNData.from_dict(asn_block)
        self.raw_responses["asn"] = data

    def merge_abuse(self, data: dict) -> None:
        """Overlay /v3/abuse response."""
        abuse_block = data.get("abuse", data)
        self.abuse = AbuseData.from_dict(abuse_block)
        self.raw_responses["abuse"] = data
