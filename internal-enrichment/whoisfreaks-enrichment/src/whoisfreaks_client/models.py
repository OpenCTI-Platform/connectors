"""
WhoisFreaks OpenCTI Connector — Typed Data Models
==================================================

Dataclasses that represent the WhoisFreaks Live WHOIS API response
(``GET /v2.0/whois/live``). ``from_response`` factory methods keep missing or
null fields graceful, so a sparse WHOIS record never raises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Registrar
# ---------------------------------------------------------------------------


@dataclass
class RegistrarData:
    """The ``domain_registrar`` object of the WHOIS response."""

    iana_id: str = ""
    handle: str = ""
    status: str = ""
    registrar_name: str = ""
    normalized_name: str = ""
    whois_server: str = ""
    rdap_server: str = ""
    website_url: str = ""
    email_address: str = ""
    phone_number: str = ""

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "RegistrarData":
        if not isinstance(d, dict):
            return cls()
        return cls(
            iana_id=_s(d.get("iana_id")),
            handle=_s(d.get("handle")),
            status=_s(d.get("status")),
            registrar_name=_s(d.get("registrar_name")),
            normalized_name=_s(d.get("normalized_name")),
            whois_server=_s(d.get("whois_server")),
            rdap_server=_s(d.get("rdap_server")),
            website_url=_s(d.get("website_url")),
            email_address=_s(d.get("email_address")),
            phone_number=_s(d.get("phone_number")),
        )

    @property
    def name(self) -> str:
        """Best display name for the registrar."""
        return self.registrar_name or self.normalized_name


# ---------------------------------------------------------------------------
# Contacts
# ---------------------------------------------------------------------------


@dataclass
class ContactData:
    """A WHOIS contact (registrant, administrative, technical, billing).

    Only the registrant contact carries the full address block; the other
    contacts commonly expose ``name`` and ``email_address`` only.
    """

    name: str = ""
    company: str = ""
    street: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = ""
    country_name: str = ""
    country_code: str = ""
    email_address: str = ""
    phone: str = ""

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "ContactData":
        if not isinstance(d, dict):
            return cls()
        return cls(
            name=_s(d.get("name")),
            company=_s(d.get("company")),
            street=_s(d.get("street")),
            city=_s(d.get("city")),
            state=_s(d.get("state")),
            zip_code=_s(d.get("zip_code")),
            country_name=_s(d.get("country_name")),
            country_code=_s(d.get("country_code")),
            email_address=_s(d.get("email_address")),
            phone=_s(d.get("phone")),
        )


# ---------------------------------------------------------------------------
# Abuse contact
# ---------------------------------------------------------------------------


@dataclass
class AbuseContactData:
    """The ``abuse_contact`` object of the WHOIS response."""

    email_address: str = ""
    phone_number: str = ""

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "AbuseContactData":
        if not isinstance(d, dict):
            return cls()
        return cls(
            email_address=_s(d.get("email_address")),
            phone_number=_s(d.get("phone_number")),
        )


# ---------------------------------------------------------------------------
# Aggregate WHOIS record
# ---------------------------------------------------------------------------


@dataclass
class WhoisRecord:
    """Full merged WHOIS record for a single domain."""

    domain_name: str = ""
    query_time: str = ""
    whois_server: str = ""
    domain_registered: str = ""
    domain_handle: str = ""
    create_date: str = ""
    update_date: str = ""
    expiry_date: str = ""
    secure_dns: bool = False
    registrar: RegistrarData = field(default_factory=RegistrarData)
    registrant: ContactData = field(default_factory=ContactData)
    administrative: ContactData = field(default_factory=ContactData)
    technical: ContactData = field(default_factory=ContactData)
    billing: ContactData = field(default_factory=ContactData)
    abuse: AbuseContactData = field(default_factory=AbuseContactData)
    name_servers: list[str] = field(default_factory=list)
    domain_status: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def is_registered(self) -> bool:
        """True unless the API explicitly reports the domain as not registered."""
        return not self.domain_registered.strip().lower().startswith("no")

    @classmethod
    def from_response(cls, data: dict) -> "WhoisRecord":
        """Build from a ``/v2.0/whois/live`` JSON response."""
        return cls(
            domain_name=_s(data.get("domain_name")),
            query_time=_s(data.get("query_time")),
            whois_server=_s(data.get("whois_server")),
            domain_registered=_s(data.get("domain_registered")),
            domain_handle=_s(data.get("domain_handle")),
            create_date=_s(data.get("create_date")),
            update_date=_s(data.get("update_date")),
            expiry_date=_s(data.get("expiry_date")),
            secure_dns=bool(data.get("secure_dns", False)),
            registrar=RegistrarData.from_dict(data.get("domain_registrar")),
            registrant=ContactData.from_dict(data.get("registrant_contact")),
            administrative=ContactData.from_dict(data.get("administrative_contact")),
            technical=ContactData.from_dict(data.get("technical_contact")),
            billing=ContactData.from_dict(data.get("billing_contact")),
            abuse=AbuseContactData.from_dict(data.get("abuse_contact")),
            name_servers=_str_list(data.get("name_servers")),
            domain_status=_str_list(data.get("domain_status")),
            raw=data if isinstance(data, dict) else {},
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _s(value) -> str:
    """Coerce a value to a stripped string, treating None as empty."""
    return str(value).strip() if value is not None else ""


def _str_list(value) -> list[str]:
    """Coerce a WHOIS array field into a clean list of non-empty strings."""
    if not isinstance(value, list):
        return []
    return [_s(item) for item in value if _s(item)]
