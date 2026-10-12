"""Typed model of the Spur IP Context object (`GET /v2/context/{ip}`).

See https://docs.spur.us/context-api/endpoints for the reference.

- Types are validated: a response with a wrong type (e.g. a string AS number)
  raises a `ValidationError` instead of producing wrong objects.
- Presence is not: Spur omits empty fields, including some that its JSON schema
  marks as required (a tunnel without `entries`, an IP without `client`...).
  Every field except `ip` is optional, lists default to empty.
- Values with a documented list (`risks`, `services`, `infrastructure`...) are
  plain strings: Spur adds values over time, and a new one must not break the
  enrichment.
- Unknown fields are ignored.
"""

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class _SpurModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, populate_by_name=True)


class AI(_SpurModel):
    """AI activity observed from the IP."""

    operator: str | None = Field(
        default=None, description="AI entity operating on the IP (e.g. `OPENAI`)."
    )
    types: list[str] = Field(
        default_factory=list, description="AI activity types (`AGENTIC`, `CRAWLER`)."
    )


class AutonomousSystemInfo(_SpurModel):
    """Autonomous system routing the IP."""

    number: int | None = Field(default=None, description="Autonomous system number.")
    organization: str | None = Field(
        default=None, description="Organization operating the autonomous system."
    )


class Concentration(_SpurModel):
    """Where the clients of the IP are concentrated."""

    city: str | None = None
    state: str | None = None
    country: str | None = None
    density: int | float | None = Field(
        default=None, description="Concentration of the clients, from 0 to 1."
    )
    skew: int | float | None = Field(
        default=None, description="Distance from the IP `location`, in km."
    )
    geohash: str | None = None


class Client(_SpurModel):
    """Clients connecting through the IP."""

    behaviors: list[str] = Field(
        default_factory=list,
        description="Client behaviors (`FILE_SHARING`, `TOR_PROXY_USER`...).",
    )
    concentration: Concentration | None = None
    count: int | None = Field(default=None, description="Number of clients.")
    countries: int | None = Field(
        default=None, description="Number of countries the clients connect from."
    )
    proxies: list[str] = Field(
        default_factory=list,
        description="Proxy services used by the clients (Spur service tags).",
    )
    spread: int | None = Field(
        default=None, description="Geographic spread of the clients."
    )
    types: list[str] = Field(
        default_factory=list,
        description="Client device types (`DESKTOP`, `HEADLESS`, `IOT`, `MOBILE`).",
    )


class Location(_SpurModel):
    """Geolocation of the IP.

    Anycast IPs have `Anycast` as city and state, and `ZZ` as country.
    """

    city: str | None = None
    state: str | None = Field(default=None, description="State name.")
    country: str | None = Field(default=None, description="ISO 3166 alpha-2 code.")


class Tunnel(_SpurModel):
    """Anonymization service (VPN, proxy, Tor...) the IP belongs to."""

    anonymous: bool | None = None
    entries: list[str] = Field(
        default_factory=list, description="Entry node IP addresses."
    )
    exits: list[str] = Field(
        default_factory=list, description="Exit node IP addresses."
    )
    operator: str | None = Field(
        default=None, description="Operator (Spur service tag, e.g. `PROTON_VPN`)."
    )
    type: str | None = Field(default=None, description="Tunnel type (`VPN`, `TOR`...).")


class IPContext(_SpurModel):
    """The Spur IP Context object: everything Spur knows about an IP."""

    ip: IPvAnyAddress
    ai: AI | None = None
    autonomous_system: AutonomousSystemInfo | None = Field(default=None, alias="as")
    client: Client | None = None
    infrastructure: str | None = Field(
        default=None, description="Infrastructure type (`DATACENTER`, `MOBILE`...)."
    )
    location: Location | None = None
    organization: str | None = Field(
        default=None, description="Organization the IP is currently assigned to."
    )
    risks: list[str] = Field(
        default_factory=list,
        description="Risk factors (`CALLBACK_PROXY`, `GEO_MISMATCH`, `TUNNEL`...).",
    )
    services: list[str] = Field(
        default_factory=list,
        description="Protocols in use (`OPENVPN`, `WIREGUARD`...).",
    )
    tunnels: list[Tunnel] = Field(default_factory=list)
