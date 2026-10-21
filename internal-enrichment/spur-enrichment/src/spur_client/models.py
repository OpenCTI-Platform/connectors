"""Typed models of the Spur Context API responses.

- `IPContext`: the IP Context object (`GET /v2/context/{ip}`).
- `TagMetadata`: the Tag Metadata object (`GET /v2/metadata/tags/{tag}`).

See https://docs.spur.us/context-api/endpoints for the reference.

- Types are validated: a response with a wrong type (e.g. a string AS number)
  raises a `ValidationError` instead of producing wrong objects.
- Presence is not: Spur omits empty fields, including some that its JSON schema
  marks as required (a tunnel without `entries`, an IP without `client`...).
  Every field except `ip` and `tag` is optional, lists default to empty.
- Values with a documented list (`risks`, `services`, `infrastructure`...) are
  plain strings: Spur adds values over time, and a new one must not break the
  enrichment.
- Unknown fields are ignored.
"""

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from pydantic.alias_generators import to_camel


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


class Resell(_SpurModel):
    """A service that a tagged service resells or routes through."""

    tag: str | None = None
    products: list[str] = Field(default_factory=list)


class TagMetadata(_SpurModel):
    """The Spur Tag Metadata object: what Spur knows about a service tag.

    Field names are the snake_case version of the camelCase API fields
    (`isNoLog` becomes `is_no_log`). The documentation marks some fields as
    required (`description`, `website`...) that real responses omit.
    """

    model_config = ConfigDict(alias_generator=to_camel)

    tag: str = Field(description="Service tag (e.g. `PROTON_VPN`).")
    name: str | None = Field(default=None, description="Human-readable name.")
    description: str | None = None
    website: str | None = None
    alias_of: str | None = Field(
        default=None, description="Canonical tag that this tag aliases."
    )
    aliases: list[str] = Field(default_factory=list)
    all_tags: list[str] = Field(default_factory=list)
    categories: list[str] = Field(
        default_factory=list,
        description="Service categories (`COMMERCIAL_VPN`, `RESIDENTIAL_PROXY`...).",
    )
    is_anonymous: bool | None = None
    is_callback_proxy: bool | None = None
    is_no_log: bool | None = None
    is_enterprise: bool | None = None
    is_inactive: bool | None = None
    is_tracked: bool | None = None
    allows_white_label: bool | None = None
    allows_local_network_access: bool | None = None
    allows_crypto: bool | None = None
    allows_free_access: bool | None = None
    allows_torrents: bool | None = None
    max_age_days: int | float | None = None
    platforms: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    targeting_types: list[str] = Field(default_factory=list)
    resold_by: list[str] = Field(default_factory=list)
    resells: list[Resell] = Field(default_factory=list)
    metrics: dict[str, int | float | None] = Field(
        default_factory=dict,
        description="Service metrics (`distinctIPs`, `churnRate`...).",
    )
