"""Validated models of CrowdStrike Falcon Intelligence API resources.

The models mirror what the API returns and nothing more: no derived field.
Fields are inferred from FalconPy's ``QueryIntelIndicatorEntities`` filter
documentation and from the existing CrowdStrike connector. They are lenient
on purpose (``extra="allow"``, few required fields) until real responses
confirm their shape. ``reports``, ``relations`` and ``scope`` are known to
exist but are left undeclared: their shape is unknown, and ``extra="allow"``
keeps them verbatim.

``CrowdStrikeActor`` mirrors an actor of ``QueryIntelActorEntities`` the same
way. ``EnrichedCrowdStrikeIndicator`` is the one model that adds a field: the
actors an indicator names, looked up by the extractor.
"""

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

_API_MODEL_CONFIG = ConfigDict(
    extra="allow",
    validate_by_alias=True,
    validate_by_name=True,
    serialize_by_alias=True,
)


class CrowdStrikeLabel(BaseModel):
    """A label attached to an indicator."""

    model_config = _API_MODEL_CONFIG

    name: str
    created_on: AwareDatetime | None = None
    last_valid_on: AwareDatetime | None = None


class CrowdStrikeIndicator(BaseModel):
    """An indicator as returned by ``GET /intel/combined/indicators/v1``."""

    model_config = _API_MODEL_CONFIG

    id: str
    indicator: str
    type: str
    # Pydantic treats names starting with "_" as private attributes, hence the
    # alias. The marker is a 10-digit Unix timestamp followed by a unique suffix.
    marker: str = Field(alias="_marker", pattern=r"^\d{10}")
    last_updated: AwareDatetime

    published_date: AwareDatetime | None = None
    deleted: bool | None = None
    malicious_confidence: str | None = None
    actors: list[str] | None = None
    malware_families: list[str] | None = None
    kill_chains: list[str] | None = None
    targets: list[str] | None = None
    vulnerabilities: list[str] | None = None
    threat_types: list[str] | None = None
    domain_types: list[str] | None = None
    ip_address_types: list[str] | None = None
    labels: list[CrowdStrikeLabel] | None = None


class CrowdStrikeActor(BaseModel):
    """An actor as returned by ``GET /intel/combined/actors/v1``.

    Only fields whose shape the existing connector shows to be scalar are
    declared. ``known_as``, ``motivations`` and ``objectives`` are requested
    too, but the existing connector handles several shapes for them, so they
    are left undeclared: ``extra="allow"`` keeps them verbatim.
    """

    model_config = _API_MODEL_CONFIG

    id: int
    name: str

    slug: str | None = None
    url: str | None = None
    description: str | None = None
    short_description: str | None = None
    actor_type: str | None = None
    first_activity_date: AwareDatetime | None = None
    last_activity_date: AwareDatetime | None = None


class EnrichedCrowdStrikeIndicator(CrowdStrikeIndicator):
    """An indicator with the actors its ``actors`` names resolve to.

    ``actor_objects_list`` is the only field that does not come from the
    indicator API. It is empty when the indicator names no actor or none
    resolves, and when it was never filled (a raw API row).
    """

    actor_objects_list: list[CrowdStrikeActor] = Field(default_factory=list)
