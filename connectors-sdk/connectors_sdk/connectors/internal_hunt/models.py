"""Typed models of the internal hunt protocol.

The models mirror the cross-repository hunt contract:

- ``HuntRequest`` is the ``event`` part of the message OpenCTI pushes to the
  queue of an ``INTERNAL_HUNT`` connector (one hunt run).
- ``NativeQuery``, ``HuntEvent`` and ``HuntResult`` describe the translated query
  and the results a connector returns from its telemetry platform.
- ``HuntEvidence`` and ``HuntRunReport`` describe what the connector reports back
  to OpenCTI with ``report_hunt_run``.

Request models ignore unknown fields so that a newer platform can extend the
message without breaking older connectors.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class HuntRunMode(StrEnum):
    """Execution mode of a hunt run."""

    EXECUTE = "execute"
    PREVIEW = "preview"


class HuntRunStatus(StrEnum):
    """Status of a hunt run (connectors report running, completed, failed and timeout)."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class _HuntRequestModel(BaseModel):
    """Base class of the read-only models parsed from the dispatch message."""

    model_config = ConfigDict(extra="ignore", frozen=True)


class HuntNativeQuery(_HuntRequestModel):
    """Native query override of a hunt for one platform."""

    platform: str = Field(description="Hunt platform slug the query is written for.")
    language: str = Field(description="Query language of the native query.")
    query: str = Field(
        default="",
        description="Native query, executed verbatim. Empty to translate the Sigma rule with `pipeline`.",
    )
    pipeline: str | None = Field(
        default=None,
        description="Name of the pySigma processing pipeline to translate the Sigma rule with.",
    )


class HuntTechnique(_HuntRequestModel):
    """Attack pattern covered by a hunt."""

    standard_id: str = Field(description="STIX id of the attack pattern.")
    name: str | None = Field(default=None, description="Name of the attack pattern.")
    x_mitre_id: str | None = Field(default=None, description="MITRE ATT&CK identifier.")


class HuntTarget(_HuntRequestModel):
    """Threat targeted by a hunt (intrusion set, malware, campaign, threat actor)."""

    standard_id: str = Field(description="STIX id of the threat.")
    entity_type: str | None = Field(default=None, description="OpenCTI entity type.")
    name: str | None = Field(default=None, description="Name of the threat.")


class HuntIndicator(_HuntRequestModel):
    """Indicator a hunt is based on."""

    standard_id: str = Field(description="STIX id of the indicator.")
    name: str | None = Field(default=None, description="Name of the indicator.")
    pattern_type: str | None = Field(default=None, description="Pattern type.")
    pattern: str | None = Field(default=None, description="Indicator pattern.")


class HuntIocSource(_HuntRequestModel):
    """Indicator or observable a value of an indicator hunt comes from."""

    standard_id: str = Field(description="STIX id of the indicator or observable.")
    entity_type: str | None = Field(default=None, description="OpenCTI entity type.")
    name: str | None = Field(default=None, description="Name or value.")


class HuntIoc(_HuntRequestModel):
    """One value an indicator hunt looks up on the platform."""

    key: str = Field(description="Key of the value, echoed in the run report.")
    observable_type: str = Field(
        description="OpenCTI observable type (IPv4-Addr, Domain-Name, StixFile...)."
    )
    hash_algorithm: str | None = Field(
        default=None, description="Hash algorithm of a StixFile value (MD5, SHA-1...)."
    )
    value: str = Field(min_length=1, description="Normalized value to look up.")
    sources: list[HuntIocSource] = Field(
        default_factory=list,
        description="Indicators and observables of the value, none for a pasted value.",
    )

    @field_validator("sources", mode="before")
    @classmethod
    def _none_to_empty_list(cls, value: Any) -> Any:
        """Turn a null list sent by the platform into an empty list."""
        return [] if value is None else value


class HuntDefinition(_HuntRequestModel):
    """Hunt to execute, as sent in the dispatch message."""

    id: str = Field(description="OpenCTI internal id of the hunt.")
    standard_id: str = Field(description="STIX id of the hunt.")
    name: str = Field(description="Name of the hunt.")
    hypothesis: str | None = Field(default=None, description="Hunt hypothesis.")
    hunt_type: Literal["telemetry", "indicators", "infrastructure"] = Field(
        default="telemetry", description="Kind of hunt."
    )
    sigma_rule: str | None = Field(
        default=None, description="Canonical Sigma rule (YAML) of the hunt."
    )
    native_query: HuntNativeQuery | None = Field(
        default=None,
        description="Native query of the hunt for the connector platform, if any.",
    )
    expected_observables: list[str] = Field(
        default_factory=list,
        description="Observable types the hunt expects in its results.",
    )
    benign_patterns: list[str] = Field(
        default_factory=list,
        description="Known benign values; matching result events are suppressed.",
    )
    escalation_threshold: int | None = Field(
        default=None, description="Number of hits from which OpenCTI escalates."
    )
    object_marking_refs: list[str] = Field(
        default_factory=list, description="Marking definitions of the hunt."
    )
    created_by_ref: str | None = Field(
        default=None, description="STIX id of the hunt author."
    )
    techniques: list[HuntTechnique] = Field(
        default_factory=list, description="Attack patterns covered by the hunt."
    )
    targets: list[HuntTarget] = Field(
        default_factory=list, description="Threats targeted by the hunt."
    )
    indicators: list[HuntIndicator] = Field(
        default_factory=list, description="Indicators the hunt is based on."
    )
    iocs: list[HuntIoc] = Field(
        default_factory=list,
        description="Indicator hunts: the values to look up on the platform.",
    )

    @field_validator(
        "expected_observables",
        "benign_patterns",
        "object_marking_refs",
        "techniques",
        "targets",
        "indicators",
        "iocs",
        mode="before",
    )
    @classmethod
    def _none_to_empty_list(cls, value: Any) -> Any:
        """Turn a null list sent by the platform into an empty list."""
        return [] if value is None else value


class HuntRunInfo(_HuntRequestModel):
    """Identity of the hunt run being executed."""

    id: str = Field(description="OpenCTI internal id of the hunt run.")
    attempt: int = Field(default=1, ge=1, description="Attempt number of the run.")
    trigger: str | None = Field(default=None, description="What triggered the run.")


class HuntTimeWindow(_HuntRequestModel):
    """Time window the hunt is executed over."""

    start: AwareDatetime = Field(description="Start of the window (inclusive).")
    end: AwareDatetime = Field(description="End of the window (inclusive).")

    @model_validator(mode="after")
    def _validate_order(self) -> HuntTimeWindow:
        """Reject a window ending before it starts."""
        if self.end < self.start:
            raise ValueError("The time window must end after it starts.")
        return self


class HuntLimits(_HuntRequestModel):
    """Execution limits of a hunt run."""

    max_results: int = Field(
        default=1000, ge=1, description="Maximum number of result events to fetch."
    )
    timeout_seconds: int = Field(
        default=600, ge=1, description="Maximum execution time of the query."
    )
    evidence_max_items: int = Field(
        default=20, ge=0, description="Maximum number of evidence items reported."
    )
    evidence_max_value_length: int = Field(
        default=256, ge=1, description="Maximum length of an evidence preview."
    )
    ioc_batch_size: int = Field(
        default=50,
        ge=1,
        description="Indicator hunts: maximum number of values in one platform lookup.",
    )


class HuntSecurityPlatform(_HuntRequestModel):
    """Security Platform identity the hunt is executed against."""

    id: str = Field(description="OpenCTI internal id of the Security Platform.")
    standard_id: str = Field(description="STIX id of the Security Platform.")
    name: str = Field(description="Name of the Security Platform.")


class HuntRequest(_HuntRequestModel):
    """One hunt run dispatched to an internal hunt connector."""

    event_type: Literal["INTERNAL_HUNT"] = Field(
        default="INTERNAL_HUNT", description="Event type of hunt messages."
    )
    mode: HuntRunMode = Field(
        default=HuntRunMode.EXECUTE,
        description="Execute the hunt, or only translate it (preview).",
    )
    hunt_run: HuntRunInfo = Field(description="Hunt run being executed.")
    hunt: HuntDefinition = Field(description="Hunt to execute.")
    time_window: HuntTimeWindow = Field(description="Time window to hunt over.")
    limits: HuntLimits = Field(
        default_factory=HuntLimits, description="Execution limits."
    )
    security_platform: HuntSecurityPlatform | None = Field(
        default=None,
        description="Security Platform the hunt runs against (null for internet hunts).",
    )

    @field_validator("limits", mode="before")
    @classmethod
    def _default_limits(cls, value: Any) -> Any:
        """Use the default limits when the platform sends null."""
        return HuntLimits() if value is None else value


class HuntConnectionCheck(BaseModel):
    """One check of the connection test of a hunt connector, as OpenCTI shows it."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(
        min_length=1,
        max_length=256,
        description="What is checked: the credentials, or a permission by its platform name.",
    )
    ok: bool = Field(description="Whether the check passed.")
    message: str = Field(
        min_length=1,
        max_length=2048,
        description="What the connector found, in plain words; for a failure, what to grant or fix.",
    )


class NativeQuery(BaseModel):
    """Query a connector executes on its platform."""

    model_config = ConfigDict(frozen=True)

    language: str = Field(description="Query language, e.g. 'spl' or 'kql'.")
    query: str = Field(min_length=1, description="Query text.")
    pipeline: str | None = Field(
        default=None, description="pySigma pipeline used for the translation."
    )
    translated: bool = Field(
        default=False,
        description="True when the query was translated from the Sigma rule.",
    )
    fields: tuple[str, ...] = Field(
        default=(),
        description="Platform field names referenced by the detection logic.",
    )


class HuntEvent(BaseModel):
    """One result event returned by a hunt query."""

    model_config = ConfigDict(frozen=True)

    timestamp: AwareDatetime | None = Field(
        default=None, description="Time of the event."
    )
    fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Event fields, flattened with dotted names.",
    )
    detection: str | None = Field(
        default=None,
        description=(
            "Detection referencing the event, when the platform groups matching "
            "events into detections (a YARA-L rule): the events of one detection "
            "are one hit."
        ),
    )


class HuntResult(BaseModel):
    """Results of a hunt query."""

    model_config = ConfigDict(frozen=True)

    events: list[HuntEvent] = Field(
        default_factory=list, description="Result events (at most `max_results`)."
    )
    total_hits: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Total number of hits, when the platform reports it: matching events, "
            "or detections for events grouped into detections."
        ),
    )
    truncated: bool = Field(
        default=False,
        description=(
            "True when the platform did not return every matching event: more "
            "matches than returned, shard or source failures, partial answers or "
            "an exhausted result budget. The hit count is then a lower bound."
        ),
    )

    @property
    def hits_count(self) -> int:
        """Return the number of hits of the run.

        A hit is a returned event, or a detection for the events a detection
        groups: the events one detection references count once.
        """
        detections = {event.detection for event in self.events if event.detection}
        returned = len(detections) + sum(1 for e in self.events if not e.detection)
        if self.total_hits is None:
            return returned
        return max(self.total_hits, returned)


class HuntEvidence(BaseModel):
    """Redacted evidence sample of a hunt run."""

    model_config = ConfigDict(frozen=True)

    field: str = Field(description="Result field name.")
    value_hash: str = Field(description="SHA-256 hex digest of the full raw value.")
    value_preview: str | None = Field(
        default=None, description="Value truncated to the evidence length limit."
    )
    count: int = Field(ge=0, description="Occurrences of the value in the results.")


class HuntIocResult(BaseModel):
    """What the platform reported for one value of an indicator hunt run."""

    model_config = ConfigDict(frozen=True)

    key: str = Field(description="Key of the value in the run message.")
    searched: bool = Field(
        default=True,
        description="False when the platform cannot look this type of value up.",
    )
    seen: bool = Field(default=False, description="The value was found.")
    hits_count: int = Field(default=0, ge=0, description="Events holding the value.")
    first_seen: AwareDatetime | None = Field(
        default=None, description="Time of the first event holding the value."
    )
    last_seen: AwareDatetime | None = Field(
        default=None, description="Time of the last event holding the value."
    )
    hosts: list[str] = Field(
        default_factory=list, description="Hosts the value was seen on."
    )
    reason: str | None = Field(default=None, description="Why it was not searched.")


class HuntRunReport(BaseModel):
    """Outcome of a hunt run reported to OpenCTI."""

    model_config = ConfigDict(frozen=True)

    status: Literal[
        HuntRunStatus.COMPLETED, HuntRunStatus.FAILED, HuntRunStatus.TIMEOUT
    ] = Field(
        description="Final status of the run, timeout when it exceeded its deadline."
    )
    translated_query: str | None = Field(
        default=None, description="Query executed on the platform."
    )
    query_language: str | None = Field(
        default=None, description="Language of the executed query."
    )
    hits_count: int | None = Field(default=None, ge=0, description="Number of hits.")
    truncated: bool | None = Field(
        default=None,
        description=(
            "Partial results (see HuntResult.truncated): OpenCTI reads the hit count "
            "as a lower bound and never concludes benign from zero hits."
        ),
    )
    distinct_entities: int | None = Field(
        default=None, ge=0, description="Number of distinct entities hit."
    )
    evidence_sample: list[HuntEvidence] | None = Field(
        default=None, description="Redacted evidence sample."
    )
    result_ids: list[str] | None = Field(
        default=None, description="STIX ids of the objects sent to OpenCTI."
    )
    cost_ms: int | None = Field(
        default=None, ge=0, description="Execution time of the run in milliseconds."
    )
    error: str | None = Field(default=None, description="Error of a failed run.")
    ioc_results: list[HuntIocResult] | None = Field(
        default=None, description="Indicator hunts: the result of each value."
    )
