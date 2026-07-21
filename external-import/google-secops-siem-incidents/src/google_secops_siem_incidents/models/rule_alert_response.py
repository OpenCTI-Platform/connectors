"""Pydantic v2 models for Legacy Search Rules Alerts response."""

from pydantic import BaseModel, ConfigDict, Field


class StringSeq(BaseModel):
    """Sequence of string values returned in an alert outcome."""

    model_config = ConfigDict(populate_by_name=True)

    string_vals: list[str] = Field(default_factory=list, alias="stringVals")


class Outcome(BaseModel):
    """A named outcome produced by a detection rule."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    int64_val: str | None = Field(None, alias="int64Val")
    string_val: str | None = Field(None, alias="stringVal")
    string_seq: StringSeq | None = Field(None, alias="stringSeq")
    field_path: str | None = Field(None, alias="fieldPath")


class AlertField(BaseModel):
    """A key-value field attached to an alert (e.g. hostname, IP)."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    field_path: str | None = Field(None, alias="fieldPath")
    string_val: str | None = Field(None, alias="stringVal")


class TimeWindow(BaseModel):
    """Start/end time range for an alert or query."""

    model_config = ConfigDict(populate_by_name=True)

    start_time: str = Field(alias="startTime")
    end_time: str = Field(alias="endTime")


class Alert(BaseModel):
    """A single detection alert raised by a rule."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    fields: list[AlertField] = Field(default_factory=list)
    time_window: TimeWindow = Field(alias="timeWindow")
    rule_type: str = Field(alias="ruleType")
    detection_timestamp: str = Field(alias="detectionTimestamp")
    commit_timestamp: str = Field(alias="commitTimestamp")
    alerting_type: str = Field(alias="alertingType")
    outcomes: list[Outcome] = Field(default_factory=list)
    result_events: dict = Field(default_factory=dict, alias="resultEvents")
    result_entity_events: dict = Field(default_factory=dict, alias="resultEntityEvents")


class RuleProperties(BaseModel):
    """Static properties of a detection rule."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    text: str
    metadata: dict = Field(default_factory=dict)


class RuleMetadata(BaseModel):
    """Metadata envelope for a detection rule (ID + properties)."""

    model_config = ConfigDict(populate_by_name=True)

    rule_id: str = Field(alias="ruleId")
    properties: RuleProperties


class RuleAlert(BaseModel):
    """A rule and its associated alerts in the Legacy Search response."""

    model_config = ConfigDict(populate_by_name=True)

    rule_metadata: RuleMetadata = Field(alias="ruleMetadata")
    alerts: list[Alert] = Field(default_factory=list)


class RuleAlertResponse(BaseModel):
    """Top-level response from the Legacy Search Rules Alerts endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    rule_alerts: list[RuleAlert] = Field(default_factory=list, alias="ruleAlerts")
    too_many_alerts: bool = Field(False, alias="tooManyAlerts")
