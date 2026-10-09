"""Pydantic models of the CrowdStrike Alerts API v2 payloads.

Only the fields used by the connector are modelled; every other field of the
alert is ignored. Reference: GET /alerts/queries/alerts/v2 and
POST /alerts/entities/alerts/v2 (falconpy ``Alerts.query_alerts_v2`` and
``Alerts.get_alerts_v2``).
"""

from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class AlertUser(_Model):
    """A user account involved in the alert (``users[]``)."""

    user_name: str | None = None
    sid: str | None = None


class MitreAttack(_Model):
    """A MITRE ATT&CK technique attached to the alert (``mitre_attack[]``)."""

    tactic_id: str | None = None
    tactic: str | None = None
    technique_id: str | None = None
    technique: str | None = None


class CrowdstrikeAlert(_Model):
    """A CrowdStrike Falcon alert, as returned by /alerts/entities/alerts/v2."""

    composite_id: str = Field(min_length=1)
    name: str | None = None
    display_name: str | None = None
    description: str | None = None
    product: str | None = None
    type: str | None = None
    severity_name: str | None = None
    status: str | None = None
    created_timestamp: AwareDatetime
    # Kept as the raw string returned by the API: it is used verbatim as the
    # incremental cursor in FQL filters, nanoseconds included.
    updated_timestamp: str = Field(min_length=1)
    start_time: AwareDatetime | None = None
    end_time: AwareDatetime | None = None
    falcon_host_link: str | None = None
    detection_id: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    priority_value: int | None = None
    priority_explanation: list[str] = Field(default_factory=list)
    host_names: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    user_names: list[str] = Field(default_factory=list)
    users: list[AlertUser] = Field(default_factory=list)
    mitre_attack: list[MitreAttack] = Field(default_factory=list)

    @field_validator(
        "host_names",
        "source_ips",
        "user_names",
        "users",
        "mitre_attack",
        "priority_explanation",
        mode="before",
    )
    @classmethod
    def _coalesce_null_list(cls, value: Any) -> Any:
        return [] if value is None else value

    @field_validator("event_ids", mode="before")
    @classmethod
    def _event_ids_as_list(cls, value: Any) -> Any:
        """The API returns ``event_ids`` as a single string on NG-SIEM alerts."""
        if not value:
            return []
        if isinstance(value, str):
            return [value]
        return value
