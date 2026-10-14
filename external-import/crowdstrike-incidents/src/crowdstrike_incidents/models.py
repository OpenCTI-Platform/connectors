"""Pydantic models of the CrowdStrike Alerts API payloads.

Only the fields used by the connector are modelled; every other field of the
alert is ignored. Reference: POST /alerts/combined/alerts/v1
(falconpy ``Alerts.get_alerts_combined``).
"""

from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


def _clean_string(value: Any) -> Any:
    """Strip strings and turn blank ones into ``None``."""
    if isinstance(value, str):
        return value.strip() or None
    return value


def _clean_string_list(value: Any) -> Any:
    """Coalesce ``null`` to ``[]`` and drop blank or ``null`` items."""
    if value is None:
        return []
    if not isinstance(value, list):
        return value
    cleaned = (_clean_string(item) for item in value)
    return [item for item in cleaned if item is not None]


class AlertUser(_Model):
    """A user account involved in the alert (``users[]``)."""

    user_name: str | None = None
    sid: str | None = None

    @field_validator("user_name", "sid", mode="before")
    @classmethod
    def _clean(cls, value: Any) -> Any:
        return _clean_string(value)


class MitreAttack(_Model):
    """A MITRE ATT&CK technique attached to the alert (``mitre_attack[]``)."""

    tactic_id: str | None = None
    tactic: str | None = None
    technique_id: str | None = None
    technique: str | None = None

    @field_validator("tactic_id", "tactic", "technique_id", "technique", mode="before")
    @classmethod
    def _clean(cls, value: Any) -> Any:
        return _clean_string(value)


class CrowdstrikeAlert(_Model):
    """A CrowdStrike Falcon alert, as returned by /alerts/combined/alerts/v1."""

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
    priority_value: int | float | None = None
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
        "priority_explanation",
        mode="before",
    )
    @classmethod
    def _clean_list(cls, value: Any) -> Any:
        return _clean_string_list(value)

    @field_validator("users", "mitre_attack", mode="before")
    @classmethod
    def _coalesce_null_list(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, list):
            return [item for item in value if item is not None]
        return value

    @field_validator(
        "name", "display_name", "description", "falcon_host_link", mode="before"
    )
    @classmethod
    def _clean(cls, value: Any) -> Any:
        return _clean_string(value)

    @field_validator("event_ids", mode="before")
    @classmethod
    def _event_ids_as_list(cls, value: Any) -> Any:
        """The API returns ``event_ids`` as a single string on NG-SIEM alerts."""
        if isinstance(value, str):
            value = [value]
        return _clean_string_list(value)


class SourceEvent(_Model):
    """The NG-SIEM ``ngsiem-rule-match-event`` behind an alert.

    Retrieved from the LogScale search API (view ``search-all``). It carries the
    threat side of the detection, absent from the alert payload: the executed
    file, its hashes and its execution context. Field names are the flattened
    LogScale field names.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    indicator_id: str = Field(alias="Ngsiem.indicator.id", min_length=1)
    file_name: str | None = Field(default=None, alias="Vendor.FileName")
    file_path: str | None = Field(default=None, alias="Vendor.FilePath")
    executable: str | None = Field(default=None, alias="process.executable")
    command_line: str | None = Field(default=None, alias="process.command_line")
    sha256: str | None = Field(default=None, alias="process.hash.sha256")
    md5: str | None = Field(default=None, alias="process.hash.md5")
    sha1: str | None = Field(default=None, alias="process.hash.sha1")
    parent_name: str | None = Field(default=None, alias="process.parent.name")
    grandparent_name: str | None = Field(
        default=None, alias="Vendor.GrandParentBaseFileName"
    )
    agent_public_ip: str | None = Field(default=None, alias="Vendor.aip")

    @field_validator(
        "file_name",
        "file_path",
        "executable",
        "command_line",
        "sha256",
        "md5",
        "sha1",
        "parent_name",
        "grandparent_name",
        "agent_public_ip",
        mode="before",
    )
    @classmethod
    def _clean(cls, value: Any) -> Any:
        return _clean_string(value)
