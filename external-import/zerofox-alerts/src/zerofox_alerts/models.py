"""Pydantic models for ZeroFox Alerts API responses."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

_SEVERITY_MAP: dict[int, str] = {1: "low", 2: "medium", 3: "high", 4: "critical"}


class ZerofoxEntity(BaseModel):
    """Monitored entity / asset (victim)."""

    model_config = ConfigDict(extra="allow")

    id: int | None = None
    name: str | None = None


class ZerofoxPerpetrator(BaseModel):
    """Perpetrator (malicious actor)."""

    model_config = ConfigDict(extra="allow")

    name: str | None = None
    display_name: str | None = None
    url: str | None = None
    timestamp: str | None = None


class ZerofoxMetadata(BaseModel):
    """Parsed metadata object (originally a stringified JSON in the API response)."""

    model_config = ConfigDict(extra="allow")

    justification: str | None = None
    alert_reasons: list[dict[str, Any]] = Field(default_factory=list)
    occurrences: list[dict[str, Any]] = Field(default_factory=list)
    content_raw_data: dict[str, Any] = Field(default_factory=dict)


class ZerofoxLog(BaseModel):
    """Log entry for an alert."""

    model_config = ConfigDict(extra="allow")

    action: str | None = None
    timestamp: str | None = None


class ZerofoxAlert(BaseModel):
    """Model for a single ZeroFox alert from the /alerts/ endpoint."""

    model_config = ConfigDict(extra="allow")

    id: int
    alert_type: str | None = None
    status: str | None = None
    severity: int | None = None
    timestamp: str | None = None
    content_created_at: str | None = None
    last_modified: str | None = None
    rule_name: str | None = None
    network: str | None = None
    notes: str | None = None
    escalated: bool = False
    tags: list[str] = Field(default_factory=list)
    offending_content_url: str | None = None
    darkweb_term: str | None = None
    entity: ZerofoxEntity | None = None
    asset: ZerofoxEntity | None = None
    perpetrator: ZerofoxPerpetrator | None = None
    metadata: ZerofoxMetadata | None = None
    logs: list[ZerofoxLog] = Field(default_factory=list)

    @field_validator("metadata", mode="before")
    @classmethod
    def parse_metadata(cls, v: Any) -> Any:
        """Parse metadata field which may be a stringified JSON."""
        if isinstance(v, str):
            try:
                return json.loads(v)
            except (json.JSONDecodeError, TypeError):
                return None
        return v

    @property
    def victim_entity(self) -> ZerofoxEntity | None:
        """Return the entity or asset field as the victim."""
        return self.entity or self.asset

    @property
    def effective_severity(self) -> str:
        """Map numeric severity to string, force critical if escalated."""
        if self.escalated:
            return "critical"
        return _SEVERITY_MAP.get(self.severity or 1, "low")

    @property
    def external_url(self) -> str:
        """Reconstruct the ZeroFox alert URL."""
        return f"https://cloud.zerofox.com/alerts/{self.id}"

    @property
    def description(self) -> str:
        """Build a rich description from notes + metadata."""
        parts = []
        if self.notes:
            parts.append(self.notes)

        if self.metadata:
            # Add alert reasons
            for reason in self.metadata.alert_reasons:
                value = reason.get("value", {})
                if isinstance(value, dict):
                    text_content = value.get("text_content")
                    if text_content:
                        parts.append(f"**Alert reason:** {text_content}")

            # Add raw data details
            details = self.metadata.content_raw_data.get("details")
            if details:
                parts.append(f"**Details:** {details}")

        return "\n\n".join(parts) if parts else ""

    @property
    def observable_domains(self) -> list[str]:
        """Extract domain names from metadata occurrences."""
        domains = []
        if self.metadata:
            for occurrence in self.metadata.occurrences:
                term = occurrence.get("term")
                if term:
                    domains.append(term)
        return domains
