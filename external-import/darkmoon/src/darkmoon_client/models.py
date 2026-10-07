"""Typed models for the Darkmoon OSS findings store (raw, on-disk JSON).

These models describe the JSON that the Darkmoon OSS engine writes to its data
directory during a campaign. They mirror, field for field, the records produced
by the engine:

    - ``DarkmoonFinding`` / ``DarkmoonEvidence`` -> one object of the
      ``vulnerabilities/<campaign_id>.json`` array (written by the engine's
      ``push_finding`` tool).
    - ``DarkmoonCampaign`` -> ``campaigns/<campaign_id>.json``.
    - ``DarkmoonTarget`` -> one object of the ``targets.json`` array.

They describe *raw* data, not STIX objects. STIX conversion happens separately
in ``connector/data_processors/findings_processor.py``. Only the fields the
connector actually uses are declared; any extra field in the JSON is ignored.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


class DarkmoonEvidence(BaseModel):
    """Evidence block attached to a finding (``finding.evidence``)."""

    model_config = ConfigDict(extra="ignore")

    commands: list[str] = []
    payloads: list[str] = []
    raw_request: str | None = None
    raw_response: str | None = None
    logs: list[str] = []
    explanation: str | None = None


class DarkmoonFinding(BaseModel):
    """A single Darkmoon finding (one entry of a vulnerabilities file)."""

    model_config = ConfigDict(extra="ignore")

    id: str | None = None
    campaign_id: str | None = None
    project_id: str | None = None
    target_id: str | None = None
    node_id: str | None = None
    title: str
    severity: str = "info"
    status: str = "unconfirmed"
    category: str | None = None
    description: str | None = None
    endpoint: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve: str | None = None
    mitre_attack_id: str | None = None
    mitre_attack_name: str | None = None
    iso27001_control: str | None = None
    plugin_or_component: str | None = None
    remediation: str | None = None
    discovered_by_agent: str | None = None
    discovered_at: str | None = None
    evidence: DarkmoonEvidence = DarkmoonEvidence()

    @field_validator("cvss_score", mode="before")
    @classmethod
    def _coerce_cvss_score(cls, value: Any) -> float | None:
        """Darkmoon may store a non-numeric cvss_score (e.g. '9.8 (High)', 'N/A').

        Parse the leading number if present, otherwise return None, mirroring
        the defensive parsing the Darkmoon report generator applies.
        """
        if value is None or isinstance(value, (int, float)):
            return float(value) if value is not None else None
        import re

        match = re.search(r"\d+(?:\.\d+)?", str(value))
        return float(match.group()) if match else None


class DarkmoonCampaign(BaseModel):
    """A Darkmoon campaign record (``campaigns/<campaign_id>.json``)."""

    model_config = ConfigDict(extra="ignore")

    id: str
    project_id: str | None = None
    target_id: str | None = None
    session_id: str | None = None
    date: str | None = None
    duration_seconds: int | None = None
    status: str | None = None
    methodology: str | None = None
    overall_risk: str | None = None
    stats: dict[str, Any] = {}
    executive_summary: str | None = None
    report_path: str | None = None


class DarkmoonTarget(BaseModel):
    """A Darkmoon target record (one entry of ``targets.json``)."""

    model_config = ConfigDict(extra="ignore")

    id: str
    host: str | None = None
    ip: str | None = None
    os: str | None = None


class CampaignBundle(BaseModel):
    """A campaign together with its findings and (optional) resolved target.

    This is the unit returned by ``DarkmoonClient.collect`` and consumed by the
    processor: one bundle becomes one OpenCTI Report grouping the campaign's
    vulnerabilities and evidence notes.
    """

    model_config = ConfigDict(extra="ignore")

    campaign: DarkmoonCampaign
    findings: list[DarkmoonFinding] = []
    target: DarkmoonTarget | None = None
