from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class TaskResponse(BaseModel):
    sys_id: str = Field(description="")
    number: str = Field(description="")
    short_description: str = Field(description="")
    description: Optional[str] = Field(default=None)
    sys_created_on: Optional[datetime] = Field(default=None)
    sys_updated_on: Optional[datetime] = Field(default=None)
    due_date: Optional[datetime] = Field(default=None)
    sys_tags: Optional[list[str]] = Field(default=None)
    security_tags: Optional[list[str]] = Field(default=None)
    comments_and_work_notes: Optional[str] = Field(default=None)

    @field_validator("sys_tags", "security_tags", mode="before")
    def parse_list(cls, value):
        if isinstance(value, str):
            return [x.strip() for x in value.split(",") if x.strip()]
        return value

    @field_validator("sys_created_on", "sys_updated_on", "due_date", mode="before")
    def parse_datetime(cls, value):
        if isinstance(value, str) and not value.strip():
            return None
        return value


class SecurityIncidentResponse(BaseModel):
    sys_id: str = Field(description="")
    number: str = Field(description="")
    short_description: str = Field(description="")
    description: Optional[str] = Field(default=None)
    state: Optional[str] = Field(default=None)
    priority: Optional[str] = Field(default=None)
    severity: Optional[str] = Field(default=None)
    category: Optional[str] = Field(default=None)
    subcategory: Optional[str] = Field(default=None)
    comments_and_work_notes: Optional[str] = Field(default=None)
    estimated_end: Optional[datetime] = Field(default=None)
    sys_created_on: Optional[datetime] = Field(default=None)
    sys_updated_on: Optional[datetime] = Field(default=None)
    mitre_technique: Optional[list[str]] = Field(default=None)
    mitre_tactic: Optional[list[str]] = Field(default=None)
    mitre_group: Optional[list[str]] = Field(default=None)
    mitre_malware: Optional[list[str]] = Field(default=None)
    mitre_tool: Optional[list[str]] = Field(default=None)

    @field_validator(
        "mitre_technique",
        "mitre_tactic",
        "mitre_group",
        "mitre_malware",
        "mitre_tool",
        mode="before",
    )
    def parse_list(cls, value):
        if isinstance(value, str):
            return [x.strip() for x in value.split(",") if x.strip()]
        return value

    @field_validator("estimated_end", "sys_created_on", "sys_updated_on", mode="before")
    def parse_datetime(cls, value):
        if isinstance(value, str) and not value.strip():
            return None
        return value
