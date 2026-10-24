"""Pydantic models of the Rösti API v2 responses (only the fields the connector uses).

See the OpenAPI spec of the Rösti API v2 (https://registry.scalar.com/@bin/apis/rosti-api@latest).
Unknown fields are ignored so that API additions never break the connector.
"""

import datetime as dt
from collections.abc import Iterable, Iterator
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

# All IOC types returned by `GET /ioc-types`.
IOC_TYPES = [
    "domain",
    "ip",
    "url",
    "sha256",
    "domain:ip",
    "filename",
    "md5",
    "sha1",
    "email",
    "filepath",
    "ip:port",
    "mutex",
    "domain:port",
    "cidr",
    "sha224",
    "sha512",
    "ssdeep",
    "user-agent",
    "port",
    "blockchain",
]


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Risk(_Model):
    """False-positive risk of an IOC (-1 = informational, 0 = nothing found ... 5 = very high)."""

    level: int
    meaning: str | None = None
    msg: str | None = None


class IOC(_Model):
    id: str
    type: str
    value: str
    category: str | None = None
    date: dt.date
    ids: bool = False
    report: str
    comment: str | None = None
    tags: list[str] | None = None
    risk: Risk | None = None
    timestamp: dt.datetime | None = None
    # IOCs with the same entity_ref describe the same thing (e.g. the MD5,
    # SHA-1 and SHA-256 of one file). None = the IOC stands alone.
    entity_ref: str | None = None


class Mitre(_Model):
    id: str
    description: str
    object_type: str


class CVE(_Model):
    id: str
    description: str | None = None
    timestamp: dt.datetime | None = None


class Yara(_Model):
    id: str
    name: str
    filename: str | None = None
    rule: str
    tags: list[str] | None = None
    hash: str | None = None


class ReportNote(_Model):
    action: str | None = None
    comment: str | None = None


class Source(_Model):
    id: str
    name: str
    url: str | None = None


class Count(_Model):
    iocs: int = 0
    yara_rules: int = 0
    mitre_ids: int = 0


class Report(_Model):
    id: str
    title: str
    date: dt.date
    url: str
    authors: list[str] | None = None
    tags: list[str] | None = None
    count: Count = Field(default_factory=Count)
    source: Source | None = None
    last_updated: dt.datetime | None = None
    mitre_ids: list[Mitre] | None = None
    cve: list[CVE] | None = None
    notes: list[ReportNote] | None = None

    @property
    def hide_yara(self) -> bool:
        """True if a note asks to hide this report's YARA rules."""
        return any(note.action == "hide_yara" for note in self.notes or [])


def group_iocs(iocs: Iterable[IOC]) -> Iterator[list[IOC]]:
    """Group consecutive IOCs that share an ``entity_ref``.

    The API returns the IOCs of a group next to each other. A group is only
    yielded once the next IOC (or the end of ``iocs``) shows that it is
    complete, so when ``iocs`` is fed page by page, the group at the end of a
    page is held back until the next page has been loaded. IOCs without an
    ``entity_ref`` are yielded as groups of one.
    """
    pending: list[IOC] = []
    for ioc in iocs:
        if pending and ioc.entity_ref and ioc.entity_ref == pending[0].entity_ref:
            pending.append(ioc)
            continue
        if pending:
            yield pending
        pending = [ioc]
    if pending:
        yield pending


class ReportBundle(_Model):
    """A report together with all the data the connector fetched for it."""

    report: Report
    # `last_updated` of the report in the list response, used as checkpoint.
    listed_last_updated: dt.datetime | None = None
    # IOCs grouped by entity_ref (see group_iocs); ungrouped IOCs are groups of one.
    ioc_groups: list[list[IOC]] = Field(default_factory=list)
    yara_rules: list[Yara] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _accept_flat_iocs(cls, data: Any) -> Any:
        """Allow ``ReportBundle(iocs=[...])``: the IOCs are grouped here."""
        if isinstance(data, dict) and "iocs" in data:
            data = dict(data)
            iocs = [
                ioc if isinstance(ioc, IOC) else IOC.model_validate(ioc)
                for ioc in data.pop("iocs") or []
            ]
            data["ioc_groups"] = list(group_iocs(iocs))
        return data

    @property
    def iocs(self) -> list[IOC]:
        """All IOCs in API order."""
        return [ioc for group in self.ioc_groups for ioc in group]
