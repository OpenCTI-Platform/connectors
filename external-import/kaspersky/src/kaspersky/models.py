"""Kaspersky models module."""

import logging
from datetime import datetime, timezone
from typing import Any, List, Optional

from pydantic import BaseModel, validator
from pydantic.datetime_parse import parse_date, parse_datetime
from pydantic.errors import DateError, DateTimeError

log = logging.getLogger(__name__)


class Base(BaseModel):
    """Kaspersky base model."""


class Publication(Base):
    """Kaspersky publication model."""

    id: str
    updated: datetime
    published: datetime
    name: str
    desc: str
    report_group: str
    tags: List[str]
    tags_industry: List[str]
    tags_geo: List[str]
    tags_actors: List[str]
    report_pdf: Optional[str] = None
    report_yara: Optional[str] = None
    report_iocs: Optional[str] = None


class OpenIOCIndicatorItem(Base):
    """Kaspersky OpenIOC indicator item model."""

    id: Optional[str]
    condition: Optional[str]
    context_document: Optional[str]
    context_search: Optional[str]
    context_type: Optional[str]
    content_type: Optional[str]
    content_text: Optional[str]


class OpenIOC(Base):
    """Kaspersky OpenIOC model."""

    id: Optional[str]
    description: Optional[str]
    authored_date: Optional[datetime]
    last_modified: Optional[datetime]
    indicator_items: List[OpenIOCIndicatorItem]


class OpenIOCCSVIndicator(Base):
    """Kaspersky OpenIOC CSV indicator model."""

    id: str
    indicator: str
    indicator_type: str
    publication: str
    detection_date: datetime


class OpenIOCCSV(Base):
    """Kaspersky OpenIOC CSV model."""

    indicators: List[OpenIOCCSVIndicator]


class YaraRule(Base):
    """Kaspersky YARA rule model."""

    name: str
    description: str
    report: Optional[str]
    last_modified: Optional[datetime]
    rule: str

    @validator("last_modified", pre=True)
    def parse_last_modified(cls, value: Any) -> Optional[datetime]:
        """Parse last_modified value."""
        if value is None:
            return None

        if not isinstance(value, str):
            raise ValueError("must be a string")

        if value.strip() == "-":
            return None

        try:
            parsed_datetime = parse_datetime(value)
            if parsed_datetime.tzinfo is None:
                parsed_datetime = parsed_datetime.replace(tzinfo=timezone.utc)
            return parsed_datetime
        except DateTimeError:
            # Ignore
            pass

        try:
            date_value = parse_date(value)
            return datetime.combine(
                date_value, datetime.min.time(), tzinfo=timezone.utc
            )
        except DateError:
            log.error("Unable to parse last_modified value: %s", value)
            return None


class Yara(Base):
    """Kaspersky YARA model."""

    rules: List[YaraRule]
