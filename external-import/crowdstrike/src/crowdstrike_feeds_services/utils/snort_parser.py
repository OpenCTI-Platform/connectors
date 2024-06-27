# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike Snort parser module."""

import logging
import re
from datetime import date, datetime
from io import StringIO
from typing import Any, List, Optional

from pydantic import BaseModel

from . import convert_comma_separated_str_to_list

logger = logging.getLogger(__name__)


class SnortRule(BaseModel):
    """Snort rule model."""

    name: str
    description: str
    last_modified: date
    reports: List[str]
    rule: str


class SnortParser:
    """Snort rules parser."""

    _RULE_STARTS: tuple[str] = ("alert",)
    _RULE_ENDS = (";)\n",)

    _NAME_PATTERN = r"msg: \".*\[(CS[A-Z]+-\d+)\]\";"
    _NAME_REGEX = re.compile(_NAME_PATTERN, re.MULTILINE)

    _DESCRIPTION_PATTERN = r"msg: \"(.*\[CS[A-Z]+-\d+\])\";"
    _DESCRIPTION_REGEX = re.compile(_DESCRIPTION_PATTERN, re.MULTILINE)

    _LAST_MODIFIED_PATTERN = r"rev:(\d+);"
    _LAST_MODIFIED_REGEX = re.compile(_LAST_MODIFIED_PATTERN, re.MULTILINE)

    _SID_PATTERN = r"rev:(\d+);"
    _SID_REGEX = re.compile(_SID_PATTERN, re.MULTILINE)

    _REPORTS_PATTERN = _NAME_PATTERN
    _REPORTS_REGEX = re.compile(_REPORTS_PATTERN, re.MULTILINE)

    @classmethod
    def parse(cls, snort_rules: str) -> List[SnortRule]:
        """Parse Snort rules string to list of Snort rule model."""
        if not snort_rules:
            logger.error("Not Snort rules to parse, empty string")
            return []

        snort_rules_list = cls._split_snort_rules(snort_rules)
        if not snort_rules_list:
            logger.error("No Snort rules in the given string: %s", snort_rules)
            return []

        logger.info("Found %d Snort rules in the given string", len(snort_rules_list))

        return cls._parse_snort_rules_list(snort_rules_list)

    @classmethod
    def _split_snort_rules(cls, snort_rules_str: str) -> List[str]:
        rule_buffer = None

        result: List[str] = []
        for line in StringIO(snort_rules_str).readlines():
            if rule_buffer is None and line.startswith(cls._RULE_STARTS):
                rule_buffer = StringIO()

            if rule_buffer is not None:
                rule_buffer.write(line)

            if rule_buffer is not None and line.endswith(cls._RULE_ENDS):
                rule = rule_buffer.getvalue()
                result.append(rule)

                rule_buffer.close()
                rule_buffer = None

        return result

    @classmethod
    def _parse_snort_rules_list(cls, snort_rule_list: List[str]) -> List[SnortRule]:
        result: List[SnortRule] = []
        for snort_rule in snort_rule_list:
            rule = cls._parse_snort_rule(snort_rule)
            if rule is None:
                continue

            result.append(rule)
        return result

    @classmethod
    def _parse_snort_rule(cls, snort_rule: str) -> Optional[SnortRule]:
        name = cls._get_name(snort_rule)
        if name is None:
            logger.error("No name for rule: %s", snort_rule)
            return None

        description = cls._get_description(snort_rule)
        if description is None:
            logger.error("No description for rule: %s", snort_rule)
            return None

        last_modified = cls._get_last_modified(snort_rule)
        if last_modified is None:
            logger.error("No last modified for rule: %s", snort_rule)
            return None

        reports = cls._get_reports(snort_rule)

        rule = SnortRule(
            name=name,
            description=description,
            last_modified=last_modified,  # type: ignore
            reports=reports,
            rule=snort_rule,
        )
        return rule

    @classmethod
    def _get_name(cls, snort_rule: str) -> Optional[str]:
        return f"CrowdStrike_{cls._match_regex(cls._NAME_REGEX, snort_rule)}_{cls._get_sid(snort_rule)}"

    @classmethod
    def _get_sid(cls, snort_rule: str) -> Optional[str]:
        return cls._match_regex(cls._SID_REGEX, snort_rule)

    @classmethod
    def _get_description(cls, snort_rule: str) -> Optional[str]:
        return cls._match_regex(cls._DESCRIPTION_REGEX, snort_rule)

    @classmethod
    def _get_last_modified(cls, snort_rule: str) -> Optional[str]:
        if last_modified_str := cls._match_regex(cls._LAST_MODIFIED_REGEX, snort_rule):
            dt = datetime.strptime(last_modified_str, "%Y%m%d")
            return date(dt.year, dt.month, dt.day)
        return None

    @classmethod
    def _get_reports(cls, snort_rule: str) -> List[str]:
        reports_str = cls._match_regex(cls._REPORTS_REGEX, snort_rule)
        return cls._comma_string_to_list(reports_str)

    @staticmethod
    def _match_regex(regex: re.Pattern[Any], string: str) -> Optional[str]:
        match = regex.search(string)
        if match:
            return match.group(1)
        else:
            return None

    @staticmethod
    def _comma_string_to_list(string: Optional[str]) -> List[str]:
        if string is None:
            return []
        return convert_comma_separated_str_to_list(string)
