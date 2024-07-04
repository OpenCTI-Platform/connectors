# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike YARA parser module."""

import logging
import re
from datetime import date
from io import StringIO
from typing import List, Optional

from pydantic import BaseModel

from . import convert_comma_separated_str_to_list

logger = logging.getLogger(__name__)


class YaraRule(BaseModel):
    """YARA rule model."""

    name: str
    description: str
    last_modified: date
    reports: List[str]
    actors: List[str]
    malware_families: List[str]
    rule: str


class YaraParser:
    """YARA rules parser."""

    _IMPORT_STARTS = "import "

    _RULE_STARTS = ("rule ", "rule  ", "rule\t", "private rule ", "global rule ")
    _RULE_ENDS = ("}",)

    _NAME_PATTERN = r"^rule\s+(\w+)(?:\s*\:.*)?$"
    _NAME_REGEX = re.compile(_NAME_PATTERN, re.MULTILINE)

    _DESCRIPTION_PATTERN = r"^\s*description\s*=\s*\"(.*)\"$"
    _DESCRIPTION_REGEX = re.compile(_DESCRIPTION_PATTERN, re.MULTILINE)

    _LAST_MODIFIED_PATTERN = r"^\s*last_modified\s*=\s*\"(.*)\"$"
    _LAST_MODIFIED_REGEX = re.compile(_LAST_MODIFIED_PATTERN, re.MULTILINE)

    _REPORTS_PATTERN = r"^\s*reports\s*=\s*\"(.*)\"$"
    _REPORTS_REGEX = re.compile(_REPORTS_PATTERN, re.MULTILINE)

    _ACTOR_PATTERN = r"^\s*actor\s*=\s*\"(.*)\"$"
    _ACTOR_REGEX = re.compile(_ACTOR_PATTERN, re.MULTILINE)

    _MALWARE_FAMILY_PATTERN = r"^\s*malware_family\s*=\s*\"(.*)\"$"
    _MALWARE_FAMILY_REGEX = re.compile(_MALWARE_FAMILY_PATTERN, re.MULTILINE)

    @classmethod
    def parse(cls, yara_rules: str) -> List[YaraRule]:
        """Parse YARA rules string to list of YARA rule model."""
        if not yara_rules:
            logger.error("Not YARA rules to parse, empty string")
            return []

        yara_rules_list = cls._split_yara_rules(yara_rules)
        if not yara_rules_list:
            logger.error("No YARA rules in the given string: %s", yara_rules)
            return []

        logger.info("Found %d YARA rules in the given string", len(yara_rules_list))

        return cls._parse_yara_rules_list(yara_rules_list)

    @classmethod
    def _split_yara_rules(cls, yara_rules_str: str) -> List[str]:
        rule_buffer = None

        result = []
        for line in StringIO(yara_rules_str).readlines():
            if rule_buffer is None and (
                line.startswith(cls._RULE_STARTS) or line.startswith(cls._IMPORT_STARTS)
            ):
                rule_buffer = StringIO()

            if rule_buffer is not None:
                rule_buffer.write(line)

            if rule_buffer is not None and line.startswith(cls._RULE_ENDS):
                rule = rule_buffer.getvalue()
                result.append(rule)

                rule_buffer.close()
                rule_buffer = None

        return result

    @classmethod
    def _parse_yara_rules_list(cls, yara_rule_list: List[str]) -> List[YaraRule]:
        result = []
        for yara_rule in yara_rule_list:
            rule = cls._parse_yara_rule(yara_rule)
            if rule is None:
                continue

            result.append(rule)
        return result

    @classmethod
    def _parse_yara_rule(cls, yara_rule: str) -> Optional[YaraRule]:
        name = cls._get_name(yara_rule)
        if name is None:
            logger.error("No name for rule: %s", yara_rule)
            return None

        description = cls._get_description(yara_rule)
        if description is None:
            logger.error("No description for rule: %s", yara_rule)
            return None

        last_modified = cls._get_last_modified(yara_rule)
        if last_modified is None:
            logger.error("No last modified for rule: %s", yara_rule)
            return None

        reports = cls._get_reports(yara_rule)

        actors = cls._get_actors(yara_rule)

        malware_families = cls._get_malware_families(yara_rule)

        rule = YaraRule(
            name=name,
            description=description,
            last_modified=last_modified,
            reports=reports,
            actors=actors,
            malware_families=malware_families,
            rule=yara_rule,
        )
        return rule

    @classmethod
    def _get_name(cls, yara_rule: str) -> Optional[str]:
        return cls._match_regex(cls._NAME_REGEX, yara_rule)

    @classmethod
    def _get_description(cls, yara_rule: str) -> Optional[str]:
        return cls._match_regex(cls._DESCRIPTION_REGEX, yara_rule)

    @classmethod
    def _get_last_modified(cls, yara_rule: str) -> Optional[str]:
        return cls._match_regex(cls._LAST_MODIFIED_REGEX, yara_rule)

    @classmethod
    def _get_reports(cls, yara_rule: str) -> List[str]:
        reports_str = cls._match_regex(cls._REPORTS_REGEX, yara_rule)
        return cls._comma_string_to_list(reports_str)

    @classmethod
    def _get_actors(cls, yara_rule: str) -> List[str]:
        actor_str = cls._match_regex(cls._ACTOR_REGEX, yara_rule)
        return cls._comma_string_to_list(actor_str)

    @classmethod
    def _get_malware_families(cls, yara_rule: str) -> List[str]:
        malware_family_str = cls._match_regex(cls._MALWARE_FAMILY_REGEX, yara_rule)
        return cls._comma_string_to_list(malware_family_str)

    @staticmethod
    def _match_regex(regex: re.Pattern, string) -> Optional[str]:
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
