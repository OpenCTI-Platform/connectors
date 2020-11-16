"""Kaspersky YARA utilities module."""

import logging
import re
from datetime import datetime
from io import StringIO
from typing import Any, List, Mapping, Optional, Tuple

from pycti import OpenCTIConnectorHelper  # type: ignore

from stix2 import Identity, Indicator, MarkingDefinition  # type: ignore

from kaspersky.models import Yara, YaraRule
from kaspersky.utils.stix2 import create_indicator


log = logging.getLogger(__name__)


_IMPORT_STARTS = "import "

_RULE_STARTS = ("rule ", "rule  ", "rule\t", "private rule ", "global rule ")
_RULE_ENDS = ("}",)

_NAME_PATTERN = r"^(?:(?:private|global)\s*)?rule\s+(\w+)(?:\s*\:)?.*$"
_NAME_REGEX = re.compile(_NAME_PATTERN, re.MULTILINE)

_DESCRIPTION_PATTERN = r"^\s*description\s*=\s*\"(.*)\"\s*$"
_DESCRIPTION_REGEX = re.compile(_DESCRIPTION_PATTERN, re.MULTILINE)

_REPORT_PATTERN = r"^\s*report\s*=\s*\"(.*)\"\s*$"
_REPORT_REGEX = re.compile(_REPORT_PATTERN, re.MULTILINE)

_LAST_MODIFIED_PATTERN = r"^\s*last_modified\s*=\s*\"(.*)\"\s*$"
_LAST_MODIFIED_REGEX = re.compile(_LAST_MODIFIED_PATTERN, re.MULTILINE)


_PATTERN_TYPE_YARA = "yara"


class YaraRuleUpdater:
    """OpenCTI YARA rule updater."""

    _KEY_ID = "id"
    _KEY_INDICATOR_PATTERN = "pattern"

    def __init__(self, helper: OpenCTIConnectorHelper):
        """Initialize YARA rule updater."""
        self.helper = helper

    def try_updating(self, yara_rule: YaraRule) -> Optional[bool]:
        """Try updating YARA rule if it already exists in the OpenCTI."""
        name = yara_rule.name

        existing_rule = self._find_rule_by_name(name)
        if existing_rule is None:
            return None

        return self._update_if_needed(yara_rule, existing_rule)

    def update_existing(self, yara_rules: List[YaraRule]) -> List[YaraRule]:
        """Update YARA rules if they already exists in the OpenCTI."""
        new_yara_rules = []

        updated = 0
        not_updated = 0

        for yara_rule in yara_rules:
            rule_updated = self.try_updating(yara_rule)
            if rule_updated is None:
                new_yara_rules.append(yara_rule)
            else:
                if rule_updated:
                    updated += 1
                else:
                    not_updated += 1

        existing = updated + not_updated

        log.info("Updated %d of %d existing YARA rules", updated, existing)

        return new_yara_rules

    def _find_rule_by_name(self, name: str) -> Optional[Tuple[str, YaraRule]]:
        indicator = self._fetch_indicator_by_name(name)
        if indicator is None:
            return None

        indicator_id = indicator.get(self._KEY_ID)
        if indicator_id is None or not indicator_id:
            self._error("Indicator '{0}' without ID", name)
            return None

        indicator_pattern = indicator.get(self._KEY_INDICATOR_PATTERN)
        if indicator_pattern is None or not indicator_pattern:
            self._error("Indicator '{0}' without pattern", name)
            return None

        yara = convert_yara_rules_to_yara_model(indicator_pattern)
        rules = yara.rules

        if not rules:
            self._error("Indicator '{0}' pattern without YARA rules", name)
            return None

        if len(rules) > 1:
            self._error(
                "Indicator '{0}' pattern contains more than one YARA rules", name
            )
            return None

        return indicator_id, rules[0]

    def _fetch_indicator_by_name(self, name: str) -> Optional[Mapping[str, Any]]:
        custom_attributes = """
            id
            pattern
        """
        filters = [{"key": "name", "values": [name], "operator": "eq"}]

        return self.helper.api.indicator.read(
            filters=filters, customAttributes=custom_attributes
        )

    def _update_if_needed(
        self, new_rule: YaraRule, existing_rule: Tuple[str, YaraRule]
    ) -> bool:
        new_rule_name = new_rule.name
        indicator_id, current_rule = existing_rule
        if self._needs_updating(current_rule, new_rule):
            updated = self._update_indicator_pattern(indicator_id, new_rule.rule)
            if updated:
                self._info("Rule '{0}' ({1}) updated", new_rule_name, indicator_id)
            else:
                self._error("Rule '{0}' ({1}) not updated", new_rule_name, indicator_id)
            return updated
        else:
            self._info("Not updating rule '{0}' ({1})", new_rule_name, indicator_id)
            return False

    def _needs_updating(self, current_rule: YaraRule, new_rule: YaraRule) -> bool:
        if current_rule.name != new_rule.name:
            self._error(
                "Current ({0}) and new ({1}) YARA rules names do no match",
                current_rule.name,
                new_rule.name,
            )
            return False

        self._info(
            "Current rule last modified '{0}', new rule last modified '{1}'",
            current_rule.last_modified,
            new_rule.last_modified,
        )

        if new_rule.last_modified is None or current_rule.last_modified is None:
            return False

        if new_rule.last_modified > current_rule.last_modified:
            return True

        return False

    def _update_indicator_pattern(
        self, indicator_id: str, new_indicator_pattern: str
    ) -> bool:
        updated = self.helper.api.stix_domain_object.update_field(
            id=indicator_id,
            key=self._KEY_INDICATOR_PATTERN,
            value=new_indicator_pattern,
        )

        if updated is None:
            return False

        return updated.get(self._KEY_ID) == indicator_id

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)


def convert_yara_rules_to_map(
    yara_rules_str: str, imports_at_top: bool = False
) -> Mapping[str, Any]:
    """
    Convert YARA rules into a map.

    :param yara_rules_str: YARA rules as string.
    :type yara_rules_str: str
    :return: YARA rules as a map.
    :rtype: Mapping[str, Any]
    """
    rules = _split_yara_rules(yara_rules_str, imports_at_top=imports_at_top)
    rule_maps = _parse_yara_rules_list_to_map(rules)

    return {"rules": rule_maps}


def convert_yara_rules_to_yara_model(
    yara_rules_str: str, imports_at_top: bool = False
) -> Yara:
    """
    Convert YARA rules into a Yara model.

    :param yara_rules_str: YARA rules as string.
    :type yara_rules_str: str
    :return: YARA rules as a Yara model.
    :rtype: Yara
    """
    yara_data = convert_yara_rules_to_map(yara_rules_str, imports_at_top=imports_at_top)
    return Yara.parse_obj(yara_data)


def _split_yara_rules(yara_rules_str: str, imports_at_top: bool = False) -> List[str]:
    imports = None
    if imports_at_top:
        imports = _get_imports(yara_rules_str)

    rule_buffer = None

    result = []
    for line in StringIO(yara_rules_str).readlines():
        if rule_buffer is None and (
            line.startswith(_RULE_STARTS)
            or (not imports_at_top and line.startswith(_IMPORT_STARTS))
        ):
            rule_buffer = StringIO()

            if imports_at_top and imports is not None:
                rule_buffer.write(imports)

        if rule_buffer is not None:
            rule_buffer.write(line)

        if rule_buffer is not None and line.startswith(_RULE_ENDS):
            rule = rule_buffer.getvalue()
            result.append(rule)

            rule_buffer.close()
            rule_buffer = None

    return result


def _get_imports(yara_rules_str: str) -> str:
    # Assuming that all imports are in the beginning of the file and
    # separated from first rule by space.
    import_buffer = StringIO()
    for line in StringIO(yara_rules_str).readlines():
        if line.startswith(_RULE_STARTS):
            break
        import_buffer.write(line)
    return import_buffer.getvalue()


def _parse_yara_rules_list_to_map(yara_rule_list: List[str]) -> List[Mapping[str, Any]]:
    result = []
    for yara_rule in yara_rule_list:
        rule = _parse_yara_rule(yara_rule)
        if rule is None:
            continue

        result.append(rule)
    return result


def _parse_yara_rule(yara_rule: str) -> Optional[Mapping[str, Any]]:
    name = _get_name(yara_rule)
    if name is None:
        log.error("No name for rule: %s", yara_rule)
        return None

    description = _get_description(yara_rule)
    if description is None:
        log.error("No description for rule: %s", yara_rule)
        return None

    report = _get_report(yara_rule)
    if report is None:
        log.info("No report for rule: %s", name)

    last_modified = _get_last_modified(yara_rule)
    if last_modified is None:
        log.info("No last modified for rule: %s", name)

    return {
        "name": name,
        "description": description,
        "report": report,
        "last_modified": last_modified,
        "rule": yara_rule,
    }


def _get_name(yara_rule: str) -> Optional[str]:
    return _match_regex(_NAME_REGEX, yara_rule)


def _get_description(yara_rule: str) -> Optional[str]:
    return _match_regex(_DESCRIPTION_REGEX, yara_rule)


def _get_report(yara_rule: str) -> Optional[str]:
    return _match_regex(_REPORT_REGEX, yara_rule)


def _get_last_modified(yara_rule: str) -> Optional[str]:
    return _match_regex(_LAST_MODIFIED_REGEX, yara_rule)


def _match_regex(regex: re.Pattern, string) -> Optional[str]:
    match = regex.search(string)
    if match:
        return match.group(1)
    else:
        return None


def create_yara_indicator(
    yara_rule: YaraRule,
    created_by: Optional[Identity] = None,
    created: Optional[datetime] = None,
    modified: Optional[datetime] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    object_markings: Optional[List[MarkingDefinition]] = None,
) -> Indicator:
    """Create a YARA rule indicator."""
    name = yara_rule.name

    description: Optional[str] = yara_rule.description
    if description == "-":
        description = None

    last_modified = yara_rule.last_modified
    if last_modified is not None:
        modified = last_modified

    if created is None:
        created = modified

    if modified is not None and created is not None and created > modified:
        created, modified = modified, created

    valid_from = created

    rule = yara_rule.rule

    return create_indicator(
        rule,
        _PATTERN_TYPE_YARA,
        created_by=created_by,
        created=created,
        modified=modified,
        name=name,
        description=description,
        valid_from=valid_from,
        labels=labels,
        confidence=confidence,
        object_markings=object_markings,
    )
