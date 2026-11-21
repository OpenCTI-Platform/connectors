"""Tests for the update of existing YARA rule Indicators."""

from unittest.mock import MagicMock

import pytest
from crowdstrike_feeds_connector.rule.yara_master_importer import YaraMasterImporter
from crowdstrike_feeds_services.utils.yara_parser import YaraParser
from pycti import Indicator as PyCTIIndicator

RULE_TEMPLATE = """rule CrowdStrike_Test_01 : test
{{
    meta:
        description = "Test rule"
        last_modified = "{last_modified}"
        reports = "CSIT-26001"
        actor = "N/A"
        malware_family = "N/A"
    condition:
        {condition}
}}
"""

OLD_RULE = RULE_TEMPLATE.format(last_modified="2026-01-01", condition="true")
NEW_RULE = RULE_TEMPLATE.format(last_modified="2026-02-01", condition="false")


def _importer(indicators: list[dict]) -> YaraMasterImporter:
    """Build an importer whose OpenCTI holds the given Indicators."""

    def read(id=None, filters=None):
        if id is not None:
            return next((i for i in indicators if i["standard_id"] == id), None)
        name = filters["filters"][0]["values"][0]
        return next((i for i in indicators if i["name"] == name), None)

    importer = YaraMasterImporter.__new__(YaraMasterImporter)
    importer.helper = MagicMock()
    importer.helper.api.indicator.read.side_effect = read
    importer.helper.api.stix_domain_object.update_field.side_effect = (
        lambda id, input: {"id": id}
    )
    return importer


def _indicator(internal_id: str, pattern: str) -> dict:
    return {
        "id": internal_id,
        "standard_id": PyCTIIndicator.generate_id(pattern),
        "name": "CrowdStrike_Test_01",
        "pattern": pattern,
    }


@pytest.fixture
def new_rule():
    [rule] = YaraParser.parse(NEW_RULE)
    return rule


def test_rule_held_by_another_indicator_is_not_updated(new_rule):
    # Two Indicators share the rule name. The name lookup returns the one
    # with the old version, while another one already holds the new version.
    importer = _importer(
        [_indicator("old-indicator", OLD_RULE), _indicator("new-indicator", NEW_RULE)]
    )

    new_rules = importer._update_existing([new_rule])

    assert new_rules == []
    importer.helper.api.stix_domain_object.update_field.assert_not_called()


def test_older_rule_is_updated(new_rule):
    importer = _importer([_indicator("old-indicator", OLD_RULE)])

    new_rules = importer._update_existing([new_rule])

    assert new_rules == []
    importer.helper.api.stix_domain_object.update_field.assert_called_once_with(
        id="old-indicator", input={"key": "pattern", "value": new_rule.rule}
    )


def test_unknown_rule_is_new(new_rule):
    importer = _importer([])

    new_rules = importer._update_existing([new_rule])

    assert new_rules == [new_rule]
    importer.helper.api.stix_domain_object.update_field.assert_not_called()
