"""End-to-end tests of a run: mapping, ATT&CK links, deployment reconciliation."""

from unittest.mock import MagicMock

import pytest
from conftest import SCHEMA_WITHOUT_DEPLOYED_ON, make_settings
from connector import ConnectorState, CrowdStrikeRulesProcessor
from connector.attack_patterns import attack_pattern_id
from connector.rule_mapper import rule_pattern
from connectors_sdk import ApiForbiddenError, ApiServerError
from crowdstrike_samples import DNS_RULE, MAC_GROUP, PROCESS_RULE, WINDOWS_GROUP
from pycti import Indicator

GONE_INDICATOR = Indicator.generate_id('{"ruletype_name": "deleted rule"}')
GONE_KEY = f"{WINDOWS_GROUP['id']}/99"


def _processor(
    helper, groups, state=None, enforced=None, **config
) -> CrowdStrikeRulesProcessor:
    processor = CrowdStrikeRulesProcessor()
    processor.inject_dependencies(
        settings=make_settings({"crowdstrike_ioa_rules": config}),
        helper=helper,
        state=state or ConnectorState(),
    )
    processor.post_init()
    processor.client = MagicMock()
    processor.client.iter_rule_groups.return_value = iter(groups)
    processor.client.enforced_rule_group_ids.return_value = (
        {group["id"] for group in groups} if enforced is None else enforced
    )
    return processor


def _run(processor) -> list[list]:
    return list(processor.transform(processor.collect()))


def _of_type(objects, stix_type, relationship_type=None):
    return [
        obj
        for obj in objects
        if obj.type == stix_type
        and (relationship_type is None or obj.relationship_type == relationship_type)
    ]


def _indicator_id(rule):
    return Indicator.generate_id(rule_pattern(rule))


def test_rules_become_ioa_indicators_deployed_on_falcon(helper):
    processor = _processor(helper, [WINDOWS_GROUP, MAC_GROUP])
    (objects,) = _run(processor)
    assert processor.builder.platform.security_platform_type == "EDR"

    indicators = {obj.id: obj for obj in _of_type(objects, "indicator")}
    process = indicators[_indicator_id(PROCESS_RULE)]
    assert process.pattern_type == "crowdstrike-ioa"
    assert process.x_mitre_platforms == ["windows"]
    assert process.x_opencti_rule_logsource == {
        "category": "process_creation",
        "product": "windows",
    }
    assert process.x_opencti_rule_level == "high"
    assert process.external_references[0].external_id == "1"

    indicates = _of_type(objects, "relationship", "indicates")
    assert sorted((r.source_ref, r.target_ref) for r in indicates) == sorted(
        [
            (_indicator_id(PROCESS_RULE), attack_pattern_id("T1059.001")),
            (_indicator_id(PROCESS_RULE), attack_pattern_id("T1027")),
        ]
    )
    deployments = {
        r.external_id: r for r in _of_type(objects, "relationship", "deployed-on")
    }
    assert deployments["1"].deployment_status == "active"
    assert deployments["1"].deployed_at == "2026-01-02T03:04:05.892Z"
    assert deployments["2"].deployment_status == "deployed"
    # Enabled rule of a disabled group.
    assert deployments["7"].deployment_status == "deployed"
    assert set(processor.state.deployed_rules) == {
        f"{WINDOWS_GROUP['id']}/1",
        f"{WINDOWS_GROUP['id']}/2",
        f"{MAC_GROUP['id']}/7",
    }


def test_platform_without_deployed_on_gets_related_to(helper):
    helper.api.query.return_value = SCHEMA_WITHOUT_DEPLOYED_ON
    (objects,) = _run(_processor(helper, [WINDOWS_GROUP]))
    descriptions = sorted(
        r.description for r in _of_type(objects, "relationship", "related-to")
    )
    assert descriptions == [
        "Deployed on CrowdStrike Falcon (status: active, rule id: 1)",
        "Deployed on CrowdStrike Falcon (status: deployed, rule id: 2)",
    ]


def test_removed_rule_carries_its_instance_id(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": GONE_INDICATOR, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={GONE_KEY: GONE_INDICATOR})
    bundles = _run(_processor(helper, [WINDOWS_GROUP], state=state))
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert (removed.source_ref, removed.external_id, removed.deployment_status) == (
        GONE_INDICATOR,
        "99",
        "removed",
    )


def test_changed_rule_logic_removes_the_previous_indicator(helper):
    old = Indicator.generate_id(
        rule_pattern(dict(PROCESS_RULE, action_label="Monitor"))
    )
    helper.api.indicator.list.return_value = [
        {"standard_id": old, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={f"{WINDOWS_GROUP['id']}/1": old})
    bundles = _run(_processor(helper, [WINDOWS_GROUP], state=state))
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert (removed.source_ref, removed.external_id) == (old, "1")


def test_disabled_rules_can_be_left_out(helper):
    processor = _processor(
        helper, [WINDOWS_GROUP, MAC_GROUP], import_disabled_rules=False
    )
    (objects,) = _run(processor)
    assert [
        r.external_id for r in _of_type(objects, "relationship", "deployed-on")
    ] == ["1"]
    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["skipped"] == {"disabled": 2}


def test_collect_passes_the_group_filter(helper):
    processor = _processor(
        helper, [WINDOWS_GROUP], rule_group_filter="platform:'windows'"
    )
    triples = processor.collect()
    assert [rule["instance_id"] for _, rule, _ in triples] == ["1", "2"]
    processor.client.iter_rule_groups.assert_called_once_with("platform:'windows'")


def _deployment_statuses(objects):
    return {
        r.external_id: r.deployment_status
        for r in _of_type(objects, "relationship", "deployed-on")
    }


def test_group_outside_prevention_policies_is_not_active(helper):
    (objects,) = _run(_processor(helper, [WINDOWS_GROUP], enforced=set()))
    assert _deployment_statuses(objects) == {"1": "deployed", "2": "deployed"}
    summary = helper.connector_logger.info.call_args_list[0].args[1]
    assert summary["rule_groups_in_prevention_policies"] == 0


def test_rules_outside_prevention_policies_can_be_left_out(helper):
    processor = _processor(
        helper, [WINDOWS_GROUP], enforced=set(), import_disabled_rules=False
    )
    assert _run(processor) == []
    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["skipped"] == {"disabled": 2}


def test_missing_policy_scope_falls_back_to_the_enabled_flags(helper):
    processor = _processor(helper, [WINDOWS_GROUP])
    processor.client.enforced_rule_group_ids.side_effect = ApiForbiddenError(
        "Forbidden (403) on GET /policy/combined/prevention/v1"
    )
    (objects,) = _run(processor)
    assert _deployment_statuses(objects) == {"1": "active", "2": "deployed"}
    (warning,) = [
        call
        for call in helper.connector_logger.warning.call_args_list
        if "prevention policies" in call.args[0]
    ]
    assert warning.args[1] == {"platform": "CrowdStrike Falcon"}


def test_policy_check_can_be_turned_off(helper):
    processor = _processor(
        helper, [WINDOWS_GROUP], enforced=set(), check_prevention_policies=False
    )
    (objects,) = _run(processor)
    assert _deployment_statuses(objects) == {"1": "active", "2": "deployed"}
    processor.client.enforced_rule_group_ids.assert_not_called()


def test_policy_errors_other_than_forbidden_fail_the_run(helper):
    processor = _processor(helper, [WINDOWS_GROUP])
    processor.client.enforced_rule_group_ids.side_effect = ApiServerError(
        "Server error (503)", status_code=503
    )
    with pytest.raises(ApiServerError):
        processor.collect()


def test_collect_errors_fail_the_run_without_touching_the_state(helper):
    state = ConnectorState(deployed_rules={GONE_KEY: GONE_INDICATOR})
    processor = _processor(helper, [], state=state)
    processor.client.iter_rule_groups.side_effect = RuntimeError("Falcon down")
    with pytest.raises(RuntimeError):
        processor.process()
    assert processor.state.deployed_rules == {GONE_KEY: GONE_INDICATOR}


def test_dns_rule_without_logic_change_keeps_its_indicator(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": _indicator_id(PROCESS_RULE), "x_opencti_stix_ids": []}
    ]
    first = _processor(helper, [WINDOWS_GROUP])
    _run(first)
    second = _processor(
        helper,
        [dict(WINDOWS_GROUP, rules=[dict(DNS_RULE, name="renamed")])],
        state=first.state,
    )
    bundles = _run(second)
    # Only the deleted process rule is removed; the renamed DNS rule is the same.
    assert len(bundles) == 2
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert removed.external_id == "1"
