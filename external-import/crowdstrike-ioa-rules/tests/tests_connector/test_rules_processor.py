"""End-to-end tests of a run: mapping, ATT&CK links, deployment reconciliation."""

from unittest.mock import MagicMock

import pytest
from conftest import SCHEMA_WITHOUT_DEPLOYED_ON, make_settings
from connector import ConnectorState, CrowdStrikeRulesProcessor
from connector.attack_patterns import attack_pattern_id
from connector.rule_mapper import rule_pattern
from connectors_sdk import ApiForbiddenError, ApiServerError
from crowdstrike_samples import (
    DNS_RULE,
    MAC_GROUP,
    PROCESS_RULE,
    WINDOWS_GROUP,
    group,
)
from pycti import Identity, Indicator

GONE_INDICATOR = Indicator.generate_id('{"ruletype_name": "deleted rule"}')
GONE_ID = f"{WINDOWS_GROUP['id']}/99"
PROCESS_ID = f"{WINDOWS_GROUP['id']}/1"
DNS_ID = f"{WINDOWS_GROUP['id']}/2"
MAC_ID = f"{MAC_GROUP['id']}/7"


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
    assert process.external_references[0].external_id == PROCESS_ID

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
    assert deployments[PROCESS_ID].deployment_status == "active"
    assert deployments[PROCESS_ID].deployed_at == "2026-01-02T03:04:05.892Z"
    assert deployments[DNS_ID].deployment_status == "deployed"
    # Enabled rule of a disabled group.
    assert deployments[MAC_ID].deployment_status == "deployed"
    assert set(processor.state.deployed_rules) == {PROCESS_ID, DNS_ID, MAC_ID}


def test_platform_without_deployed_on_gets_related_to(helper):
    helper.api.query.return_value = SCHEMA_WITHOUT_DEPLOYED_ON
    (objects,) = _run(_processor(helper, [WINDOWS_GROUP]))
    descriptions = sorted(
        r.description for r in _of_type(objects, "relationship", "related-to")
    )
    assert descriptions == [
        f"Deployed on CrowdStrike Falcon (status: active, rule id: {PROCESS_ID})",
        f"Deployed on CrowdStrike Falcon (status: deployed, rule id: {DNS_ID})",
    ]


def test_removed_rule_carries_its_namespaced_id(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": GONE_INDICATOR, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={GONE_ID: GONE_INDICATOR})
    bundles = _run(_processor(helper, [WINDOWS_GROUP], state=state))
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert (removed.source_ref, removed.external_id, removed.deployment_status) == (
        GONE_INDICATOR,
        GONE_ID,
        "removed",
    )


def test_same_instance_id_in_two_groups_never_shares_an_id(helper):
    other_rule = dict(PROCESS_RULE, action_label="Monitor")
    other_group = group(
        WINDOWS_GROUP, id="1f2e3d4c5b6a79880011223344556677", rules=[other_rule]
    )
    windows_group = group(WINDOWS_GROUP, rules=[PROCESS_RULE])
    other_id = f"{other_group['id']}/1"
    first = _processor(helper, [windows_group, other_group])
    (objects,) = _run(first)
    deployments = {
        r.source_ref: r.external_id
        for r in _of_type(objects, "relationship", "deployed-on")
    }
    assert deployments == {
        _indicator_id(PROCESS_RULE): PROCESS_ID,
        _indicator_id(other_rule): other_id,
    }
    references = {
        i.id: i.external_references[0].external_id
        for i in _of_type(objects, "indicator")
    }
    assert references == deployments

    # The rule deleted from one group is removed under its own id only.
    helper.api.indicator.list.return_value = [
        {"standard_id": _indicator_id(other_rule), "x_opencti_stix_ids": []}
    ]
    second = _processor(helper, [windows_group], state=first.state)
    current, removals = _run(second)
    (kept,) = _of_type(current, "relationship", "deployed-on")
    assert kept.external_id == PROCESS_ID
    (removed,) = _of_type(removals, "relationship", "deployed-on")
    assert (removed.source_ref, removed.external_id, removed.deployment_status) == (
        _indicator_id(other_rule),
        other_id,
        "removed",
    )
    assert second.state.deployed_rules == {PROCESS_ID: _indicator_id(PROCESS_RULE)}


def test_changed_rule_logic_removes_the_previous_indicator(helper):
    old = Indicator.generate_id(
        rule_pattern(dict(PROCESS_RULE, action_label="Monitor"))
    )
    helper.api.indicator.list.return_value = [
        {"standard_id": old, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={PROCESS_ID: old})
    bundles = _run(_processor(helper, [WINDOWS_GROUP], state=state))
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert (removed.source_ref, removed.external_id) == (old, PROCESS_ID)


def test_disabled_rules_can_be_left_out(helper):
    processor = _processor(
        helper, [WINDOWS_GROUP, MAC_GROUP], import_disabled_rules=False
    )
    (objects,) = _run(processor)
    assert [
        r.external_id for r in _of_type(objects, "relationship", "deployed-on")
    ] == [PROCESS_ID]
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
    assert _deployment_statuses(objects) == {PROCESS_ID: "deployed", DNS_ID: "deployed"}
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
    assert _deployment_statuses(objects) == {PROCESS_ID: "active", DNS_ID: "deployed"}
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
    assert _deployment_statuses(objects) == {PROCESS_ID: "active", DNS_ID: "deployed"}
    processor.client.enforced_rule_group_ids.assert_not_called()


def test_policy_errors_other_than_forbidden_fail_the_run(helper):
    processor = _processor(helper, [WINDOWS_GROUP])
    processor.client.enforced_rule_group_ids.side_effect = ApiServerError(
        "Server error (503)", status_code=503
    )
    with pytest.raises(ApiServerError):
        processor.collect()


def test_collect_errors_fail_the_run_without_touching_the_state(helper):
    state = ConnectorState(deployed_rules={GONE_ID: GONE_INDICATOR})
    processor = _processor(helper, [], state=state)
    processor.client.iter_rule_groups.side_effect = RuntimeError("Falcon down")
    with pytest.raises(RuntimeError):
        processor.process()
    assert processor.state.deployed_rules == {GONE_ID: GONE_INDICATOR}


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
    assert removed.external_id == PROCESS_ID


EXISTING_PLATFORM = Identity.generate_id("SOC Falcon", "securityplatform")
EXISTING = {
    "entity_type": "SecurityPlatform",
    "standard_id": EXISTING_PLATFORM,
    "name": "SOC Falcon",
}


def test_configured_platform_id_targets_the_existing_platform(helper):
    helper.api.identity.read.return_value = EXISTING
    processor = _processor(helper, [WINDOWS_GROUP], platform_id="internal-platform-id")
    (objects,) = _run(processor)
    helper.api.identity.read.assert_called_once_with(id="internal-platform-id")
    deployments = _of_type(objects, "relationship", "deployed-on")
    assert deployments
    assert {deployment.target_ref for deployment in deployments} == {EXISTING_PLATFORM}
    # The platform another integration created is referenced, never rewritten.
    assert not [
        obj
        for obj in _of_type(objects, "identity")
        if obj.identity_class == "securityplatform"
    ]
    assert processor.state.platform_id == EXISTING_PLATFORM


@pytest.mark.parametrize(
    "found",
    [None, {"entity_type": "System", "standard_id": "identity--x", "name": "SOC"}],
)
def test_configured_platform_id_must_be_a_security_platform(helper, found):
    helper.api.identity.read.return_value = found
    processor = _processor(helper, [WINDOWS_GROUP], platform_id="unknown")
    with pytest.raises(ValueError, match="is not a Security Platform"):
        _run(processor)


UNMAPPED_GONE_ID = "gone-rule"
UNMAPPED_GONE_INDICATOR = Indicator.generate_id("gone rule pattern")


def test_unmapped_rule_keeps_the_deployments_missing_from_the_run(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": UNMAPPED_GONE_INDICATOR, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={UNMAPPED_GONE_ID: UNMAPPED_GONE_INDICATOR})
    processor = _processor(helper, [WINDOWS_GROUP, MAC_GROUP], state=state)
    map_rule = processor.to_detection_rule
    calls = []

    def to_detection_rule(raw_rule):
        calls.append(raw_rule)
        if len(calls) == 1:
            raise ValueError("unexpected payload shape")
        return map_rule(raw_rule)

    processor.to_detection_rule = to_detection_rule
    bundles = _run(processor)
    statuses = [
        deployment.deployment_status
        for bundle in bundles
        for deployment in _of_type(bundle, "relationship", "deployed-on")
    ]
    # The unmapped rule cannot be told apart from the gone one: nothing is removed
    assert statuses
    assert "removed" not in statuses
    assert processor.state.deployed_rules[UNMAPPED_GONE_ID] == UNMAPPED_GONE_INDICATOR
    assert len(processor.state.deployed_rules) > 1
    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["complete"] is False
    assert summary["skipped"]["invalid"] == 1


def test_switched_platform_is_reconciled_while_the_former_removals_wait(helper):
    former_platform = "identity--3a9e2b6c-5a51-5d3c-9b07-4f1f3c1d9a10"
    # Run 1: the platform changed and the former one cannot be asked.
    helper.api.indicator.list.side_effect = RuntimeError("platform down")
    state = ConnectorState(
        deployed_rules={GONE_ID: GONE_INDICATOR}, platform_id=former_platform
    )
    processor = _processor(helper, [WINDOWS_GROUP], state=state)
    (bundle,) = _run(processor)
    platform = processor.builder.platform_id
    new_indicators = {
        r.source_ref for r in _of_type(bundle, "relationship", "deployed-on")
    }
    assert new_indicators
    assert processor.state.platform_id == platform
    assert set(processor.state.deployed_rules.values()) == new_indicators
    assert processor.state.pending_removals is None
    assert processor.state.former_platform_removals == {
        former_platform: {GONE_INDICATOR: GONE_ID}
    }

    # Run 2: every rule was deleted from the new platform before the recovery.
    helper.api.indicator.list.side_effect = lambda **kwargs: [
        {"standard_id": indicator_id, "x_opencti_stix_ids": []}
        for indicator_id in kwargs["filters"]["filters"][0]["values"]
    ]
    processor = _processor(helper, [], state=processor.state)
    removals = [
        r for b in _run(processor) for r in _of_type(b, "relationship", "deployed-on")
    ]
    assert {r.deployment_status for r in removals} == {"removed"}
    assert {(r.source_ref, r.target_ref) for r in removals} == {
        (GONE_INDICATOR, former_platform),
        *((indicator_id, platform) for indicator_id in new_indicators),
    }
    assert processor.state.deployed_rules == {}
    assert processor.state.pending_removals is None
    assert processor.state.former_platform_removals is None
