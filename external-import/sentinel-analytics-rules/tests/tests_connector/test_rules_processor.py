"""End-to-end tests of a run: mapping, ATT&CK links, deployment reconciliation."""

from unittest.mock import MagicMock

import pytest
from conftest import SCHEMA_WITHOUT_DEPLOYED_ON, make_settings
from connector import ConnectorState, SentinelRulesProcessor
from connector.attack_patterns import attack_pattern_id
from connector.deployed_rules_processor import RULES_PER_BUNDLE
from connector.rule_mapper import map_rule
from pycti import Identity, Indicator, StixCoreRelationship
from sentinel_samples import FUSION_RULE, NRT_RULE, SCHEDULED_RULE, rule

OLD_INDICATOR = Indicator.generate_id("an older version of the query")
GONE_INDICATOR = Indicator.generate_id("a rule deleted from Sentinel")


def _processor(helper, rules, state=None, **config) -> SentinelRulesProcessor:
    processor = SentinelRulesProcessor()
    processor.inject_dependencies(
        settings=make_settings({"sentinel_analytics_rules": config}),
        helper=helper,
        state=state or ConnectorState(),
    )
    processor.post_init()
    processor.client = MagicMock()
    processor.client.iter_alert_rules.return_value = iter(rules)
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


def _indicator_id(raw):
    return Indicator.generate_id(map_rule(raw).pattern)


def test_rules_become_indicators_linked_to_techniques_and_deployed(helper):
    processor = _processor(helper, [SCHEDULED_RULE, NRT_RULE, FUSION_RULE])
    (objects,) = _run(processor)
    builder = processor.builder
    assert objects[:3] == builder.common_objects
    assert builder.platform.name == "Microsoft Sentinel"
    assert builder.platform.security_platform_type == "SIEM"

    indicators = {obj.id: obj for obj in _of_type(objects, "indicator")}
    assert set(indicators) == {
        _indicator_id(SCHEDULED_RULE),
        _indicator_id(NRT_RULE),
    }
    scheduled = indicators[_indicator_id(SCHEDULED_RULE)]
    assert scheduled.pattern_type == "sentinel-rule"
    assert indicators[_indicator_id(NRT_RULE)].pattern_type == "kql"
    assert scheduled.x_opencti_rule_level == "high"
    assert scheduled.external_references[0].external_id == SCHEDULED_RULE["name"]

    # Unknown to the platform and unnamed by Sentinel: created under the MITRE id.
    assert {p.name for p in _of_type(objects, "attack-pattern")} == {
        "T1059",
        "T1059.001",
        "T1530",
    }
    indicates = _of_type(objects, "relationship", "indicates")
    assert sorted((r.source_ref, r.target_ref) for r in indicates) == sorted(
        [
            (_indicator_id(SCHEDULED_RULE), attack_pattern_id("T1059")),
            (_indicator_id(SCHEDULED_RULE), attack_pattern_id("T1059.001")),
            (_indicator_id(NRT_RULE), attack_pattern_id("T1530")),
        ]
    )

    deployments = {
        r.source_ref: r for r in _of_type(objects, "relationship", "deployed-on")
    }
    active = deployments[_indicator_id(SCHEDULED_RULE)]
    assert active.id == StixCoreRelationship.generate_id(
        "deployed-on", _indicator_id(SCHEDULED_RULE), builder.platform.id
    )
    assert active.deployment_status == "active"
    assert active.external_id == SCHEDULED_RULE["name"]
    assert active.deployed_at == "2026-01-02T03:04:05.123Z"
    assert deployments[_indicator_id(NRT_RULE)].deployment_status == "deployed"
    assert "deployed_at" not in deployments[_indicator_id(NRT_RULE)]

    assert processor.state.deployed_rules == {
        SCHEDULED_RULE["name"]: _indicator_id(SCHEDULED_RULE),
        NRT_RULE["name"]: _indicator_id(NRT_RULE),
    }
    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["skipped"] == {"kind_Fusion": 1}
    assert summary["relationship"] == "deployed-on"


def test_techniques_held_by_the_platform_are_not_resent(helper):
    helper.api.attack_pattern.list.return_value = [
        {"standard_id": attack_pattern_id("T1059"), "x_opencti_stix_ids": []}
    ]
    (objects,) = _run(_processor(helper, [SCHEDULED_RULE]))
    assert [p.x_mitre_id for p in _of_type(objects, "attack-pattern")] == ["T1059.001"]
    assert len(_of_type(objects, "relationship", "indicates")) == 2


def test_platform_without_deployed_on_gets_related_to(helper):
    helper.api.query.return_value = SCHEMA_WITHOUT_DEPLOYED_ON
    (objects,) = _run(_processor(helper, [NRT_RULE]))
    assert _of_type(objects, "relationship", "deployed-on") == []
    (related,) = _of_type(objects, "relationship", "related-to")
    assert related.description == (
        "Deployed on Microsoft Sentinel (status: deployed, rule id: nrt-1)"
    )


def test_gone_and_changed_rules_are_removed(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": GONE_INDICATOR, "x_opencti_stix_ids": []},
        {"standard_id": OLD_INDICATOR, "x_opencti_stix_ids": []},
    ]
    state = ConnectorState(
        deployed_rules={
            "gone-rule": GONE_INDICATOR,
            SCHEDULED_RULE["name"]: OLD_INDICATOR,
        }
    )
    processor = _processor(helper, [SCHEDULED_RULE], state=state)
    bundles = _run(processor)
    assert len(bundles) == 2
    removed = {
        r.source_ref: r for r in _of_type(bundles[1], "relationship", "deployed-on")
    }
    assert {i: r.external_id for i, r in removed.items()} == {
        GONE_INDICATOR: "gone-rule",
        OLD_INDICATOR: SCHEDULED_RULE["name"],
    }
    assert all(r.deployment_status == "removed" for r in removed.values())
    assert all(r.removed_at == r.last_sync_at for r in removed.values())
    assert processor.state.deployed_rules == {
        SCHEDULED_RULE["name"]: _indicator_id(SCHEDULED_RULE)
    }


def test_removed_rules_deleted_from_the_platform_need_nothing(helper):
    state = ConnectorState(deployed_rules={"gone-rule": GONE_INDICATOR})
    assert len(_run(_processor(helper, [SCHEDULED_RULE], state=state))) == 1


def test_removals_are_retried_when_the_platform_cannot_be_asked(helper):
    helper.api.indicator.list.side_effect = RuntimeError("platform down")
    state = ConnectorState(deployed_rules={"gone-rule": GONE_INDICATOR})
    processor = _processor(helper, [SCHEDULED_RULE], state=state)
    assert len(_run(processor)) == 1
    assert processor.state.pending_removals == {GONE_INDICATOR: "gone-rule"}

    helper.api.indicator.list.side_effect = None
    helper.api.indicator.list.return_value = [
        {"standard_id": GONE_INDICATOR, "x_opencti_stix_ids": []}
    ]
    processor.client.iter_alert_rules.return_value = iter([SCHEDULED_RULE])
    bundles = _run(processor)
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert removed.source_ref == GONE_INDICATOR
    assert processor.state.pending_removals is None


def test_disabled_rules_can_be_left_out(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": _indicator_id(NRT_RULE), "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={"nrt-1": _indicator_id(NRT_RULE)})
    processor = _processor(
        helper, [SCHEDULED_RULE, NRT_RULE], state=state, import_disabled_rules=False
    )
    bundles = _run(processor)
    assert [i.name for i in _of_type(bundles[0], "indicator")] == ["Encoded PowerShell"]
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert (removed.source_ref, removed.deployment_status) == (
        _indicator_id(NRT_RULE),
        "removed",
    )


def test_large_rule_sets_are_split_into_bundles(helper):
    rules = [
        {
            **rule(SCHEDULED_RULE, query=f"SecurityEvent | take {index}"),
            "name": f"r{index}",
        }
        for index in range(RULES_PER_BUNDLE + 1)
    ]
    bundles = _run(_processor(helper, rules))
    assert [len(_of_type(b, "indicator")) for b in bundles] == [RULES_PER_BUNDLE, 1]


def test_process_sends_the_bundles_in_one_work(helper):
    helper.api.work.initiate_work.return_value = "work-1"
    helper.send_stix2_bundle.return_value = ["bundle"]
    processor = _processor(helper, [SCHEDULED_RULE])
    processor.process()
    helper.api.work.initiate_work.assert_called_once()
    assert helper.send_stix2_bundle.call_count == 1
    helper.api.work.to_processed.assert_called_once()


def test_collect_errors_fail_the_run_without_touching_the_state(helper):
    state = ConnectorState(deployed_rules={"gone-rule": GONE_INDICATOR})
    processor = _processor(helper, [], state=state)
    processor.client.iter_alert_rules.side_effect = RuntimeError("ARM down")
    with pytest.raises(RuntimeError):
        processor.process()
    assert processor.state.deployed_rules == {"gone-rule": GONE_INDICATOR}
    helper.send_stix2_bundle.assert_not_called()


EXISTING_PLATFORM = Identity.generate_id("SOC Sentinel", "securityplatform")
EXISTING = {
    "entity_type": "SecurityPlatform",
    "standard_id": EXISTING_PLATFORM,
    "name": "SOC Sentinel",
}


def test_configured_platform_id_targets_the_existing_platform(helper):
    helper.api.identity.read.return_value = EXISTING
    processor = _processor(helper, [SCHEDULED_RULE], platform_id="internal-platform-id")
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
    processor = _processor(helper, [SCHEDULED_RULE], platform_id="unknown")
    with pytest.raises(ValueError, match="is not a Security Platform"):
        _run(processor)


UNMAPPED_GONE_KEY = "gone-rule"
UNMAPPED_GONE_INDICATOR = Indicator.generate_id("gone rule pattern")


def test_unmapped_rule_keeps_the_deployments_missing_from_the_run(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": UNMAPPED_GONE_INDICATOR, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={UNMAPPED_GONE_KEY: UNMAPPED_GONE_INDICATOR})
    processor = _processor(helper, [SCHEDULED_RULE, NRT_RULE], state=state)
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
    assert processor.state.deployed_rules[UNMAPPED_GONE_KEY] == UNMAPPED_GONE_INDICATOR
    assert len(processor.state.deployed_rules) > 1
    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["complete"] is False
    assert summary["skipped"]["invalid"] == 1


def test_switched_platform_is_reconciled_while_the_former_removals_wait(helper):
    former_platform = "identity--3a9e2b6c-5a51-5d3c-9b07-4f1f3c1d9a10"
    # Run 1: the platform changed and the former one cannot be asked.
    helper.api.indicator.list.side_effect = RuntimeError("platform down")
    state = ConnectorState(
        deployed_rules={"gone-rule": GONE_INDICATOR}, platform_id=former_platform
    )
    processor = _processor(helper, [SCHEDULED_RULE, NRT_RULE], state=state)
    (bundle,) = _run(processor)
    platform = processor.builder.platform_id
    new_indicators = {
        r.source_ref for r in _of_type(bundle, "relationship", "deployed-on")
    }
    assert new_indicators == {_indicator_id(SCHEDULED_RULE), _indicator_id(NRT_RULE)}
    assert processor.state.platform_id == platform
    assert set(processor.state.deployed_rules.values()) == new_indicators
    assert processor.state.pending_removals is None
    assert processor.state.former_platform_removals == {
        former_platform: {GONE_INDICATOR: "gone-rule"}
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


def test_triggers_sharing_a_query_are_distinct_deployments(helper):
    stricter = rule(SCHEDULED_RULE, triggerThreshold=20)
    stricter["name"] = "stricter-rule"
    processor = _processor(helper, [SCHEDULED_RULE, stricter])
    objects = _run(processor)[0]

    indicators = _of_type(objects, "indicator")
    assert {i.pattern_type for i in indicators} == {"sentinel-rule"}
    assert len({i.id for i in indicators}) == 2
    deployments = _of_type(objects, "relationship", "deployed-on")
    assert {d.external_id for d in deployments} == {
        SCHEDULED_RULE["name"],
        "stricter-rule",
    }
    assert len(set(processor.state.deployed_rules.values())) == 2


def test_trigger_change_removes_the_former_logic(helper):
    processor = _processor(helper, [SCHEDULED_RULE])
    _run(processor)
    (former_indicator,) = processor.state.deployed_rules.values()

    helper.api.indicator.list.return_value = [
        {"standard_id": former_indicator, "x_opencti_stix_ids": []}
    ]
    raised = rule(SCHEDULED_RULE, triggerThreshold=20)
    processor = _processor(helper, [raised], state=processor.state)
    bundles = _run(processor)

    (current,) = _of_type(bundles[0], "relationship", "deployed-on")
    assert current.source_ref != former_indicator
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert (removed.source_ref, removed.deployment_status) == (
        former_indicator,
        "removed",
    )
    assert removed.external_id == SCHEDULED_RULE["name"]
