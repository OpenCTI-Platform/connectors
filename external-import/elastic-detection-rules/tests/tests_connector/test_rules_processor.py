"""End-to-end tests of a run: mapping, ATT&CK links, deployment reconciliation."""

from unittest.mock import MagicMock

import pytest
from conftest import SCHEMA_WITHOUT_DEPLOYED_ON, make_settings
from connector import ConnectorState, ElasticRulesProcessor
from connector.attack_patterns import attack_pattern_id
from connector.deployed_rules_processor import RULES_PER_BUNDLE
from elastic_samples import EQL_RULE, KUERY_RULE, ML_RULE, rule
from pycti import Indicator, StixCoreRelationship

OLD_INDICATOR = Indicator.generate_id("an older version of the rule")
GONE_INDICATOR = Indicator.generate_id("a rule deleted from Kibana")


def _processor(helper, rules, state=None, **config) -> ElasticRulesProcessor:
    processor = ElasticRulesProcessor()
    processor.inject_dependencies(
        settings=make_settings({"elastic_detection_rules": config}),
        helper=helper,
        state=state or ConnectorState(),
    )
    processor.post_init()
    processor.client = MagicMock()
    processor.client.iter_rules.return_value = iter(rules)
    processor.client.rule_url = lambda saved_object_id: f"https://k/{saved_object_id}"
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
    return Indicator.generate_id(raw["query"])


def test_rules_become_indicators_linked_to_techniques_and_deployed(helper):
    processor = _processor(helper, [KUERY_RULE, EQL_RULE, ML_RULE])
    bundles = _run(processor)

    assert len(bundles) == 1
    objects = bundles[0]
    builder = processor.builder
    assert objects[:3] == builder.common_objects

    indicators = {obj.id: obj for obj in _of_type(objects, "indicator")}
    assert set(indicators) == {_indicator_id(KUERY_RULE), _indicator_id(EQL_RULE)}
    kuery_indicator = indicators[_indicator_id(KUERY_RULE)]
    assert kuery_indicator.pattern_type == "kuery"
    assert kuery_indicator.x_opencti_rule_level == "high"
    assert kuery_indicator.x_mitre_platforms == ["windows"]

    # Techniques unknown to the platform are created under the Elastic names.
    patterns = {obj.x_mitre_id: obj.name for obj in _of_type(objects, "attack-pattern")}
    assert patterns == {
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "PowerShell",
        "T1003": "OS Credential Dumping",
    }
    indicates = _of_type(objects, "relationship", "indicates")
    assert sorted((r.source_ref, r.target_ref) for r in indicates) == sorted(
        [
            (_indicator_id(KUERY_RULE), attack_pattern_id("T1059")),
            (_indicator_id(KUERY_RULE), attack_pattern_id("T1059.001")),
            (_indicator_id(EQL_RULE), attack_pattern_id("T1003")),
        ]
    )

    deployments = {
        r.source_ref: r for r in _of_type(objects, "relationship", "deployed-on")
    }
    active = deployments[_indicator_id(KUERY_RULE)]
    assert active.target_ref == builder.platform.id
    assert active.deployment_status == "active"
    assert active.external_id == KUERY_RULE["rule_id"]
    assert active.deployed_at == "2026-01-02T03:04:05.000Z"
    assert active.id == StixCoreRelationship.generate_id(
        "deployed-on", _indicator_id(KUERY_RULE), builder.platform.id
    )
    disabled = deployments[_indicator_id(EQL_RULE)]
    assert disabled.deployment_status == "deployed"
    assert disabled.last_sync_at == active.last_sync_at

    assert processor.state.deployed_rules == {
        KUERY_RULE["rule_id"]: _indicator_id(KUERY_RULE),
        EQL_RULE["rule_id"]: _indicator_id(EQL_RULE),
    }
    assert processor.state.pending_removals is None


def test_techniques_held_by_the_platform_are_not_resent(helper):
    helper.api.attack_pattern.list.return_value = [
        {"standard_id": attack_pattern_id("T1059"), "x_opencti_stix_ids": []},
        {"standard_id": attack_pattern_id("T1059.001"), "x_opencti_stix_ids": []},
    ]
    objects = _run(_processor(helper, [KUERY_RULE]))[0]
    assert _of_type(objects, "attack-pattern") == []
    assert len(_of_type(objects, "relationship", "indicates")) == 2
    lookup = helper.api.attack_pattern.list.call_args.kwargs
    assert sorted(lookup["filters"]["filters"][0]["values"]) == sorted(
        [attack_pattern_id("T1059"), attack_pattern_id("T1059.001")]
    )


def test_platform_without_deployed_on_gets_related_to(helper):
    helper.api.query.return_value = SCHEMA_WITHOUT_DEPLOYED_ON
    processor = _processor(helper, [KUERY_RULE])
    objects = _run(processor)[0]

    assert _of_type(objects, "relationship", "deployed-on") == []
    related = _of_type(objects, "relationship", "related-to")
    assert len(related) == 1
    assert related[0].target_ref == processor.builder.platform.id
    assert related[0].description == (
        "Deployed on Elastic Security (status: active, "
        f"rule id: {KUERY_RULE['rule_id']})"
    )
    warnings = [call.args[0] for call in helper.connector_logger.warning.call_args_list]
    assert sum("deployed-on" in message for message in warnings) == 1


def test_rules_gone_since_the_previous_run_are_removed(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": GONE_INDICATOR, "x_opencti_stix_ids": []},
        {"standard_id": OLD_INDICATOR, "x_opencti_stix_ids": []},
    ]
    state = ConnectorState(
        deployed_rules={
            "gone-rule": GONE_INDICATOR,
            # Same rule, logic changed since: its former Indicator is removed.
            KUERY_RULE["rule_id"]: OLD_INDICATOR,
        }
    )
    processor = _processor(helper, [KUERY_RULE], state=state)
    bundles = _run(processor)

    assert len(bundles) == 2
    removal = bundles[1]
    assert removal[:3] == processor.builder.common_objects
    removed = {
        r.source_ref: r for r in _of_type(removal, "relationship", "deployed-on")
    }
    assert set(removed) == {GONE_INDICATOR, OLD_INDICATOR}
    assert removed[GONE_INDICATOR].external_id == "gone-rule"
    assert removed[OLD_INDICATOR].external_id == KUERY_RULE["rule_id"]
    for relationship in removed.values():
        assert relationship.deployment_status == "removed"
        assert relationship.removed_at == relationship.last_sync_at
        assert "deployed_at" not in relationship
    assert processor.state.deployed_rules == {
        KUERY_RULE["rule_id"]: _indicator_id(KUERY_RULE)
    }


def test_removed_rules_deleted_from_the_platform_need_nothing(helper):
    state = ConnectorState(deployed_rules={"gone-rule": GONE_INDICATOR})
    processor = _processor(helper, [KUERY_RULE], state=state)
    bundles = _run(processor)
    assert len(bundles) == 1
    assert processor.state.deployed_rules == {
        KUERY_RULE["rule_id"]: _indicator_id(KUERY_RULE)
    }
    assert processor.state.pending_removals is None


def test_indicator_still_deployed_through_another_rule_is_not_removed(helper):
    twin = rule(KUERY_RULE, rule_id="twin-rule", id="twin-saved-object")
    state = ConnectorState(deployed_rules={"gone-rule": _indicator_id(KUERY_RULE)})
    processor = _processor(helper, [twin], state=state)
    assert len(_run(processor)) == 1
    helper.api.indicator.list.assert_not_called()


def test_rules_sharing_their_logic_share_one_deployment(helper):
    disabled_twin = rule(
        KUERY_RULE,
        rule_id="twin-rule",
        id="twin-saved-object",
        enabled=False,
        threat=EQL_RULE["threat"],
    )
    processor = _processor(helper, [disabled_twin, KUERY_RULE])
    objects = _run(processor)[0]

    indicator_id = _indicator_id(KUERY_RULE)
    (indicator,) = _of_type(objects, "indicator")
    assert indicator.id == indicator_id
    # The enabled rule describes the shared Indicator and its deployment.
    assert indicator.external_references[0].external_id == KUERY_RULE["rule_id"]
    (deployment,) = _of_type(objects, "relationship", "deployed-on")
    assert deployment.deployment_status == "active"
    assert deployment.external_id == KUERY_RULE["rule_id"]
    assert {r.target_ref for r in _of_type(objects, "relationship", "indicates")} == {
        attack_pattern_id("T1059"),
        attack_pattern_id("T1059.001"),
        attack_pattern_id("T1003"),
    }
    assert processor.state.deployed_rules == {
        "twin-rule": indicator_id,
        KUERY_RULE["rule_id"]: indicator_id,
    }


def test_large_removals_are_split_into_bundles(helper):
    gone = {
        f"gone-{index}": Indicator.generate_id(f"gone rule {index}")
        for index in range(RULES_PER_BUNDLE + 1)
    }
    helper.api.indicator.list.side_effect = lambda **kwargs: [
        {"standard_id": indicator_id, "x_opencti_stix_ids": []}
        for indicator_id in kwargs["filters"]["filters"][0]["values"]
    ]
    processor = _processor(
        helper, [KUERY_RULE], state=ConnectorState(deployed_rules=gone)
    )
    bundles = _run(processor)

    assert [len(_of_type(b, "relationship", "deployed-on")) for b in bundles] == [
        1,
        RULES_PER_BUNDLE,
        1,
    ]
    for bundle in bundles[1:]:
        assert bundle[:3] == processor.builder.common_objects
        assert {
            r.deployment_status for r in _of_type(bundle, "relationship", "deployed-on")
        } == {"removed"}


def test_renamed_platform_gets_the_previous_deployments_removed(helper):
    former_platform = "identity--3a9e2b6c-5a51-5d3c-9b07-4f1f3c1d9a10"
    helper.api.indicator.list.return_value = [
        {"standard_id": _indicator_id(KUERY_RULE), "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(
        deployed_rules={KUERY_RULE["rule_id"]: _indicator_id(KUERY_RULE)},
        platform_id=former_platform,
    )
    processor = _processor(helper, [KUERY_RULE], state=state)
    bundles = _run(processor)

    assert len(bundles) == 2
    (current,) = _of_type(bundles[0], "relationship", "deployed-on")
    assert current.target_ref == processor.builder.platform.id
    assert current.deployment_status == "active"
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert removed.target_ref == former_platform
    assert removed.source_ref == _indicator_id(KUERY_RULE)
    assert removed.deployment_status == "removed"
    assert processor.state.platform_id == processor.builder.platform.id


def test_renamed_platform_keeps_its_state_until_removals_are_sent(helper):
    former_platform = "identity--3a9e2b6c-5a51-5d3c-9b07-4f1f3c1d9a10"
    helper.api.indicator.list.side_effect = RuntimeError("platform down")
    previous = {"gone-rule": GONE_INDICATOR}
    state = ConnectorState(deployed_rules=previous, platform_id=former_platform)
    processor = _processor(helper, [KUERY_RULE], state=state)
    assert len(_run(processor)) == 1
    assert processor.state.platform_id == former_platform
    assert processor.state.deployed_rules == previous
    assert processor.state.pending_removals is None


def test_first_run_records_the_platform(helper):
    processor = _processor(helper, [KUERY_RULE])
    _run(processor)
    assert processor.state.platform_id == processor.builder.platform.id


def test_removals_are_retried_when_the_platform_cannot_be_asked(helper):
    helper.api.indicator.list.side_effect = RuntimeError("platform down")
    state = ConnectorState(deployed_rules={"gone-rule": GONE_INDICATOR})
    processor = _processor(helper, [KUERY_RULE], state=state)
    assert len(_run(processor)) == 1
    assert processor.state.pending_removals == {GONE_INDICATOR: "gone-rule"}

    helper.api.indicator.list.side_effect = None
    helper.api.indicator.list.return_value = [
        {"standard_id": GONE_INDICATOR, "x_opencti_stix_ids": []}
    ]
    processor.client.iter_rules.return_value = iter([KUERY_RULE])
    bundles = _run(processor)
    assert len(bundles) == 2
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert (removed.source_ref, removed.external_id) == (GONE_INDICATOR, "gone-rule")
    assert processor.state.pending_removals is None


def test_disabled_rules_left_out_count_as_removed(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": _indicator_id(EQL_RULE), "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(
        deployed_rules={EQL_RULE["rule_id"]: _indicator_id(EQL_RULE)}
    )
    processor = _processor(
        helper, [KUERY_RULE, EQL_RULE], state=state, import_disabled_rules=False
    )
    bundles = _run(processor)
    assert {i.id for i in _of_type(bundles[0], "indicator")} == {
        _indicator_id(KUERY_RULE)
    }
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert removed.source_ref == _indicator_id(EQL_RULE)
    assert removed.deployment_status == "removed"


def test_large_rule_sets_are_split_into_bundles(helper):
    rules = [
        rule(KUERY_RULE, rule_id=f"rule-{index}", query=f"process.pid:{index}")
        for index in range(RULES_PER_BUNDLE * 2 + 1)
    ]
    processor = _processor(helper, rules)
    bundles = _run(processor)
    assert [len(_of_type(b, "indicator")) for b in bundles] == [
        RULES_PER_BUNDLE,
        RULES_PER_BUNDLE,
        1,
    ]
    for bundle in bundles:
        assert bundle[:3] == processor.builder.common_objects
        # Each bundle carries the techniques its relationships target.
        assert len(_of_type(bundle, "attack-pattern")) == 2
    assert len(processor.state.deployed_rules) == len(rules)


def test_invalid_and_duplicate_rules_are_skipped(helper):
    broken = rule(KUERY_RULE, rule_id="broken", name=123, created_at="not a date")
    duplicate = rule(KUERY_RULE, query="process.pid:1")
    processor = _processor(helper, [KUERY_RULE, broken, duplicate])
    objects = _run(processor)[0]
    assert len(_of_type(objects, "indicator")) == 1
    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["skipped"] == {"invalid": 1, "duplicate": 1}


def test_nothing_to_send_without_rules(helper):
    processor = _processor(helper, [])
    assert _run(processor) == []
    assert processor.state.deployed_rules == {}


def test_collect_passes_the_rule_filter(helper):
    processor = _processor(
        helper, [KUERY_RULE], rule_filter="alert.attributes.enabled:true"
    )
    assert processor.collect() == [KUERY_RULE]
    processor.client.iter_rules.assert_called_once_with("alert.attributes.enabled:true")


def test_process_sends_every_bundle_in_one_work(helper):
    helper.api.work.initiate_work.return_value = "work-1"
    helper.send_stix2_bundle.return_value = ["bundle"]
    helper.api.indicator.list.return_value = [
        {"standard_id": GONE_INDICATOR, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={"gone-rule": GONE_INDICATOR})
    processor = _processor(helper, [KUERY_RULE], state=state)

    processor.process()

    helper.api.work.initiate_work.assert_called_once()
    assert helper.send_stix2_bundle.call_count == 2
    helper.api.work.to_processed.assert_called_once()
    assert "in_error" not in helper.api.work.to_processed.call_args.kwargs


def test_collect_errors_fail_the_run_without_touching_the_state(helper):
    state = ConnectorState(deployed_rules={"gone-rule": GONE_INDICATOR})
    processor = _processor(helper, [], state=state)
    processor.client.iter_rules.side_effect = RuntimeError("Kibana down")
    with pytest.raises(RuntimeError):
        processor.process()
    assert processor.state.deployed_rules == {"gone-rule": GONE_INDICATOR}
    helper.send_stix2_bundle.assert_not_called()
