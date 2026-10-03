"""End-to-end tests of a run: mapping, ATT&CK links, deployment reconciliation."""

from unittest.mock import MagicMock

import pytest
from conftest import SCHEMA_WITHOUT_DEPLOYED_ON, make_settings
from connector import ConnectorState, SplunkRulesProcessor
from connector.attack_patterns import attack_pattern_id
from connector.deployed_rules_processor import RULES_PER_BUNDLE
from pycti import Identity, Indicator
from splunk_samples import CORRELATION_SEARCH, REPORT, SCHEDULED_ALERT, entry

EXISTING_PLATFORM = Identity.generate_id("Splunk splunk-prod-01", "securityplatform")
GONE_INDICATOR = Indicator.generate_id("index=old | stats count")
GONE_KEY = "search/admin/Old detection"
CORRELATION_KEY = (
    "DA-ESS-ContentUpdate/nobody/ESCU - Windows PowerShell Encoded Command - Rule"
)


def _processor(helper, entries, state=None, **config) -> SplunkRulesProcessor:
    processor = SplunkRulesProcessor()
    processor.inject_dependencies(
        settings=make_settings({"splunk_saved_searches": config}),
        helper=helper,
        state=state or ConnectorState(),
    )
    processor.post_init()
    real_client = processor.client
    processor.client = MagicMock()
    processor.client.iter_saved_searches.return_value = iter(entries)
    processor.client.saved_search_url = real_client.saved_search_url
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
    return Indicator.generate_id(raw["content"]["search"])


def test_saved_searches_become_spl_indicators(helper):
    processor = _processor(
        helper,
        [CORRELATION_SEARCH, SCHEDULED_ALERT, REPORT],
        web_url="https://splunk.example.com:8000",
    )
    (objects,) = _run(processor)
    indicators = {obj.id: obj for obj in _of_type(objects, "indicator")}
    assert set(indicators) == {
        _indicator_id(CORRELATION_SEARCH),
        _indicator_id(SCHEDULED_ALERT),
    }
    correlation = indicators[_indicator_id(CORRELATION_SEARCH)]
    assert correlation.pattern_type == "spl"
    assert correlation.x_opencti_rule_level == "high"
    assert correlation.external_references[0].url == (
        "https://splunk.example.com:8000/app/DA-ESS-ContentUpdate/search?s="
        "%2FservicesNS%2Fnobody%2FDA-ESS-ContentUpdate%2Fsaved%2Fsearches%2F"
        "ESCU%2520-%2520Windows%2520PowerShell%2520Encoded%2520Command%2520-%2520Rule"
    )

    indicates = _of_type(objects, "relationship", "indicates")
    assert sorted((r.source_ref, r.target_ref) for r in indicates) == sorted(
        [
            (_indicator_id(CORRELATION_SEARCH), attack_pattern_id("T1059.001")),
            (_indicator_id(CORRELATION_SEARCH), attack_pattern_id("T1027")),
            (_indicator_id(SCHEDULED_ALERT), attack_pattern_id("T1110")),
            (_indicator_id(SCHEDULED_ALERT), attack_pattern_id("T1110.003")),
        ]
    )
    deployments = {
        r.source_ref: r for r in _of_type(objects, "relationship", "deployed-on")
    }
    assert deployments[_indicator_id(CORRELATION_SEARCH)].deployment_status == "active"
    assert deployments[_indicator_id(CORRELATION_SEARCH)].external_id == (
        CORRELATION_SEARCH["name"]
    )
    # Splunk exposes no creation time.
    assert "deployed_at" not in deployments[_indicator_id(CORRELATION_SEARCH)]
    assert deployments[_indicator_id(SCHEDULED_ALERT)].deployment_status == "deployed"
    assert processor.state.deployed_rules == {
        CORRELATION_KEY: _indicator_id(CORRELATION_SEARCH),
        "search/admin/Brute force on VPN (T1110)": _indicator_id(SCHEDULED_ALERT),
    }
    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["skipped"] == {"out_of_scope": 1}


def test_correlation_scope_only(helper):
    processor = _processor(
        helper,
        [CORRELATION_SEARCH, SCHEDULED_ALERT],
        search_scope="correlation_searches",
    )
    (objects,) = _run(processor)
    assert [i.id for i in _of_type(objects, "indicator")] == [
        _indicator_id(CORRELATION_SEARCH)
    ]
    assert "url" not in _of_type(objects, "indicator")[0].external_references[0]


def test_platform_without_deployed_on_gets_related_to(helper):
    helper.api.query.return_value = SCHEMA_WITHOUT_DEPLOYED_ON
    (objects,) = _run(_processor(helper, [CORRELATION_SEARCH]))
    (related,) = _of_type(objects, "relationship", "related-to")
    assert related.description == (
        "Deployed on Splunk (status: active, rule id: "
        "ESCU - Windows PowerShell Encoded Command - Rule)"
    )


def _security_platforms(objects):
    return [
        obj
        for obj in _of_type(objects, "identity")
        if obj.identity_class == "securityplatform"
    ]


def test_configured_platform_id_targets_the_existing_platform(helper):
    helper.api.identity.read.return_value = {
        "entity_type": "SecurityPlatform",
        "standard_id": EXISTING_PLATFORM,
        "name": "Splunk splunk-prod-01",
    }
    processor = _processor(
        helper, [CORRELATION_SEARCH], platform_id="2b8f1d4e-internal-id"
    )
    (objects,) = _run(processor)
    helper.api.identity.read.assert_called_once_with(id="2b8f1d4e-internal-id")
    (deployment,) = _of_type(objects, "relationship", "deployed-on")
    assert deployment.target_ref == EXISTING_PLATFORM
    # The platform another integration created is referenced, never rewritten.
    assert _security_platforms(objects) == []
    assert processor.state.platform_id == EXISTING_PLATFORM


def test_configured_platform_id_names_the_platform_in_related_to(helper):
    helper.api.query.return_value = SCHEMA_WITHOUT_DEPLOYED_ON
    helper.api.identity.read.return_value = {
        "entity_type": "SecurityPlatform",
        "standard_id": EXISTING_PLATFORM,
        "name": "Splunk splunk-prod-01",
    }
    (objects,) = _run(
        _processor(helper, [CORRELATION_SEARCH], platform_id=EXISTING_PLATFORM)
    )
    (related,) = _of_type(objects, "relationship", "related-to")
    assert related.target_ref == EXISTING_PLATFORM
    assert related.description.startswith("Deployed on Splunk splunk-prod-01 ")


@pytest.mark.parametrize(
    "found",
    [None, {"entity_type": "System", "standard_id": "identity--x", "name": "SOC"}],
)
def test_configured_platform_id_must_be_a_security_platform(helper, found):
    helper.api.identity.read.return_value = found
    processor = _processor(helper, [CORRELATION_SEARCH], platform_id="unknown")
    with pytest.raises(ValueError, match="is not a Security Platform"):
        _run(processor)


def test_switching_to_a_configured_platform_moves_the_deployments(helper):
    helper.api.identity.read.return_value = {
        "entity_type": "SecurityPlatform",
        "standard_id": EXISTING_PLATFORM,
        "name": "Splunk splunk-prod-01",
    }
    helper.api.indicator.list.return_value = [
        {"standard_id": _indicator_id(CORRELATION_SEARCH), "x_opencti_stix_ids": []}
    ]
    named_platform = Identity.generate_id("Splunk", "securityplatform")
    state = ConnectorState(
        deployed_rules={CORRELATION_KEY: _indicator_id(CORRELATION_SEARCH)},
        platform_id=named_platform,
    )
    processor = _processor(
        helper, [CORRELATION_SEARCH], state=state, platform_id=EXISTING_PLATFORM
    )
    deployed, removed = _run(processor)
    (current,) = _of_type(deployed, "relationship", "deployed-on")
    assert (current.target_ref, current.deployment_status) == (
        EXISTING_PLATFORM,
        "active",
    )
    (former,) = _of_type(removed, "relationship", "deployed-on")
    assert (former.target_ref, former.deployment_status) == (
        named_platform,
        "removed",
    )
    assert processor.state.platform_id == EXISTING_PLATFORM


def test_unmapped_search_keeps_the_deployments_missing_from_the_run(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": GONE_INDICATOR, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={GONE_KEY: GONE_INDICATOR})
    processor = _processor(helper, [CORRELATION_SEARCH, SCHEDULED_ALERT], state=state)
    map_rule = processor.to_detection_rule

    def to_detection_rule(raw_rule):
        if raw_rule is SCHEDULED_ALERT:
            raise ValueError("unexpected payload shape")
        return map_rule(raw_rule)

    processor.to_detection_rule = to_detection_rule
    bundles = _run(processor)
    deployments = [
        deployment
        for bundle in bundles
        for deployment in _of_type(bundle, "relationship", "deployed-on")
    ]
    # The unmapped search cannot be told apart from the gone one: nothing is removed
    assert [d.deployment_status for d in deployments] == ["active"]
    assert processor.state.deployed_rules == {
        GONE_KEY: GONE_INDICATOR,
        CORRELATION_KEY: _indicator_id(CORRELATION_SEARCH),
    }
    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["complete"] is False
    assert summary["skipped"] == {"invalid": 1}


def test_removed_saved_search_carries_its_name(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": GONE_INDICATOR, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={GONE_KEY: GONE_INDICATOR})
    processor = _processor(helper, [CORRELATION_SEARCH], state=state)
    bundles = _run(processor)
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert removed.source_ref == GONE_INDICATOR
    assert removed.external_id == "Old detection"
    assert removed.deployment_status == "removed"


def test_disabled_saved_searches_can_be_left_out(helper):
    processor = _processor(
        helper, [CORRELATION_SEARCH, SCHEDULED_ALERT], import_disabled_rules=False
    )
    (objects,) = _run(processor)
    assert len(_of_type(objects, "indicator")) == 1


def test_large_sets_are_split_into_bundles(helper):
    entries = [
        {**entry(CORRELATION_SEARCH, search=f"index=main | head {i}"), "name": f"s{i}"}
        for i in range(RULES_PER_BUNDLE + 3)
    ]
    bundles = _run(_processor(helper, entries))
    assert [len(_of_type(b, "indicator")) for b in bundles] == [RULES_PER_BUNDLE, 3]


def test_collect_errors_fail_the_run_without_touching_the_state(helper):
    state = ConnectorState(deployed_rules={GONE_KEY: GONE_INDICATOR})
    processor = _processor(helper, [], state=state)
    processor.client.iter_saved_searches.side_effect = RuntimeError("Splunk down")
    with pytest.raises(RuntimeError):
        processor.process()
    assert processor.state.deployed_rules == {GONE_KEY: GONE_INDICATOR}
