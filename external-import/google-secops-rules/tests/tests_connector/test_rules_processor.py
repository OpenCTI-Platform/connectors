"""End-to-end tests of a run: mapping, ATT&CK links, deployment reconciliation."""

from unittest.mock import MagicMock

import pytest
from conftest import SCHEMA_WITHOUT_DEPLOYED_ON, FakeCredentials, make_settings
from connector import ConnectorState, GoogleSecOpsRulesProcessor
from connector import rules_processor as rules_processor_module
from connector.attack_patterns import attack_pattern_id
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pycti import Identity, Indicator
from secops_client import GoogleSecOpsRulesClient
from secops_samples import (
    ARCHIVED_RULE,
    DEPLOYMENTS,
    DNS_RULE,
    POWERSHELL_RULE,
    POWERSHELL_TEXT,
    rule,
)

POWERSHELL_ID = "ru_e6abfcb5-1b85-41b0-b64c-695b3250436f"
DNS_ID = "ru_0b8ad7d2-2f0e-4c2a-9d1b-7d7c3a0f5e21"
ARCHIVED_ID = "ru_7c1d9e2a-0f3b-4b8e-a6c5-1e2d3f4a5b6c"
ARCHIVED_INDICATOR = Indicator.generate_id(ARCHIVED_RULE["text"])


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    """Skip parsing the sample private key: credentials are faked."""
    monkeypatch.setattr(
        rules_processor_module,
        "service_account_credentials",
        lambda **_: FakeCredentials(),
    )


def _processor(helper, rules, deployments=None, state=None, **config):
    processor = GoogleSecOpsRulesProcessor()
    processor.inject_dependencies(
        settings=make_settings({"google_secops_rules": config}),
        helper=helper,
        state=state or ConnectorState(),
    )
    processor.post_init()
    processor.client = MagicMock()
    processor.client.iter_rules.return_value = iter(rules)
    deployments = DEPLOYMENTS if deployments is None else deployments
    processor.client.rule_deployments.return_value = {
        deployment["name"].split("/rules/")[1].split("/")[0]: deployment
        for deployment in deployments
    }
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


def test_setup_builds_a_regional_client(helper):
    processor = GoogleSecOpsRulesProcessor()
    processor.inject_dependencies(
        settings=make_settings({"google_secops_rules": {"api_version": "v1"}}),
        helper=helper,
        state=ConnectorState(),
    )
    processor.post_init()
    assert isinstance(processor.client, GoogleSecOpsRulesClient)
    assert processor.client._base_url == "https://europe-chronicle.googleapis.com"
    assert processor.client._instance_path == (
        "/v1/projects/soc-project/locations/europe"
        "/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6"
    )
    platform = processor.builder.platform
    assert (platform.name, platform.security_platform_type) == ("Google SecOps", "SIEM")


def test_rules_become_yara_l_indicators_deployed_on_secops(helper):
    processor = _processor(helper, [POWERSHELL_RULE, DNS_RULE, ARCHIVED_RULE])
    (objects,) = _run(processor)

    (platform,) = [
        obj
        for obj in _of_type(objects, "identity")
        if obj.identity_class == "securityplatform"
    ]
    assert platform.security_platform_type == "SIEM"
    indicators = {obj.id: obj for obj in _of_type(objects, "indicator")}
    assert len(indicators) == 2
    powershell = indicators[Indicator.generate_id(POWERSHELL_TEXT)]
    assert powershell.pattern_type == "yara-l"
    assert powershell.pattern == POWERSHELL_TEXT
    assert powershell.name == "mitre_attack_T1059_001_encoded_powershell"
    assert powershell.x_opencti_rule_level == "high"
    assert powershell.x_opencti_rule_logsource == {
        "category": "process_creation",
        "product": "windows",
    }
    assert powershell.x_mitre_platforms == ["windows"]
    assert powershell.external_references[0].source_name == "Google SecOps"
    assert powershell.external_references[0].external_id == POWERSHELL_ID

    indicates = _of_type(objects, "relationship", "indicates")
    assert sorted((r.source_ref, r.target_ref) for r in indicates) == sorted(
        [
            (powershell.id, attack_pattern_id("T1059.001")),
            (powershell.id, attack_pattern_id("T1027")),
            (powershell.id, attack_pattern_id("T1140")),
            (Indicator.generate_id(DNS_RULE["text"]), attack_pattern_id("T1071.004")),
        ]
    )
    deployments = {
        r.external_id: r for r in _of_type(objects, "relationship", "deployed-on")
    }
    assert set(deployments) == {POWERSHELL_ID, DNS_ID}
    assert deployments[POWERSHELL_ID].deployment_status == "active"
    assert deployments[POWERSHELL_ID].deployed_at == "2026-01-02T03:04:05.123Z"
    assert deployments[POWERSHELL_ID].target_ref == platform.id
    assert deployments[DNS_ID].deployment_status == "deployed"
    assert set(processor.state.deployed_rules) == {POWERSHELL_ID, DNS_ID}

    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["skipped"] == {"archived": 1}
    assert summary["relationship"] == "deployed-on"
    fetched = helper.connector_logger.info.call_args_list[0].args[1]
    assert (fetched["rules"], fetched["live"], fetched["archived"]) == (3, 1, 1)


def test_platform_without_deployed_on_gets_related_to(helper):
    helper.api.query.return_value = SCHEMA_WITHOUT_DEPLOYED_ON
    (objects,) = _run(_processor(helper, [POWERSHELL_RULE, DNS_RULE]))
    assert _of_type(objects, "relationship", "deployed-on") == []
    descriptions = sorted(
        r.description for r in _of_type(objects, "relationship", "related-to")
    )
    assert descriptions == [
        f"Deployed on Google SecOps (status: active, rule id: {POWERSHELL_ID})",
        f"Deployed on Google SecOps (status: deployed, rule id: {DNS_ID})",
    ]
    warnings = [
        call
        for call in helper.connector_logger.warning.call_args_list
        if "deployed-on" in call.args[0]
    ]
    assert len(warnings) == 1


def test_rule_archived_since_the_previous_run_is_removed(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": ARCHIVED_INDICATOR, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={ARCHIVED_ID: ARCHIVED_INDICATOR})
    bundles = _run(_processor(helper, [POWERSHELL_RULE, ARCHIVED_RULE], state=state))
    assert len(bundles) == 2
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert (removed.source_ref, removed.external_id, removed.deployment_status) == (
        ARCHIVED_INDICATOR,
        ARCHIVED_ID,
        "removed",
    )
    assert removed.removed_at is not None


def test_edited_rule_text_removes_the_previous_indicator(helper):
    old_text = POWERSHELL_TEXT.replace("/-enc/", "/-encodedcommand/")
    old = Indicator.generate_id(old_text)
    helper.api.indicator.list.return_value = [
        {"standard_id": old, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={POWERSHELL_ID: old})
    bundles = _run(_processor(helper, [POWERSHELL_RULE], state=state))
    (removed,) = _of_type(bundles[1], "relationship", "deployed-on")
    assert (removed.source_ref, removed.external_id) == (old, POWERSHELL_ID)
    assert [obj.id for obj in _of_type(bundles[0], "indicator")] == [
        Indicator.generate_id(POWERSHELL_TEXT)
    ]


def test_rules_that_are_not_live_can_be_left_out(helper):
    processor = _processor(
        helper, [POWERSHELL_RULE, DNS_RULE], import_disabled_rules=False
    )
    (objects,) = _run(processor)
    assert [
        r.external_id for r in _of_type(objects, "relationship", "deployed-on")
    ] == [POWERSHELL_ID]
    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["skipped"] == {"disabled": 1}


def test_rule_without_deployment_is_deployed_not_active(helper):
    (objects,) = _run(_processor(helper, [POWERSHELL_RULE], deployments=[]))
    (deployment,) = _of_type(objects, "relationship", "deployed-on")
    assert deployment.deployment_status == "deployed"


def test_known_techniques_are_referenced_not_recreated(helper):
    helper.api.attack_pattern.list.return_value = [
        {"standard_id": attack_pattern_id("T1059.001"), "x_opencti_stix_ids": []}
    ]
    (objects,) = _run(_processor(helper, [POWERSHELL_RULE]))
    created = {obj.x_mitre_id for obj in _of_type(objects, "attack-pattern")}
    assert created == {"T1027", "T1140"}


def test_invalid_rule_does_not_stop_the_run(helper):
    broken = rule(POWERSHELL_RULE, createTime="not a date")
    (objects,) = _run(_processor(helper, [broken, DNS_RULE]))
    assert [
        r.external_id for r in _of_type(objects, "relationship", "deployed-on")
    ] == [DNS_ID]
    summary = helper.connector_logger.info.call_args_list[-1].args[1]
    assert summary["skipped"] == {"invalid": 1}


def test_collect_errors_fail_the_run_without_touching_the_state(helper):
    state = ConnectorState(deployed_rules={ARCHIVED_ID: ARCHIVED_INDICATOR})
    processor = _processor(helper, [], state=state)
    processor.client.rule_deployments.side_effect = RuntimeError("SecOps down")
    with pytest.raises(RuntimeError):
        processor.process()
    assert processor.state.deployed_rules == {ARCHIVED_ID: ARCHIVED_INDICATOR}


def test_invalid_private_key_fails_at_startup(helper, monkeypatch):
    monkeypatch.undo()
    processor = GoogleSecOpsRulesProcessor()
    processor.inject_dependencies(
        settings=make_settings(), helper=helper, state=ConnectorState()
    )
    with pytest.raises(ValueError, match="Invalid Google service account private key"):
        processor.post_init()


def test_real_private_key_builds_service_account_credentials(helper, monkeypatch):
    monkeypatch.undo()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    processor = GoogleSecOpsRulesProcessor()
    processor.inject_dependencies(
        settings=make_settings(
            {
                "google_secops_rules": {
                    "private_key": pem.replace("\n", "\\n"),
                    "private_key_id": "0123abcd",
                }
            }
        ),
        helper=helper,
        state=ConnectorState(),
    )
    processor.post_init()
    credentials = processor.client._credentials
    assert credentials.service_account_email == (
        "opencti@soc-project.iam.gserviceaccount.com"
    )
    assert credentials.project_id == "soc-project"
    assert credentials.signer_email == credentials.service_account_email
    assert credentials.signer.key_id == "0123abcd"
    assert credentials.scopes == ["https://www.googleapis.com/auth/cloud-platform"]


EXISTING_PLATFORM = Identity.generate_id("SOC SecOps", "securityplatform")
EXISTING = {
    "entity_type": "SecurityPlatform",
    "standard_id": EXISTING_PLATFORM,
    "name": "SOC SecOps",
}


def test_configured_platform_id_targets_the_existing_platform(helper):
    helper.api.identity.read.return_value = EXISTING
    processor = _processor(
        helper, [POWERSHELL_RULE], platform_id="internal-platform-id"
    )
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
    processor = _processor(helper, [POWERSHELL_RULE], platform_id="unknown")
    with pytest.raises(ValueError, match="is not a Security Platform"):
        _run(processor)


UNMAPPED_GONE_KEY = "gone-rule"
UNMAPPED_GONE_INDICATOR = Indicator.generate_id("gone rule pattern")


def test_unmapped_rule_keeps_the_deployments_missing_from_the_run(helper):
    helper.api.indicator.list.return_value = [
        {"standard_id": UNMAPPED_GONE_INDICATOR, "x_opencti_stix_ids": []}
    ]
    state = ConnectorState(deployed_rules={UNMAPPED_GONE_KEY: UNMAPPED_GONE_INDICATOR})
    processor = _processor(helper, [POWERSHELL_RULE, DNS_RULE], state=state)
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
