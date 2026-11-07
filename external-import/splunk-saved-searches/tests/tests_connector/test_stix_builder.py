from datetime import datetime, timedelta, timezone

import pytest
from connector.attack_patterns import attack_pattern_id
from connector.detection_rule import DetectionRule
from connector.stix_builder import RuleStixBuilder, stix_timestamp
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from pycti import Identity, Indicator, StixCoreRelationship

RUN_TIME = datetime(2026, 10, 3, 8, 30, 15, 123456, tzinfo=timezone.utc)
CREATED = datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
INDICATOR_ID = "indicator--5b3d4a2c-0000-4000-8000-000000000001"


@pytest.fixture
def builder() -> RuleStixBuilder:
    return RuleStixBuilder(
        author=OrganizationAuthor(name="Vendor"),
        marking=TLPMarking(level="amber"),
        platform_name="My SIEM",
        platform_type="SIEM",
        platform_description="The SIEM.",
        source_name="My SIEM",
    )


def _rule(**overrides) -> DetectionRule:
    values = {
        "external_id": "rule-1",
        "name": "Encoded PowerShell",
        "description": "Detects encoded PowerShell.",
        "pattern": 'process.name:"powershell.exe"',
        "pattern_type": "kuery",
        "enabled": True,
    }
    values.update(overrides)
    return DetectionRule(**values)


def test_stix_timestamp():
    assert stix_timestamp(RUN_TIME) == "2026-10-03T08:30:15.123Z"
    assert stix_timestamp(datetime(2026, 1, 1)) == "2026-01-01T00:00:00.000Z"
    plus_two = datetime(2026, 1, 1, 2, tzinfo=timezone(timedelta(hours=2)))
    assert stix_timestamp(plus_two) == "2026-01-01T00:00:00.000Z"


def test_security_platform_identity(builder):
    platform = builder.platform
    assert platform.id == Identity.generate_id("My SIEM", "securityplatform")
    assert platform.identity_class == "securityplatform"
    assert platform.security_platform_type == "SIEM"
    assert platform.created_by_ref == builder.author.id
    assert builder.common_objects == [builder.author, builder.marking, platform]


def test_existing_platform_is_referenced_not_rewritten(builder):
    existing = Identity.generate_id("SOC SIEM", "securityplatform")
    builder.target_existing_platform(existing, "SOC SIEM")
    assert builder.common_objects == [builder.author, builder.marking]
    deployed = builder.deployment(INDICATOR_ID, "rule-1", "active", RUN_TIME, True)
    assert deployed.target_ref == existing
    related = builder.deployment(INDICATOR_ID, "rule-1", "active", RUN_TIME, False)
    assert related.target_ref == existing
    assert related.description.startswith("Deployed on SOC SIEM ")


def test_indicator_carries_rule_metadata(builder):
    rule = _rule(
        level="high",
        logsource={"product": "windows"},
        platforms=["windows"],
        created_at=CREATED,
        url="https://siem.example.com/rules/rule-1",
    )
    indicator = builder.indicator(rule, RUN_TIME)
    assert indicator.id == Indicator.generate_id(rule.pattern)
    assert indicator.pattern_type == "kuery"
    assert indicator.name == "Encoded PowerShell"
    assert indicator.valid_from == CREATED
    assert indicator.x_opencti_rule_level == "high"
    assert indicator.x_opencti_rule_logsource == {"product": "windows"}
    assert indicator.x_mitre_platforms == ["windows"]
    assert "x_opencti_rule_status" not in indicator
    assert indicator.created_by_ref == builder.author.id
    assert indicator.object_marking_refs == [builder.marking.id]
    reference = indicator.external_references[0]
    assert reference.source_name == "My SIEM"
    assert reference.external_id == "rule-1"
    assert reference.url == "https://siem.example.com/rules/rule-1"


def test_indicator_without_optional_metadata(builder):
    indicator = builder.indicator(_rule(), RUN_TIME)
    for name in (
        "x_opencti_rule_level",
        "x_opencti_rule_logsource",
        "x_mitre_platforms",
    ):
        assert name not in indicator
    assert indicator.valid_from == RUN_TIME
    assert "url" not in indicator.external_references[0]


def test_indicator_valid_from_falls_back_to_the_last_modification(builder):
    indicator = builder.indicator(_rule(modified_at=CREATED), RUN_TIME)
    assert indicator.valid_from == CREATED


def test_indicates(builder):
    target = attack_pattern_id("T1059")
    relationship = builder.indicates(INDICATOR_ID, target)
    assert relationship.relationship_type == "indicates"
    assert relationship.source_ref == INDICATOR_ID
    assert relationship.target_ref == target
    assert relationship.id == StixCoreRelationship.generate_id(
        "indicates", INDICATOR_ID, target
    )
    assert relationship.created_by_ref == builder.author.id
    assert relationship.object_marking_refs == [builder.marking.id]


def test_deployed_on(builder):
    relationship = builder.deployment(
        indicator_id=INDICATOR_ID,
        external_id="rule-1",
        status="active",
        last_sync_at=RUN_TIME,
        deployed_on_supported=True,
        deployed_at=CREATED,
    )
    assert relationship.relationship_type == "deployed-on"
    assert relationship.id == StixCoreRelationship.generate_id(
        "deployed-on", INDICATOR_ID, builder.platform.id
    )
    assert relationship.source_ref == INDICATOR_ID
    assert relationship.target_ref == builder.platform.id
    assert relationship.deployment_status == "active"
    assert relationship.external_id == "rule-1"
    assert relationship.deployed_at == "2025-01-02T03:04:05.000Z"
    assert relationship.last_sync_at == "2026-10-03T08:30:15.123Z"
    assert "removed_at" not in relationship
    assert "start_time" not in relationship


def test_removed_deployment(builder):
    relationship = builder.deployment(
        indicator_id=INDICATOR_ID,
        external_id="rule-1",
        status="removed",
        last_sync_at=RUN_TIME,
        deployed_on_supported=True,
        removed_at=RUN_TIME,
    )
    assert relationship.deployment_status == "removed"
    assert relationship.removed_at == "2026-10-03T08:30:15.123Z"
    assert "deployed_at" not in relationship


def test_related_to_fallback(builder):
    relationship = builder.deployment(
        indicator_id=INDICATOR_ID,
        external_id="rule-1",
        status="deployed",
        last_sync_at=RUN_TIME,
        deployed_on_supported=False,
        deployed_at=CREATED,
    )
    assert relationship.relationship_type == "related-to"
    assert relationship.id == StixCoreRelationship.generate_id(
        "related-to", INDICATOR_ID, builder.platform.id
    )
    assert relationship.target_ref == builder.platform.id
    assert relationship.description == (
        "Deployed on My SIEM (status: deployed, rule id: rule-1)"
    )
    assert "deployment_status" not in relationship
