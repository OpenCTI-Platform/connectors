"""Tests for the Wiz issue payload models."""

from wiz_cloud.models import WizIssue, WizSourceRule


def test_source_rule_parses_its_security_sub_categories():
    rule = WizSourceRule.model_validate(
        {
            "name": "Confirmed Critical Severity Malware Found",
            "securitySubCategories": [
                {
                    "title": "Develop Capabilities: Malware",
                    "externalId": "TA0042-T1587.001",
                    "description": "Adversaries may develop malware.",
                    "category": {
                        "name": "Resource Development",
                        "description": "",
                        "framework": {
                            "name": "MITRE ATT&CK Matrix",
                            "project": None,
                        },
                    },
                }
            ],
        }
    )

    sub_category = rule.security_sub_categories[0]
    assert sub_category.external_id == "TA0042-T1587.001"
    assert sub_category.category.name == "Resource Development"
    assert sub_category.category.framework.name == "MITRE ATT&CK Matrix"
    assert sub_category.category.framework.project is None


def test_source_rule_without_sub_categories_still_parses():
    """MVP1 payloads selected only `name`; they must keep working."""
    rule = WizSourceRule.model_validate({"name": "Service account token accessed"})

    assert rule.security_sub_categories is None


def test_source_rule_tolerates_null_sub_categories():
    """Wiz returns null rather than [] for empty connections."""
    rule = WizSourceRule.model_validate(
        {"name": "A rule", "securitySubCategories": None}
    )

    assert rule.security_sub_categories is None


def test_an_issue_with_null_source_rules_is_not_dropped():
    """A null connection must not fail validation and lose the whole issue."""
    issue = WizIssue.model_validate(
        {
            "id": "issue-1",
            "type": "THREAT_DETECTION",
            "severity": "HIGH",
            "status": "IN_PROGRESS",
            "createdAt": "2026-08-24T10:00:00Z",
            "sourceRules": None,
        }
    )

    assert issue.source_rules == []
    assert issue.rule_name is None


def test_import_ttps_defaults_to_true():
    """TTPs ride along in the issues query, so they cost no extra call."""
    from wiz_cloud.settings import WizCloudConfig

    config = WizCloudConfig(
        api_url="https://api.us17.app.wiz.io/graphql",
        client_id="id",
        client_secret="secret",
    )

    assert config.import_ttps is True
