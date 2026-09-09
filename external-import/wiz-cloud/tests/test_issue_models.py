"""Tests for the Wiz issue payload models."""

from wiz_cloud.models import WizSourceRule


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
