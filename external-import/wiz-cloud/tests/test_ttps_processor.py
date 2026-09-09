"""Tests for the Wiz TTPs processor."""

from connectors_sdk.models import AttackPattern, Relationship
from wiz_cloud.models import WizIssue


def _issue(issue_data: dict, sub_categories: list[dict]) -> WizIssue:
    """Build an issue whose single source rule carries the given entries.

    Args:
        issue_data: A raw issue fixture.
        sub_categories: The securitySubCategories of its source rule.

    Returns:
        The parsed issue.
    """
    return WizIssue.model_validate(
        {
            **issue_data,
            "sourceRules": [
                {"name": "A rule", "securitySubCategories": sub_categories}
            ],
        }
    )


def _of_type(objects: list, kind: type) -> list:
    return [item for item in objects if isinstance(item, kind)]


def test_converts_a_mitre_sub_category(
    ttps_processor, incident, signin_issue_data, mitre_sub_category
):
    issue = _issue(signin_issue_data, [mitre_sub_category])

    objects = ttps_processor.objects_for_issue(issue, incident)

    patterns = _of_type(objects, AttackPattern)
    assert len(patterns) == 1
    assert patterns[0].name == "Develop Capabilities: Malware"
    # The TA0042 tactic prefix must be dropped, or the pattern never merges
    # with the T1587.001 the MITRE connector already imported.
    assert patterns[0].mitre_id == "T1587.001"


def test_emits_a_uses_relationship_from_the_incident(
    ttps_processor, incident, signin_issue_data, mitre_sub_category
):
    issue = _issue(signin_issue_data, [mitre_sub_category])

    objects = ttps_processor.objects_for_issue(issue, incident)

    relationships = _of_type(objects, Relationship)
    assert len(relationships) == 1
    assert relationships[0].type == "uses"
    assert relationships[0].source is incident
    assert relationships[0].target is _of_type(objects, AttackPattern)[0]


def test_ignores_the_wiz_proprietary_frameworks(
    ttps_processor, incident, signin_issue_data, wiz_sub_category
):
    """Their externalIds are not MITRE ids and would pollute x_mitre_id."""
    issue = _issue(signin_issue_data, [wiz_sub_category])

    objects = ttps_processor.objects_for_issue(issue, incident)

    assert objects == []


def test_keeps_only_the_mitre_entries_of_a_mixed_rule(
    ttps_processor, incident, signin_issue_data, mitre_sub_category, wiz_sub_category
):
    issue = _issue(signin_issue_data, [mitre_sub_category, wiz_sub_category])

    objects = ttps_processor.objects_for_issue(issue, incident)

    assert len(_of_type(objects, AttackPattern)) == 1


def test_matches_the_framework_case_insensitively(
    ttps_processor, incident, signin_issue_data, mitre_sub_category
):
    """The framework name is free text from Wiz."""
    mitre_sub_category["category"]["framework"]["name"] = "  MITRE ATT&CK matrix "
    issue = _issue(signin_issue_data, [mitre_sub_category])

    objects = ttps_processor.objects_for_issue(issue, incident)

    assert len(_of_type(objects, AttackPattern)) == 1


def test_accepts_the_cloud_matrix(
    ttps_processor, incident, signin_issue_data, mitre_sub_category
):
    mitre_sub_category["category"]["framework"]["name"] = "MITRE ATT&CK Cloud Matrix"
    issue = _issue(signin_issue_data, [mitre_sub_category])

    objects = ttps_processor.objects_for_issue(issue, incident)

    assert len(_of_type(objects, AttackPattern)) == 1


def test_skips_an_external_id_without_a_technique(
    ttps_processor, incident, signin_issue_data, mitre_sub_category
):
    mitre_sub_category["externalId"] = "TA0042"
    issue = _issue(signin_issue_data, [mitre_sub_category])

    objects = ttps_processor.objects_for_issue(issue, incident)

    assert objects == []
    assert ttps_processor._logger.debug.called


def test_falls_back_to_the_technique_id_when_the_title_is_blank(
    ttps_processor, incident, signin_issue_data, mitre_sub_category
):
    """AttackPattern.name has min_length=1, so a blank title cannot be used."""
    mitre_sub_category["title"] = ""
    issue = _issue(signin_issue_data, [mitre_sub_category])

    objects = ttps_processor.objects_for_issue(issue, incident)

    assert _of_type(objects, AttackPattern)[0].name == "T1587.001"


def test_returns_nothing_for_an_issue_without_source_rules(
    ttps_processor, incident, signin_issue_data
):
    issue = WizIssue.model_validate({**signin_issue_data, "sourceRules": []})

    assert ttps_processor.objects_for_issue(issue, incident) == []


def test_derives_the_kill_chain_phase_from_the_tactic(
    ttps_processor, incident, signin_issue_data, mitre_sub_category
):
    issue = _issue(signin_issue_data, [mitre_sub_category])

    pattern = _of_type(
        ttps_processor.objects_for_issue(issue, incident), AttackPattern
    )[0]

    assert len(pattern.kill_chain_phases) == 1
    assert pattern.kill_chain_phases[0].chain_name == "mitre-attack"
    assert pattern.kill_chain_phases[0].phase_name == "resource-development"


def test_one_technique_under_two_tactics_becomes_one_pattern(
    ttps_processor, incident, signin_issue_data, mitre_sub_category
):
    """ATT&CK techniques legitimately belong to several tactics."""
    second = {
        **mitre_sub_category,
        "externalId": "TA0002-T1587.001",
        "category": {
            **mitre_sub_category["category"],
            "name": "Execution",
        },
    }
    issue = _issue(signin_issue_data, [mitre_sub_category, second])

    objects = ttps_processor.objects_for_issue(issue, incident)

    patterns = _of_type(objects, AttackPattern)
    assert len(patterns) == 1
    assert [phase.phase_name for phase in patterns[0].kill_chain_phases] == [
        "resource-development",
        "execution",
    ]
    assert len(_of_type(objects, Relationship)) == 1


def test_a_technique_repeated_across_rules_is_emitted_once(
    ttps_processor, incident, signin_issue_data, mitre_sub_category
):
    issue = WizIssue.model_validate(
        {
            **signin_issue_data,
            "sourceRules": [
                {"name": "Rule A", "securitySubCategories": [mitre_sub_category]},
                {"name": "Rule B", "securitySubCategories": [mitre_sub_category]},
            ],
        }
    )

    objects = ttps_processor.objects_for_issue(issue, incident)

    assert len(_of_type(objects, AttackPattern)) == 1


def test_a_category_without_a_name_yields_no_phase(
    ttps_processor, incident, signin_issue_data, mitre_sub_category
):
    mitre_sub_category["category"]["name"] = ""
    issue = _issue(signin_issue_data, [mitre_sub_category])

    pattern = _of_type(
        ttps_processor.objects_for_issue(issue, incident), AttackPattern
    )[0]

    assert pattern.kill_chain_phases is None
