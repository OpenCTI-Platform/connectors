from unittest.mock import MagicMock, patch

from rflib.pyrf import RecordedFutureApiClient

PLACEHOLDER_RULE_ID = "Fake-Id-Playbook-Alert"


def _response(payload):
    response = MagicMock()
    response.headers = {"Content-Type": "application/json"}
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def _rules_page(total, rule_ids):
    return {
        "data": {
            "results": [
                {
                    "id": rule_id,
                    "title": f"Rule {rule_id}",
                    "priority": True,
                    "intelligence_goals": [{"name": "Brand Monitoring"}],
                }
                for rule_id in rule_ids
            ]
        },
        "counts": {"total": total, "returned": len(rule_ids)},
    }


def _client():
    return RecordedFutureApiClient(x_rf_token="token", helper=MagicMock())


def test_placeholder_rule_added_once_across_pages():
    """Three pages of rules yield each real rule once and one placeholder rule."""
    client = _client()
    pages = [
        _response(_rules_page(5, ["r1", "r2"])),
        _response(_rules_page(5, ["r3", "r4"])),
        _response(_rules_page(5, ["r5"])),
    ]

    with patch("rflib.pyrf.requests.get", side_effect=pages) as mock_get:
        client.get_prioritedrule_ids(limit=2)

    assert mock_get.call_count == 3
    rule_ids = [rule.rule_id for rule in client.priorited_rules]
    assert rule_ids.count(PLACEHOLDER_RULE_ID) == 1
    assert [r for r in rule_ids if r != PLACEHOLDER_RULE_ID] == [
        "r1",
        "r2",
        "r3",
        "r4",
        "r5",
    ]


def test_placeholder_rule_kept_for_single_page():
    """A single page still provides the placeholder rule for its vocabulary."""
    client = _client()

    with patch(
        "rflib.pyrf.requests.get",
        return_value=_response(_rules_page(1, ["r1"])),
    ):
        client.get_prioritedrule_ids(limit=100)

    placeholders = [
        rule for rule in client.priorited_rules if rule.rule_id == PLACEHOLDER_RULE_ID
    ]
    assert len(placeholders) == 1
    assert placeholders[0].rule_intelligence_goal == "TYPOSQUATTING DETECTION"


def test_missing_counts_stops_pagination():
    """A page without the counts field is logged once and ends the loop."""
    client = _client()

    with patch(
        "rflib.pyrf.requests.get",
        return_value=_response({"data": {"results": []}}),
    ) as mock_get:
        client.get_prioritedrule_ids(limit=100)

    assert mock_get.call_count == 1
    client.helper.connector_logger.error.assert_called_once_with(
        "Response does not contain mandatory <counts> field"
    )
