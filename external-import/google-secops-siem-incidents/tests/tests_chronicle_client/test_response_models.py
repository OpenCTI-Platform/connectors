"""RED tests — Chronicle alert response structure parsing.

Tests that Chronicle alert JSON payloads are parsed into Pydantic v2 models
with camelCase aliases and correct defaults.
"""

from typing import Any

from google_secops_siem_incidents.models.rule_alert_response import (
    RuleAlertResponse,
)

from tests.tests_chronicle_client.factories import (
    AlertFactory,
    OutcomeFactory,
    RuleAlertFactory,
    RuleAlertResponseFactory,
    RuleMetadataFactory,
    RulePropertiesFactory,
    StringSeqFactory,
)


# ---------------------------------------------------------------------------
# Scenario: Full alert response is parsed with all fields
# ---------------------------------------------------------------------------
def test_full_alert_response_is_parsed_with_all_fields():
    """A complete Chronicle alert payload parses into the expected structure."""

    def _given_full_response():
        return RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(
                    rule_metadata=RuleMetadataFactory.build(rule_id="ru_abc-123"),
                    alerts=[
                        AlertFactory.build(detection_timestamp="2025-01-15T08:30:00Z")
                    ],
                )
            ],
        )

    def _then_parsed_structure_is_correct(response: RuleAlertResponse):
        assert len(response.rule_alerts) == 1
        assert response.rule_alerts[0].rule_metadata.rule_id == "ru_abc-123"
        assert (
            response.rule_alerts[0].alerts[0].detection_timestamp
            == "2025-01-15T08:30:00Z"
        )

    response = _given_full_response()
    _then_parsed_structure_is_correct(response)


# ---------------------------------------------------------------------------
# Scenario: tooManyAlerts defaults to false when not present
# ---------------------------------------------------------------------------
def test_too_many_alerts_defaults_to_false():
    """When 'tooManyAlerts' is absent from the payload, the value is False."""

    def _given_response_without_flag() -> dict[str, Any]:
        return {"ruleAlerts": []}

    def _then_too_many_alerts_is_false(response: RuleAlertResponse):
        assert response.too_many_alerts is False

    response = RuleAlertResponse.model_validate(_given_response_without_flag())
    _then_too_many_alerts_is_false(response)


# ---------------------------------------------------------------------------
# Scenario: Optional result fields default to empty when absent
# ---------------------------------------------------------------------------
def test_optional_result_fields_default_to_empty():
    """Alert missing resultEvents/resultEntityEvents gets empty dicts."""

    def _given_alert_without_result_fields() -> dict[str, Any]:
        alert = AlertFactory.build().model_dump(by_alias=True)
        alert.pop("resultEvents", None)
        alert.pop("resultEntityEvents", None)
        rule_alert = RuleAlertFactory.build(
            rule_metadata=RuleMetadataFactory.build(),
        ).model_dump(by_alias=True)
        rule_alert["alerts"] = [alert]
        return {"ruleAlerts": [rule_alert], "tooManyAlerts": False}

    def _then_result_fields_are_empty(response: RuleAlertResponse):
        a = response.rule_alerts[0].alerts[0]
        assert a.result_events == {}
        assert a.result_entity_events == {}

    response = RuleAlertResponse.model_validate(_given_alert_without_result_fields())
    _then_result_fields_are_empty(response)


# ---------------------------------------------------------------------------
# Scenario: Alert outcomes with sequence values are parsed correctly
# ---------------------------------------------------------------------------
def test_alert_outcomes_with_sequence_values():
    """An outcome with a string sequence parses correctly."""

    def _given_response_with_seq_outcome():
        seq = StringSeqFactory.build(string_vals=["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        outcome = OutcomeFactory.build(name="ips", string_seq=seq)
        return RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(alerts=[AlertFactory.build(outcomes=[outcome])])
            ]
        )

    def _then_outcome_has_string_sequence(response: RuleAlertResponse):
        outcome = response.rule_alerts[0].alerts[0].outcomes[0]
        assert outcome.string_seq is not None
        assert len(outcome.string_seq.string_vals) == 3
        assert outcome.string_seq.string_vals[0] == "10.0.0.1"

    response = _given_response_with_seq_outcome()
    _then_outcome_has_string_sequence(response)


# ---------------------------------------------------------------------------
# Scenario: Alert fields carry name and value pairs
# ---------------------------------------------------------------------------
def test_alert_fields_carry_name_and_value_pairs():
    """Alert fields parse into AlertField with name, path, and value."""

    from tests.tests_chronicle_client.factories import AlertFieldFactory

    def _given_response_with_fields():
        fields = [
            AlertFieldFactory.build(
                name="hostname",
                field_path="principal.hostname",
                string_val="workstation-01",
            ),
            AlertFieldFactory.build(
                name="ip_address",
                field_path="principal.ip",
                string_val="192.168.1.100",
            ),
        ]
        return RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(alerts=[AlertFactory.build(fields=fields)])
            ]
        )

    def _then_alert_has_correct_fields(response: RuleAlertResponse):
        fields = response.rule_alerts[0].alerts[0].fields
        assert len(fields) == 2
        assert fields[0].name == "hostname"
        assert fields[0].string_val == "workstation-01"

    response = _given_response_with_fields()
    _then_alert_has_correct_fields(response)


# ---------------------------------------------------------------------------
# Scenario: Response with camelCase field names is parsed using aliases
# ---------------------------------------------------------------------------
def test_camel_case_field_names_are_parsed_using_aliases():
    """camelCase keys from Chronicle API are recognised via Field aliases."""

    def _given_camel_case_payload() -> dict[str, Any]:
        return {
            "ruleAlerts": [
                {
                    "ruleMetadata": {
                        "ruleId": "ru_cc",
                        "properties": {"name": "CC", "text": "t", "metadata": {}},
                    },
                    "alerts": [],
                }
            ],
            "tooManyAlerts": True,
        }

    def _then_aliased_fields_are_recognised(response: RuleAlertResponse):
        assert len(response.rule_alerts) == 1
        assert response.too_many_alerts is True

    response = RuleAlertResponse.model_validate(_given_camel_case_payload())
    _then_aliased_fields_are_recognised(response)


# ---------------------------------------------------------------------------
# Scenario: Response fields can be assigned using snake_case names
# ---------------------------------------------------------------------------
def test_snake_case_field_names_are_accepted():
    """snake_case field names work via populate_by_name=True."""

    def _given_snake_case_payload() -> dict[str, Any]:
        return {
            "rule_alerts": [
                {
                    "rule_metadata": {
                        "rule_id": "ru_sc",
                        "properties": {"name": "SC", "text": "t", "metadata": {}},
                    },
                    "alerts": [],
                }
            ],
            "too_many_alerts": False,
        }

    def _then_fields_match_camel_case_variant(response: RuleAlertResponse):
        assert len(response.rule_alerts) == 1
        assert response.rule_alerts[0].rule_metadata.rule_id == "ru_sc"

    response = RuleAlertResponse.model_validate(_given_snake_case_payload())
    _then_fields_match_camel_case_variant(response)


# ---------------------------------------------------------------------------
# Scenario: Rule metadata includes arbitrary key-value properties
# ---------------------------------------------------------------------------
def test_rule_metadata_includes_arbitrary_properties():
    """Rule metadata.properties.metadata carries arbitrary k/v pairs."""

    def _given_response_with_metadata_properties():
        props = RulePropertiesFactory.build(
            metadata={"severity": "HIGH", "author": "soc-team-42"}
        )
        return RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(
                    rule_metadata=RuleMetadataFactory.build(properties=props)
                )
            ]
        )

    def _then_metadata_has_expected_keys(response: RuleAlertResponse):
        meta = response.rule_alerts[0].rule_metadata.properties.metadata
        assert meta["severity"] == "HIGH"
        assert meta["author"] == "soc-team-42"

    response = _given_response_with_metadata_properties()
    _then_metadata_has_expected_keys(response)
