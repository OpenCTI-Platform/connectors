"""Unit tests for the Anthropic AI Enrichment connector.

These cover the defects raised in review: an unsafe/unclamped confidence
cast, unvalidated AI list output being iterated directly, the
threat-actor-group entity lookup using the wrong API endpoint, a retry
loop that gave up instead of retrying on JSON/API errors, and a parsed
JSON value that isn't a dict.
"""

from unittest.mock import MagicMock

import anthropic
import main as connector_module
import pytest
from main import (
    AnthropicAIEnrichmentConnector,
    normalize_attack_ids,
    normalize_string_list,
)


class _NonRetryableAPIError(anthropic.APIError):
    """A minimal stand-in for a real non-retryable error (bad request, auth,
    permission, ...). We avoid constructing the real SDK exception classes
    directly since their __init__ signatures require a live httpx response
    object that isn't relevant to what this test is checking."""

    def __init__(self, message: str):
        self.message = message

    def __str__(self) -> str:
        return self.message


@pytest.fixture
def connector(monkeypatch):
    """A connector instance built from a fake ConnectorSettings and a mocked
    OpenCTIConnectorHelper, with the Anthropic client itself also mocked so
    no real network call is made."""
    monkeypatch.setattr(connector_module.anthropic, "Anthropic", MagicMock())
    monkeypatch.setattr(connector_module.time, "sleep", MagicMock())

    config = MagicMock()
    config.anthropic.api_key = "test-api-key"
    config.anthropic.model = "claude-3-5-haiku-latest"

    helper = MagicMock()
    helper.connect_confidence_level = 100

    return AnthropicAIEnrichmentConnector(config=config, helper=helper)


class TestNormalizeStringList:
    def test_accepts_a_list_of_strings(self):
        assert normalize_string_list(["APT28", " Sandworm "]) == ["APT28", "Sandworm"]

    def test_wraps_a_bare_string_instead_of_iterating_characters(self):
        assert normalize_string_list("APT28") == ["APT28"]

    def test_drops_empty_and_non_string_items(self):
        assert normalize_string_list(["APT28", "", None, 42, "  "]) == ["APT28"]

    def test_non_list_non_string_input_returns_empty(self):
        assert normalize_string_list(None) == []
        assert normalize_string_list(123) == []


class TestNormalizeAttackIds:
    def test_accepts_well_formed_ids_and_uppercases_them(self):
        assert normalize_attack_ids(["t1059.001", "T1003"]) == ["T1059.001", "T1003"]

    def test_drops_malformed_ids(self):
        assert normalize_attack_ids(["T1059.001", "not-an-id", "T99", ""]) == [
            "T1059.001"
        ]

    def test_wraps_a_bare_string(self):
        assert normalize_attack_ids("T1059.001") == ["T1059.001"]


class TestSafeConfidence:
    def test_valid_integer_passes_through(self, connector):
        assert connector._safe_confidence(72) == 72

    def test_string_number_is_parsed(self, connector):
        assert connector._safe_confidence("85") == 85

    def test_invalid_value_falls_back_to_default(self, connector):
        assert connector._safe_confidence("not-a-number", default=40) == 40
        assert connector._safe_confidence(None, default=40) == 40

    def test_out_of_range_values_are_clamped_to_0_100(self, connector):
        assert connector._safe_confidence(150) == 100
        assert connector._safe_confidence(-10) == 0

    def test_result_is_capped_at_the_connector_confidence_level(self, connector):
        connector.helper.connect_confidence_level = 50
        assert connector._safe_confidence(95) == 50
        assert connector._safe_confidence(30) == 30


class TestReadEntityRouting:
    def test_threat_actor_group_uses_the_threat_actor_group_endpoint(self, connector):
        connector.helper.api.threat_actor_group.read.return_value = {"id": "actor--1"}
        connector.helper.api.intrusion_set.read.return_value = {"id": "wrong-type"}

        result = connector._read_entity("threat-actor-group", "actor--1")

        assert result == {"id": "actor--1"}
        connector.helper.api.threat_actor_group.read.assert_called_once_with(
            id="actor--1"
        )
        connector.helper.api.intrusion_set.read.assert_not_called()

    def test_intrusion_set_uses_the_intrusion_set_endpoint(self, connector):
        connector.helper.api.intrusion_set.read.return_value = {"id": "is--1"}

        result = connector._read_entity("intrusion-set", "is--1")

        assert result == {"id": "is--1"}
        connector.helper.api.intrusion_set.read.assert_called_once_with(id="is--1")

    def test_unknown_entity_type_returns_empty_dict(self, connector):
        assert connector._read_entity("identity", "identity--1") == {}


class TestLinkingNormalizesUntrustedAiOutput:
    def test_link_threat_actors_ignores_a_bare_string_instead_of_looping_chars(
        self, connector
    ):
        connector.helper.api.threat_actor_group.read.return_value = None

        connector._link_threat_actors("report--1", "APT28", confidence=50)

        connector.helper.api.threat_actor_group.read.assert_called_once()
        called_filters = connector.helper.api.threat_actor_group.read.call_args.kwargs[
            "filters"
        ]
        assert called_filters["filters"][0]["values"] == ["APT28"]

    def test_link_attack_patterns_drops_malformed_technique_ids(self, connector):
        connector.helper.api.attack_pattern.read.return_value = None
        connector.helper.api.attack_pattern.create.return_value = {"id": "pattern--1"}

        connector._link_attack_patterns(
            "report--1", ["T1059.001", "not-a-technique"], confidence=50
        )

        assert connector.helper.api.attack_pattern.create.call_count == 1
        assert (
            connector.helper.api.attack_pattern.create.call_args.kwargs["x_mitre_id"]
            == "T1059.001"
        )


class TestCallAnthropicRetries:
    def _message(self, text: str):
        message = MagicMock()
        message.content = [MagicMock(text=text)]
        return message

    def test_retries_on_invalid_json_and_eventually_succeeds(self, connector):
        connector.client.messages.create.side_effect = [
            self._message("not json"),
            self._message('{"confidence": 80}'),
        ]

        result = connector._call_anthropic("{content}", "some content")

        assert result == {"confidence": 80}
        assert connector.client.messages.create.call_count == 2

    def test_gives_up_after_three_failed_attempts(self, connector):
        connector.client.messages.create.return_value = self._message("not json")

        result = connector._call_anthropic("{content}", "some content")

        assert result is None
        assert connector.client.messages.create.call_count == 3

    def test_does_not_retry_a_non_retryable_api_error(self, connector):
        connector.client.messages.create.side_effect = _NonRetryableAPIError(
            "bad api key"
        )

        result = connector._call_anthropic("{content}", "some content")

        assert result is None
        assert connector.client.messages.create.call_count == 1

    def test_retries_when_the_model_returns_a_json_list_instead_of_an_object(
        self, connector
    ):
        connector.client.messages.create.side_effect = [
            self._message("[1, 2, 3]"),
            self._message('{"confidence": 80}'),
        ]

        result = connector._call_anthropic("{content}", "some content")

        assert result == {"confidence": 80}
        assert connector.client.messages.create.call_count == 2
