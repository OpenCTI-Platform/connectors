# pragma: no cover
# type: ignore
"""Tests of hunts holding several Sigma rules, each translated and run on its own."""

from datetime import datetime, timezone

import pytest
from connectors_sdk.connectors.internal_hunt import (
    HuntEvent,
    HuntExecutionError,
    HuntResult,
    HuntTimeoutError,
    HuntTranslationError,
)

from .conftest import SIGMA_RULE, DummyHuntConnector

WHOAMI_RULE = """
title: Whoami discovery
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: whoami
  condition: selection
"""

BROKEN_RULE = "title: Broken rule\nlogsource: {product: windows}\ndetection: {}"


class PerRuleConnector(DummyHuntConnector):
    """Dummy connector answering each query with the result of the first marker it holds."""

    def __init__(self, settings, results) -> None:
        super().__init__(settings)
        self.results = results

    def execute(self, native_query, time_window, limits, deadline=None):
        self.executed.append((native_query, time_window, limits))
        for marker, result in self.results.items():
            if marker in native_query.query:
                if isinstance(result, BaseException):
                    raise result
                return result
        return HuntResult()


@pytest.fixture
def rules_connector(hunt_settings, hunt_helper):
    def _make(results=None):
        connector = PerRuleConnector(hunt_settings, results or {})
        connector._helper = hunt_helper
        from unittest.mock import MagicMock

        connector._logger = MagicMock()
        return connector

    return _make


def rules_event(hunt_event, *rules, **overrides):
    return hunt_event(
        hunt={
            "sigma_rules": [
                {"key": f"rule-{index}", "title": title, "rule": rule}
                for index, (title, rule) in enumerate(rules, start=1)
            ]
        },
        **overrides,
    )


def hit(hour, **fields):
    return HuntEvent(
        timestamp=datetime(2026, 10, 3, hour, tzinfo=timezone.utc), fields=fields
    )


def report_kwargs(helper):
    return helper.report_hunt_run.call_args


def test_preview_reports_the_translation_of_each_rule(
    rules_connector, hunt_event, hunt_helper
):
    # Given a hunt with a rule that translates and one that does not
    connector = rules_connector()
    event = rules_event(
        hunt_event,
        ("Encoded PowerShell", SIGMA_RULE),
        ("Broken rule", BROKEN_RULE),
        mode="preview",
    )

    # When the preview is processed
    message = connector.process_message(event)

    # Then each rule has its own result, nothing runs, and the run shows every
    # translated query under the title of its rule
    args, kwargs = report_kwargs(hunt_helper)
    assert args == ("run-1", "completed")
    assert connector.executed == []
    first, second = kwargs["rule_results"]
    assert (first["key"], first["status"]) == ("rule-1", "completed")
    assert first["translated_query"].startswith("CommandLine contains")
    assert (second["key"], second["status"]) == ("rule-2", "failed")
    assert second["error"].startswith("HuntTranslationError")
    assert kwargs["translated_query"].startswith("-- Encoded PowerShell\nCommandLine")
    assert kwargs["query_language"] == "test"
    assert "1 of 2 rule(s) translated" in message


def test_preview_fails_when_no_rule_translates(
    rules_connector, hunt_event, hunt_helper
):
    # Given a hunt whose only rule does not translate
    connector = rules_connector()
    event = rules_event(hunt_event, ("Broken rule", BROKEN_RULE), mode="preview")

    # When/Then the preview fails for good, with the result of the rule
    with pytest.raises(HuntTranslationError):
        connector.process_message(event)
    args, kwargs = report_kwargs(hunt_helper)
    assert args == ("run-1", "failed")
    assert kwargs["retryable"] is False
    assert [item["status"] for item in kwargs["rule_results"]] == ["failed"]
    # And the failure is reported once
    assert hunt_helper.report_hunt_run.call_count == 1


def test_each_rule_runs_on_its_own_and_fails_alone(
    rules_connector, hunt_event, hunt_helper
):
    # Given a rule with hits on two hosts, a rule the platform rejects and a rule
    # that does not translate
    connector = rules_connector(
        {
            "-enc": HuntResult(
                events=[
                    hit(
                        2,
                        CommandLine="powershell -enc AAAA",
                        DestinationIp="8.8.8.8",
                        host="ws1",
                    ),
                    hit(
                        4,
                        CommandLine="powershell -enc BBBB",
                        DestinationIp="8.8.8.8",
                        host="ws2",
                    ),
                ]
            ),
            "whoami": HuntExecutionError("platform down"),
        }
    )
    event = rules_event(
        hunt_event,
        ("Encoded PowerShell", SIGMA_RULE),
        ("Whoami discovery", WHOAMI_RULE),
        ("Broken rule", BROKEN_RULE),
    )

    # When the run is processed
    message = connector.process_message(event)

    # Then the run completes with the hits of the rule that ran, each rule
    # reporting its own result
    args, kwargs = report_kwargs(hunt_helper)
    assert args == ("run-1", "completed")
    results = {item["key"]: item for item in kwargs["rule_results"]}
    assert results["rule-1"]["status"] == "completed"
    assert results["rule-1"]["hits_count"] == 2
    assert results["rule-1"]["first_hit_at"].startswith("2026-10-03T02:00:00")
    assert results["rule-1"]["last_hit_at"].startswith("2026-10-03T04:00:00")
    assert results["rule-2"]["status"] == "failed"
    assert results["rule-2"]["error"] == "HuntExecutionError: platform down"
    assert results["rule-2"]["translated_query"].startswith("CommandLine")
    assert results["rule-3"]["status"] == "failed"
    assert results["rule-3"]["translated_query"] is None
    assert kwargs["hits_count"] == 2
    assert len(kwargs["hit_keys"]) == 2
    # And every hit is counted per rule and victim
    observations = sorted(
        (item["key"], item["host"], item["hits_count"])
        for item in kwargs["observations"]
    )
    assert observations == [("rule-1", "ws1", 1), ("rule-1", "ws2", 1)]
    assert kwargs["first_hit_at"].startswith("2026-10-03T02:00:00")
    assert "2 hit(s) over 1 of 3 rule(s)" in message


def test_a_hit_found_by_two_rules_counts_once(rules_connector, hunt_event, hunt_helper):
    # Given two rules matching the same event
    same = HuntResult(events=[hit(2, CommandLine="powershell -enc whoami", host="ws1")])
    connector = rules_connector({"-enc": same, "whoami": same})
    event = rules_event(
        hunt_event,
        ("Encoded PowerShell", SIGMA_RULE),
        ("Whoami discovery", WHOAMI_RULE),
    )

    # When the run is processed
    connector.process_message(event)

    # Then the run holds the hit once, each rule counting it
    _, kwargs = report_kwargs(hunt_helper)
    assert len(kwargs["hit_keys"]) == 1
    assert [item["hits_count"] for item in kwargs["rule_results"]] == [1, 1]
    assert {item["key"] for item in kwargs["observations"]} == {"rule-1", "rule-2"}
    assert {tuple(item["hit_keys"]) for item in kwargs["observations"]} == {
        tuple(kwargs["hit_keys"])
    }


def test_rules_share_the_maximum_number_of_results(
    rules_connector, hunt_event, hunt_helper
):
    # Given a run allowed one result and a first rule reading it
    connector = rules_connector(
        {"-enc": HuntResult(events=[hit(2, CommandLine="x -enc y", host="ws1")])}
    )
    event = rules_event(
        hunt_event,
        ("Encoded PowerShell", SIGMA_RULE),
        ("Whoami discovery", WHOAMI_RULE),
        limits={"max_results": 1, "timeout_seconds": 5},
    )

    # When the run is processed
    connector.process_message(event)

    # Then the second rule does not run and the run says its results are partial
    _, kwargs = report_kwargs(hunt_helper)
    assert len(connector.executed) == 1
    assert kwargs["queries_count"] == 1
    assert kwargs["truncated"] is True
    second = kwargs["rule_results"][1]
    assert (second["status"], second["truncated"]) == ("completed", True)


def test_run_fails_when_every_rule_fails(rules_connector, hunt_event, hunt_helper):
    # Given rules the platform rejects
    connector = rules_connector(
        {
            "-enc": HuntExecutionError("platform down"),
            "whoami": HuntExecutionError("still down"),
        }
    )
    event = rules_event(
        hunt_event,
        ("Encoded PowerShell", SIGMA_RULE),
        ("Whoami discovery", WHOAMI_RULE),
    )

    # When/Then the run fails with the first error, once, and can be run again
    with pytest.raises(HuntExecutionError, match="platform down"):
        connector.process_message(event)
    args, kwargs = report_kwargs(hunt_helper)
    assert args == ("run-1", "failed")
    assert kwargs["retryable"] is True
    assert [item["status"] for item in kwargs["rule_results"]] == ["failed", "failed"]
    assert hunt_helper.report_hunt_run.call_count == 1


def test_a_rule_timing_out_times_the_run_out(rules_connector, hunt_event, hunt_helper):
    # Given a rule running past the run deadline
    connector = rules_connector({"-enc": HuntTimeoutError("deadline reached")})
    event = rules_event(hunt_event, ("Encoded PowerShell", SIGMA_RULE))

    # When/Then the whole run times out
    with pytest.raises(HuntTimeoutError):
        connector.process_message(event)
    args, _ = report_kwargs(hunt_helper)
    assert args == ("run-1", "timeout")


def test_an_older_pycti_gets_the_run_without_rule_results(rules_connector, hunt_event):
    # Given a pycti whose report takes observations, but neither hit keys nor
    # rule results
    class _OlderHelper:
        work_id = "work-1"

        def __init__(self):
            self.reports = []

        def stix2_create_bundle(self, *args, **kwargs):
            return '{"type": "bundle"}'

        def send_stix2_bundle(self, *args, **kwargs):
            return ["bundle-1"]

        def report_hunt_run(
            self,
            run_id,
            status,
            hits_count=None,
            distinct_entities=None,
            evidence_sample=None,
            translated_query=None,
            query_language=None,
            cost_ms=None,
            result_ids=None,
            error=None,
            truncated=None,
            observations=None,
        ):
            self.reports.append((status, observations))

    connector = rules_connector(
        {"-enc": HuntResult(events=[hit(2, CommandLine="x -enc y", host="ws1")])}
    )
    connector._helper = _OlderHelper()

    # When the run is processed
    connector.process_message(
        rules_event(hunt_event, ("Encoded PowerShell", SIGMA_RULE))
    )

    # Then the report holds what that pycti takes, the observations without keys
    [(status, observations)] = connector.helper.reports
    assert status == "completed"
    assert observations == [
        {
            "key": "rule-1",
            "host": "ws1",
            "hits_count": 1,
            "first_seen": "2026-10-03T02:00:00Z",
            "last_seen": "2026-10-03T02:00:00Z",
        }
    ]
