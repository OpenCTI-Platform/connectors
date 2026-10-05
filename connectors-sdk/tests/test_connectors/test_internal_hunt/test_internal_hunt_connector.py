# pragma: no cover
# type: ignore
"""Tests of the InternalHuntConnector base class."""

import json
from datetime import datetime, timezone
from enum import Enum
from unittest.mock import MagicMock, patch

import pytest
import stix2
from connectors_sdk.connectors.internal_hunt import (
    HuntAccessDeniedError,
    HuntEvent,
    HuntExecutionError,
    HuntQueryRejectedError,
    HuntRequestError,
    HuntResult,
    HuntTimeoutError,
    HuntTranslationError,
    HuntUnsupportedPyctiError,
    InternalHuntConnector,
    NativeQuery,
    RunDeadline,
    ensure_pycti_hunt_support,
)
from connectors_sdk.connectors.internal_hunt.internal_hunt_connector import (
    ERROR_MESSAGE_MAX_LENGTH,
    _error_message,
)
from connectors_sdk.models import IPV4Address

from .conftest import DummyHuntConnector, make_hunt_config

MODULE = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"


class _HuntHelper:
    """Helper class exposing the hunt API, like a pycti release supporting hunts."""

    def __init__(self, config):
        self.config = config
        self.connector_logger = MagicMock()

    def listen_hunt(self, message_callback):
        self.callback = message_callback

    def register_hunt_platform(self, **kwargs):
        self.registered = kwargs
        return {"id": "connector-hunt-id"}

    def report_hunt_run(self, *args, **kwargs):
        return {}


class _HuntConnectorType(Enum):
    INTERNAL_HUNT = "INTERNAL_HUNT"


def _results(*fields, total=None):
    return HuntResult(
        events=[
            HuntEvent(
                timestamp=datetime(2026, 10, 3, 2, tzinfo=timezone.utc),
                fields=item,
            )
            for item in fields
        ],
        total_hits=total,
    )


def _report_kwargs(helper):
    args, kwargs = helper.report_hunt_run.call_args
    return args, kwargs


# ----------------------------------------------------------------------
# Construction and startup
# ----------------------------------------------------------------------


def test_init_requires_hunt_settings_and_languages(hunt_settings):
    # Given settings that are not hunt connector settings
    wrong_settings = MagicMock()
    wrong_settings.connector = MagicMock()

    class _NoLanguage(DummyHuntConnector):
        languages = ()

    # When/Then the connector refuses them, and requires a language
    with pytest.raises(TypeError, match="BaseInternalHuntConnectorConfig"):
        DummyHuntConnector(wrong_settings)
    with pytest.raises(ValueError, match="language"):
        _NoLanguage(hunt_settings)


def test_helper_and_logger_require_start(hunt_settings):
    # Given a connector that is not started
    connector = DummyHuntConnector(hunt_settings)

    # When/Then the helper and the logger are not available yet
    with pytest.raises(RuntimeError):
        _ = connector.helper
    with pytest.raises(RuntimeError):
        _ = connector.logger
    assert connector.platform == "splunk"


def test_ensure_pycti_hunt_support_reports_missing_api():
    # Given the installed pycti (without hunt support) and a pycti providing it
    # When/Then the check fails with the missing parts, or passes
    with patch(f"{MODULE}.OpenCTIConnectorHelper", MagicMock(spec=[])):
        with pytest.raises(HuntUnsupportedPyctiError) as error:
            ensure_pycti_hunt_support()
    assert "OpenCTIConnectorHelper.listen_hunt" in str(error.value)

    with (
        patch(f"{MODULE}.OpenCTIConnectorHelper", _HuntHelper),
        patch("pycti.connector.opencti_connector.ConnectorType", _HuntConnectorType),
    ):
        ensure_pycti_hunt_support()


def test_ensure_pycti_hunt_support_reports_missing_connector_type():
    # Given a pycti with the helper methods but without the INTERNAL_HUNT type
    class _OtherType(Enum):
        STREAM = "STREAM"

    # When/Then the missing connector type is reported
    with (
        patch(f"{MODULE}.OpenCTIConnectorHelper", _HuntHelper),
        patch("pycti.connector.opencti_connector.ConnectorType", _OtherType),
    ):
        with pytest.raises(HuntUnsupportedPyctiError, match="INTERNAL_HUNT"):
            ensure_pycti_hunt_support()


def test_start_registers_the_platform_and_listens(hunt_settings):
    # Given a pycti providing the hunt API
    connector = DummyHuntConnector(hunt_settings)

    # When the connector starts
    with (
        patch(f"{MODULE}.OpenCTIConnectorHelper", _HuntHelper),
        patch("pycti.connector.opencti_connector.ConnectorType", _HuntConnectorType),
    ):
        connector.start()

    # Then the platform is registered and hunt runs are listened to
    helper = connector.helper
    assert helper.config == {"connector": {"type": "INTERNAL_HUNT"}}
    assert helper.registered == {
        "platform": "splunk",
        "languages": ["test", "other"],
        "security_platform_name": "Test SIEM",
        "security_platform_type": "SIEM",
        "supports_preview": True,
        "max_concurrent_runs": None,
        # A connector without an indicator lookup declares it to a pycti that knows indicator hunts
        "supports_indicators": False,
    }
    assert helper.callback == connector.process_message


def test_register_platform_for_internet_connectors(hunt_settings, hunt_helper):
    # Given an internet hunt connector
    hunt_settings.connector = make_hunt_config(
        scope=["internet"], security_platform_name=None, max_concurrent_runs=2
    )
    connector = DummyHuntConnector(hunt_settings)
    connector._helper = hunt_helper
    connector._logger = MagicMock()
    hunt_helper.register_hunt_platform.return_value = None

    # When the platform is registered
    registration = connector.register_platform()

    # Then no Security Platform is requested
    kwargs = hunt_helper.register_hunt_platform.call_args.kwargs
    assert kwargs["platform"] == "internet"
    assert kwargs["security_platform_name"] is None
    assert kwargs["max_concurrent_runs"] == 2
    assert registration == {}


def test_start_fails_fast_with_an_old_pycti(hunt_settings):
    # Given the installed pycti without hunt support
    connector = DummyHuntConnector(hunt_settings)

    # When/Then the connector refuses to start
    with patch(f"{MODULE}.OpenCTIConnectorHelper", MagicMock(spec=[])):
        with pytest.raises(HuntUnsupportedPyctiError):
            connector.start()


# ----------------------------------------------------------------------
# Query resolution
# ----------------------------------------------------------------------


def test_preview_reports_the_translated_query(
    connector_factory, hunt_event, hunt_helper
):
    # Given a preview run
    connector = connector_factory()

    # When it is processed
    message = connector.process_message(hunt_event(mode="preview"))

    # Then the translation is reported and nothing is executed or sent
    args, kwargs = _report_kwargs(hunt_helper)
    assert args == ("run-1", "completed")
    assert kwargs["translated_query"] == (
        'CommandLine contains " -enc " and DestinationIp="8.8.8.8"'
    )
    assert kwargs["query_language"] == "test"
    assert kwargs["hits_count"] is None
    assert connector.executed == []
    hunt_helper.send_stix2_bundle.assert_not_called()
    assert "preview" in message


def test_native_query_override_is_executed_verbatim(connector_factory, hunt_event):
    # Given a hunt with a native query for the connector platform
    connector = connector_factory()
    event = hunt_event(
        hunt={
            "native_query": {
                "platform": "splunk",
                "language": "other",
                "query": "  native query  ",
                "pipeline": None,
            }
        }
    )

    # When it is processed
    connector.process_message(event)

    # Then the native query is executed instead of the Sigma rule
    native_query = connector.executed[0][0]
    assert native_query == NativeQuery(language="other", query="native query")


def test_native_query_for_another_platform_is_ignored(connector_factory, hunt_event):
    # Given a hunt whose native query targets another platform
    connector = connector_factory()
    event = hunt_event(
        hunt={
            "native_query": {
                "platform": "microsoft-sentinel",
                "language": "kql",
                "query": "SecurityEvent",
            }
        }
    )

    # When it is processed
    connector.process_message(event)

    # Then the Sigma rule is translated
    assert connector.executed[0][0].translated is True


def test_blank_native_query_selects_the_pipeline(connector_factory, hunt_event):
    # Given a native query override without query but with a pipeline
    connector = connector_factory()
    event = hunt_event(
        mode="preview",
        hunt={
            "sigma_rule": "title: t\nlogsource: {product: windows}\ndetection: {sel: {fieldA: v}, condition: sel}",
            "native_query": {
                "platform": "splunk",
                "language": "test",
                "query": " ",
                "pipeline": "dummy",
            },
        },
    )

    # When/Then the rule is translated with the requested pipeline
    query = connector.resolve_query(connector.parse_request(event))
    assert query.pipeline == "dummy"
    assert query.query == 'mappedA="v"'


def test_unsupported_native_language_fails_the_run(
    connector_factory, hunt_event, hunt_helper
):
    # Given a native query in a language the connector cannot execute
    connector = connector_factory()
    event = hunt_event(
        hunt={"native_query": {"platform": "splunk", "language": "kql", "query": "x"}}
    )

    # When/Then the run fails and is reported as failed
    with pytest.raises(HuntTranslationError, match="kql"):
        connector.process_message(event)
    args, kwargs = _report_kwargs(hunt_helper)
    assert args == ("run-1", "failed")
    assert kwargs["error"].startswith("HuntTranslationError")
    assert kwargs["translated_query"] is None


def test_hunt_without_logic_fails(connector_factory, hunt_event):
    # Given a hunt without Sigma rule nor native query
    connector = connector_factory()

    # When/Then the run fails
    with pytest.raises(HuntTranslationError, match="no Sigma rule"):
        connector.process_message(hunt_event(hunt={"sigma_rule": "  "}))


def test_combine_queries(connector_factory):
    # Given a connector with and without join operator
    connector = connector_factory()

    class _Joined(DummyHuntConnector):
        query_join = " OR "

    joined = _Joined(connector.settings)

    # When/Then several queries are joined or rejected
    assert connector.combine_queries(["a"]) == "a"
    with pytest.raises(HuntTranslationError, match="no query"):
        connector.combine_queries([])
    with pytest.raises(HuntTranslationError, match="2 queries"):
        connector.combine_queries(["a", "b"])
    assert joined.combine_queries(["a", "b"]) == "(a) OR (b)"


# ----------------------------------------------------------------------
# Execution
# ----------------------------------------------------------------------


def test_execution_sends_knowledge_and_reports_the_run(
    connector_factory, hunt_event, hunt_helper
):
    # Given results with a public IP, a benign event and a raw payload
    result = _results(
        {"DestinationIp": "8.8.8.8", "host": "ws1", "_raw": "raw event"},
        {"DestinationIp": "8.8.8.8", "host": "ws2", "CommandLine": "x -enc y"},
        {"DestinationIp": "1.1.1.1", "host": "sccm-server"},
    )
    connector = connector_factory(result)
    event = hunt_event(hunt={"benign_patterns": ["SCCM"]})

    # When the run is processed
    message = connector.process_message(event)

    # Then the sightings and observables are sent within the work
    bundle_objects = hunt_helper.stix2_create_bundle.call_args.args[0]
    types = sorted(obj["type"] for obj in bundle_objects)
    assert types == ["ipv4-addr", "observed-data", "sighting", "sighting"]
    send_kwargs = hunt_helper.send_stix2_bundle.call_args.kwargs
    assert send_kwargs == {"work_id": "work-1", "cleanup_inconsistent_bundle": False}

    # And the completed run is reported with redacted evidence
    args, kwargs = _report_kwargs(hunt_helper)
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 2
    assert kwargs["distinct_entities"] == 2
    assert kwargs["query_language"] == "test"
    assert sorted(kwargs["result_ids"]) == sorted(obj["id"] for obj in bundle_objects)
    evidence = kwargs["evidence_sample"]
    assert evidence[0]["field"] == "CommandLine"
    assert all(item["field"] != "_raw" for item in evidence)
    assert all(len(item["value_preview"]) <= 16 for item in evidence)
    assert kwargs["cost_ms"] >= 0
    assert "2 hit(s)" in message

    # And the execute hook received the window and the limits
    _, time_window, limits = connector.executed[0]
    assert time_window.start == datetime(2026, 10, 3, tzinfo=timezone.utc)
    assert limits.max_results == 100


def test_execution_without_hits_sends_nothing(
    connector_factory, hunt_event, hunt_helper
):
    # Given an empty result
    connector = connector_factory(HuntResult())

    # When the run is processed
    connector.process_message(hunt_event())

    # Then nothing is sent and zero hits of complete results are reported
    hunt_helper.send_stix2_bundle.assert_not_called()
    _, kwargs = _report_kwargs(hunt_helper)
    assert kwargs["hits_count"] == 0
    assert kwargs["truncated"] is False
    assert kwargs["result_ids"] == []
    assert kwargs["evidence_sample"] == []


def test_execution_reports_partial_results_as_truncated(
    connector_factory, hunt_event, hunt_helper
):
    # Given an empty result the platform marked as partial (shard failures)
    connector = connector_factory(HuntResult(truncated=True))

    # When the run is processed
    connector.process_message(hunt_event())

    # Then the report says so, so that OpenCTI never reads zero hits as benign
    args, kwargs = _report_kwargs(hunt_helper)
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 0
    assert kwargs["truncated"] is True


def test_execution_without_security_platform_logs_a_warning(
    connector_factory, hunt_event, hunt_helper
):
    # Given hits for a run without Security Platform
    connector = connector_factory(_results({"DestinationIp": "8.8.8.8"}))

    # When the run is processed
    connector.process_message(hunt_event(security_platform=None))

    # Then sightings are skipped with a warning
    connector.logger.warning.assert_called_once()
    bundle_objects = hunt_helper.stix2_create_bundle.call_args.args[0]
    assert "sighting" not in {obj["type"] for obj in bundle_objects}


def test_observable_types_are_restricted_by_hunt_and_configuration(
    hunt_settings, connector_factory, hunt_event, hunt_helper
):
    # Given a configuration allowing IPs only, and a hunt expecting domains only
    hunt_settings.connector = make_hunt_config(observable_types=["IPv4-Addr"])
    connector = connector_factory(
        _results({"DestinationIp": "8.8.8.8", "dns.question.name": "evil.com"})
    )

    # When the run is processed
    connector.process_message(
        hunt_event(hunt={"expected_observables": ["Domain-Name"]})
    )

    # Then no observable is created
    bundle_objects = hunt_helper.stix2_create_bundle.call_args.args[0]
    assert {obj["type"] for obj in bundle_objects} == {"sighting"}


def test_max_results_is_enforced(connector_factory, hunt_event, hunt_helper):
    # Given a platform returning more events than allowed
    connector = connector_factory(
        _results(*[{"DestinationIp": "8.8.8.8"} for _ in range(5)])
    )
    event = hunt_event(limits={"max_results": 2, "timeout_seconds": 5})

    # When the run is processed
    connector.process_message(event)

    # Then the events are capped but the hit count keeps the total
    _, kwargs = _report_kwargs(hunt_helper)
    assert kwargs["hits_count"] == 5


def test_execution_error_fails_the_run(connector_factory, hunt_event, hunt_helper):
    # Given a platform error
    connector = connector_factory(HuntExecutionError("platform down"))

    # When/Then the run is reported as failed with the translated query, and the error is raised
    with pytest.raises(HuntExecutionError, match="platform down"):
        connector.process_message(hunt_event())
    args, kwargs = _report_kwargs(hunt_helper)
    assert args == ("run-1", "failed")
    assert kwargs["error"] == "HuntExecutionError: platform down"
    assert kwargs["translated_query"].startswith("CommandLine")
    assert kwargs["retryable"] is True
    connector.logger.error.assert_called()


@pytest.mark.parametrize(
    "error, retryable",
    [
        pytest.param(HuntQueryRejectedError("Invalid UDM field"), False, id="rejected"),
        pytest.param(
            HuntTranslationError("Invalid UDM field"), False, id="translation"
        ),
        pytest.param(HuntUnsupportedPyctiError("old pycti"), False, id="pycti"),
        pytest.param(HuntExecutionError("platform down"), True, id="platform"),
        pytest.param(HuntAccessDeniedError("role missing"), True, id="access_denied"),
        pytest.param(RuntimeError("unexpected"), True, id="unexpected"),
    ],
)
def test_failed_run_tells_whether_running_it_again_can_succeed(
    connector_factory, hunt_event, hunt_helper, error, retryable
):
    # Given a run failing with a deterministic or a transient error
    connector = connector_factory(error)

    # When it is processed
    with pytest.raises(type(error)):
        connector.process_message(hunt_event())

    # Then the failed run says whether OpenCTI should retry it
    args, kwargs = _report_kwargs(hunt_helper)
    assert args == ("run-1", "failed")
    assert kwargs["retryable"] is retryable


@pytest.mark.parametrize(
    "mode", [pytest.param("execute", id="run"), pytest.param("preview", id="preview")]
)
def test_translation_failure_is_terminal_in_run_and_preview(
    connector_factory, hunt_event, hunt_helper, mode
):
    # Given a Sigma rule the platform pipeline cannot translate
    connector = connector_factory()
    event = hunt_event(
        mode=mode,
        hunt={"sigma_rule": "title: t\nlogsource: {product: windows}\ndetection: {}"},
    )

    # When/Then the run fails before anything runs on the platform, and is not retried
    with pytest.raises(HuntTranslationError):
        connector.process_message(event)
    args, kwargs = _report_kwargs(hunt_helper)
    assert args == ("run-1", "failed")
    assert kwargs["error"].startswith("HuntTranslationError: ")
    assert kwargs["retryable"] is False
    assert connector.executed == []


def test_invalid_message_is_terminal(connector_factory, hunt_helper):
    # Given/When a message OpenCTI cannot have meant as a run
    with pytest.raises(HuntRequestError):
        connector_factory().process_message({"hunt_run": {"id": "run-1"}})

    # Then it is reported failed, never to be retried
    assert _report_kwargs(hunt_helper)[1]["retryable"] is False


def test_pycti_without_terminal_failures_gets_the_error_only(
    connector_factory, hunt_event
):
    # Given a pycti whose report does not take the retryable flag
    class _OlderHelper:
        work_id = "work-1"

        def __init__(self):
            self.reports = []

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
        ):
            self.reports.append((run_id, status, error))

    connector = connector_factory(HuntQueryRejectedError("Invalid UDM field"))
    connector._helper = _OlderHelper()

    # When/Then the failure is reported with its error class, without the flag
    with pytest.raises(HuntQueryRejectedError):
        connector.process_message(hunt_event())
    assert connector.helper.reports == [
        ("run-1", "failed", "HuntQueryRejectedError: Invalid UDM field")
    ]


def test_invalid_execute_result_fails_the_run(connector_factory, hunt_event):
    # Given an execute hook returning something else than a HuntResult
    connector = connector_factory()
    connector.result = ["not", "a", "result"]

    # When/Then the run fails
    with pytest.raises(HuntExecutionError, match="must return a HuntResult"):
        connector.process_message(hunt_event())


def test_timeout_cancels_and_fails_the_run(connector_factory, hunt_event, hunt_helper):
    # Given a query running longer than the run timeout
    connector = connector_factory(HuntResult())
    connector.block = True
    event = hunt_event(limits={"timeout_seconds": 1})

    # When/Then the run times out, the platform job is cancelled and the run is reported as a timeout
    with pytest.raises(HuntTimeoutError, match="1 seconds"):
        connector.process_message(event)
    assert len(connector.timeouts) == 1
    args, kwargs = _report_kwargs(hunt_helper)
    assert args == ("run-1", "timeout")
    assert kwargs["error"].startswith("HuntTimeoutError")


def test_query_finishing_after_the_deadline_times_out(
    connector_factory, hunt_event, hunt_helper
):
    # Given a query that returns once the run deadline has passed, before the
    # wait for it ends
    connector = connector_factory(_results({"DestinationIp": "8.8.8.8"}))
    late = MagicMock(spec=RunDeadline)
    late.remaining.return_value = 5.0
    late.expired.return_value = True

    # When/Then the run is a timeout, not a completed run, and the finished
    # query has nothing to cancel
    with patch(f"{MODULE}.RunDeadline", return_value=late):
        with pytest.raises(HuntTimeoutError, match="30 seconds"):
            connector.process_message(hunt_event(limits={"timeout_seconds": 30}))
    assert connector.deadlines == [late]
    assert connector.timeouts == []
    args, _ = _report_kwargs(hunt_helper)
    assert args == ("run-1", "timeout")
    hunt_helper.send_stix2_bundle.assert_not_called()


def test_execute_shares_the_run_deadline(connector_factory, hunt_event):
    # Given a run with a 30 seconds timeout
    connector = connector_factory(_results({"DestinationIp": "8.8.8.8"}))
    created = []

    def _deadline(timeout_seconds):
        created.append(RunDeadline(timeout_seconds))
        return created[-1]

    # When the run is processed
    with patch(f"{MODULE}.RunDeadline", side_effect=_deadline):
        connector.process_message(hunt_event(limits={"timeout_seconds": 30}))

    # Then execute() receives the single deadline the run is waited for with
    assert len(created) == 1
    assert connector.deadlines == created
    assert 0 < created[0].remaining() <= 30


def test_benign_suppression_counts_within_the_run_timeout(
    connector_factory, hunt_event, hunt_helper
):
    # Given a benign regex that backtracks on the returned value
    connector = connector_factory(_results({"user": "a" * 60 + "!"}))
    event = hunt_event(
        hunt={"benign_patterns": ["/(a|aa)+$/"]}, limits={"timeout_seconds": 1}
    )

    # When/Then the run is reported as a timeout instead of blocking
    with pytest.raises(HuntTimeoutError, match="benign pattern"):
        connector.process_message(event)
    args, _ = _report_kwargs(hunt_helper)
    assert args == ("run-1", "timeout")
    hunt_helper.send_stix2_bundle.assert_not_called()


def test_timeout_survives_cancellation_errors(connector_factory, hunt_event):
    # Given a cancellation hook that fails
    connector = connector_factory(HuntResult())
    connector.block = True

    def _failing_cancel(native_query):
        connector.release.set()
        raise RuntimeError("cannot cancel")

    connector.on_timeout = _failing_cancel

    # When/Then the timeout is still reported and the cancellation error logged
    with pytest.raises(HuntTimeoutError):
        connector.process_message(hunt_event(limits={"timeout_seconds": 1}))
    connector.logger.warning.assert_called_once()


def test_default_on_timeout_does_nothing(hunt_settings):
    # Given/When/Then the default timeout hook is a no-op
    assert (
        InternalHuntConnector.on_timeout(
            DummyHuntConnector(hunt_settings), NativeQuery(language="x", query="q")
        )
        is None
    )


# ----------------------------------------------------------------------
# Invalid messages and reporting errors
# ----------------------------------------------------------------------


def test_invalid_message_with_run_id_is_reported(connector_factory, hunt_helper):
    # Given a message with a run id but no hunt
    connector = connector_factory()

    # When/Then the run is reported as failed and the error raised
    with pytest.raises(HuntRequestError, match="Invalid hunt run message"):
        connector.process_message({"hunt_run": {"id": "run-9"}})
    args, kwargs = _report_kwargs(hunt_helper)
    assert args == ("run-9", "failed")
    assert kwargs["error"].startswith("HuntRequestError")


@pytest.mark.parametrize(
    "event",
    [
        pytest.param({}, id="no_run"),
        pytest.param({"hunt_run": "run-9"}, id="run_not_object"),
        pytest.param({"hunt_run": {"id": ""}}, id="empty_run_id"),
    ],
)
def test_invalid_message_without_run_id_is_not_reported(
    connector_factory, hunt_helper, event
):
    # Given a message without usable run id
    connector = connector_factory()

    # When/Then the error is raised without report
    with pytest.raises(HuntRequestError):
        connector.process_message(event)
    hunt_helper.report_hunt_run.assert_not_called()


def test_report_failure_does_not_mask_the_error(
    connector_factory, hunt_event, hunt_helper
):
    # Given a platform rejecting the failure report
    connector = connector_factory(HuntExecutionError("boom"))
    hunt_helper.report_hunt_run.side_effect = RuntimeError("report rejected")

    # When/Then the original error is raised and the report error logged
    with pytest.raises(HuntExecutionError, match="boom") as raised:
        connector.process_message(hunt_event())
    assert connector.logger.error.call_count == 2
    # And the listen_hunt wrapper of pycti still reports the failure itself
    assert getattr(raised.value, "hunt_run_reported", False) is False


def test_reported_failure_is_not_reported_again_by_pycti(
    connector_factory, hunt_event, hunt_helper
):
    # Given a run that times out
    connector = connector_factory(HuntResult())
    connector.block = True

    # When the run is processed
    with pytest.raises(HuntTimeoutError) as raised:
        connector.process_message(hunt_event(limits={"timeout_seconds": 1}))

    # Then the timeout is reported once, and flagged so that the wrapper does not report it as failed
    assert raised.value.hunt_run_reported is True
    statuses = [call.args[1] for call in hunt_helper.report_hunt_run.call_args_list]
    assert statuses == ["timeout"]


def test_reported_flag_tolerates_errors_without_attributes(
    connector_factory, hunt_event, hunt_helper
):
    # Given an execute hook raising an exception type without instance attributes
    class SlotError(Exception):
        __slots__ = ()

        def __setattr__(self, name, value):
            raise AttributeError(name)

    connector = connector_factory(SlotError("no attributes"))

    # When/Then the run is reported failed and the original error is raised unchanged
    with pytest.raises(SlotError):
        connector.process_message(hunt_event())
    statuses = [call.args[1] for call in hunt_helper.report_hunt_run.call_args_list]
    assert statuses == ["failed"]


def test_completed_report_comes_before_the_knowledge(
    connector_factory, hunt_event, hunt_helper
):
    # Given a run with results
    connector = connector_factory(_results({"DestinationIp": "8.8.8.8"}))

    # When the run is processed
    connector.process_message(hunt_event())

    # Then the run is reported completed, with the ids of its knowledge, before the bundle is sent
    names = [call[0] for call in hunt_helper.mock_calls]
    assert names.index("report_hunt_run") < names.index("send_stix2_bundle")
    _, kwargs = _report_kwargs(hunt_helper)
    sent = hunt_helper.stix2_create_bundle.call_args.args[0]
    assert kwargs["result_ids"] == [obj["id"] for obj in sent]


def test_unreported_run_sends_no_knowledge(connector_factory, hunt_event, hunt_helper):
    # Given a platform refusing the completed report
    connector = connector_factory(_results({"DestinationIp": "8.8.8.8"}))
    hunt_helper.report_hunt_run.side_effect = [RuntimeError("report rejected"), None]

    # When/Then the run is reported failed and no knowledge is sent
    with pytest.raises(RuntimeError, match="report rejected"):
        connector.process_message(hunt_event())
    hunt_helper.send_stix2_bundle.assert_not_called()
    statuses = [call.args[1] for call in hunt_helper.report_hunt_run.call_args_list]
    assert statuses == ["completed", "failed"]


def test_knowledge_failure_keeps_the_completed_run(
    connector_factory, hunt_event, hunt_helper
):
    # Given a bundle that cannot be sent once the run is reported completed
    connector = connector_factory(_results({"DestinationIp": "8.8.8.8"}))
    hunt_helper.send_stix2_bundle.side_effect = RuntimeError("queue unavailable")

    # When/Then the work ends in error and the run is never reported failed
    with pytest.raises(RuntimeError, match="queue unavailable") as raised:
        connector.process_message(hunt_event())
    statuses = [call.args[1] for call in hunt_helper.report_hunt_run.call_args_list]
    assert statuses == ["completed"]
    assert raised.value.hunt_run_reported is True
    connector.logger.error.assert_called()


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def test_send_bundle_accepts_models_stix_objects_and_dicts(
    connector_factory, hunt_helper
):
    # Given an SDK model, a stix2 object, a STIX dict and a duplicate
    connector = connector_factory()
    model = IPV4Address(value="8.8.8.8")
    stix_object = stix2.v21.DomainName(value="evil.com")
    stix_dict = json.loads(stix2.v21.URL(value="https://evil.com/").serialize())

    # When the bundle is sent
    ids = connector.send_bundle([model, stix_object, stix_dict, model])

    # Then every object is sent once
    assert ids == [model.id, stix_object.id, stix_dict["id"]]
    assert len(hunt_helper.stix2_create_bundle.call_args.args[0]) == 3


def test_send_bundle_rejects_unknown_objects(connector_factory):
    # Given/When/Then objects that are not STIX are rejected
    with pytest.raises(TypeError, match="Unsupported STIX object"):
        connector_factory().send_bundle([object()])
    with pytest.raises(TypeError):
        connector_factory().send_bundle([{"type": "no-id"}])


def test_error_message_formats_and_truncates():
    # Given/When/Then exceptions are formatted with their type and truncated
    assert _error_message(ValueError("bad")) == "ValueError: bad"
    assert _error_message(ValueError()) == "ValueError"
    assert len(_error_message(ValueError("x" * 5000))) == ERROR_MESSAGE_MAX_LENGTH


def test_default_post_init_does_nothing(hunt_settings):
    # Given/When/Then the default post_init hook is a no-op
    assert InternalHuntConnector.post_init(DummyHuntConnector(hunt_settings)) is None
