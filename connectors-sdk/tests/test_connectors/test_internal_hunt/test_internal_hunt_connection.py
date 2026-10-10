# pragma: no cover
# type: ignore
"""Tests of the connection test and the declared permissions of the hunt connector base."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.internal_hunt import (
    HuntAccessDeniedError,
    HuntConnectionCheck,
    HuntEvent,
    HuntRequestError,
    HuntResult,
    HuntTimeoutError,
    HuntUnsupportedPyctiError,
    NativeQuery,
)

from .conftest import DummyHuntConnector

CHECK_EVENT = {
    "event_type": "INTERNAL_HUNT",
    "mode": "check",
    "connection_check": {"id": "check-1"},
}


class SearchingConnector(DummyHuntConnector):
    """Declares its permissions and tests its search."""

    required_permissions = (("search", "Run the hunt searches"),)
    documentation_url = "https://docs.example.com/hunt"

    def connection_test_query(self):
        return NativeQuery(language="test", query="index=* | head 1")


@pytest.fixture
def searching_connector(hunt_settings, hunt_helper):
    connector = SearchingConnector(hunt_settings)
    connector._helper = hunt_helper
    connector._logger = MagicMock()
    return connector


def reported_checks(hunt_helper):
    check_id, checks = hunt_helper.report_hunt_connection_check.call_args.args
    assert check_id == "check-1"
    return checks


def test_registers_the_permissions_and_the_documentation_it_declares(
    searching_connector, hunt_helper
):
    # Given/When the connector registers its platform
    searching_connector.register_platform()

    # Then OpenCTI receives what the account needs and where it is documented
    kwargs = hunt_helper.register_hunt_platform.call_args.kwargs
    assert kwargs["required_permissions"] == [
        {"name": "search", "purpose": "Run the hunt searches"}
    ]
    assert kwargs["documentation_url"] == "https://docs.example.com/hunt"


def test_reports_a_passed_connection_test(searching_connector, hunt_helper):
    # Given a platform answering the test search with an event
    searching_connector.result = HuntResult(
        events=[HuntEvent(timestamp=datetime.now(timezone.utc), fields={"a": 1})]
    )

    # When OpenCTI asks for a connection test
    message = searching_connector.process_message(dict(CHECK_EVENT))

    # Then the search runs over a short window with one result, and passes
    native_query, time_window, limits = searching_connector.executed[0]
    assert native_query.query == "index=* | head 1"
    assert limits.max_results == 1
    assert (time_window.end - time_window.start).total_seconds() == 900
    assert reported_checks(hunt_helper) == [
        {
            "name": "Search",
            "ok": True,
            "message": "The account can run searches on the platform.",
        }
    ]
    assert message == "Connection test passed"
    hunt_helper.report_hunt_run.assert_not_called()


def test_a_search_finding_nothing_passes_with_a_warning(
    searching_connector, hunt_helper
):
    # Given/When the test search is allowed but finds no event
    searching_connector.process_message(dict(CHECK_EVENT))

    # Then the check passes and says what to verify
    [check] = reported_checks(hunt_helper)
    assert check["ok"] is True
    assert "found no event in the last 15 minutes" in check["message"]


@pytest.mark.parametrize(
    "error, expected",
    [
        pytest.param(
            HuntAccessDeniedError(
                "Access denied: The search was refused (403): the role needs search."
            ),
            "Access denied: The search was refused (403): the role needs search.",
            id="access_denied",
        ),
        pytest.param(
            HuntTimeoutError("slow"),
            "The platform did not answer in time: check its URL and the network path from the connector.",
            id="timeout",
        ),
        pytest.param(ValueError("bad URL"), "ValueError: bad URL", id="unexpected"),
        pytest.param(HuntRequestError(), "HuntRequestError", id="no_message"),
    ],
)
def test_reports_a_failed_check_in_plain_words(
    searching_connector, hunt_helper, error, expected
):
    # Given a platform refusing the search
    searching_connector.result = error

    # When OpenCTI asks for a connection test
    message = searching_connector.process_message(dict(CHECK_EVENT))

    # Then the failed check carries the reason, as the work message does
    [check] = reported_checks(hunt_helper)
    assert check == {"name": "Search", "ok": False, "message": expected}
    assert message == f"Connection test failed: {expected}"


def test_a_connector_without_a_test_search_says_so(connector_factory, hunt_helper):
    # Given/When a connector without a test search is asked for a connection test
    connector_factory().process_message(dict(CHECK_EVENT))

    # Then the test fails and says how to check the connection instead
    [check] = reported_checks(hunt_helper)
    assert check["ok"] is False
    assert "Run now" in check["message"]


def test_a_connector_running_no_check_fails_the_test(
    searching_connector, hunt_helper, monkeypatch
):
    # Given a connector overriding the checks with none
    monkeypatch.setattr(searching_connector, "connection_checks", lambda deadline: [])

    # When/Then the test is reported failed rather than passed
    searching_connector.process_message(dict(CHECK_EVENT))
    assert reported_checks(hunt_helper) == [
        {"name": "Connection", "ok": False, "message": "The connector ran no check."}
    ]


def test_refuses_a_connection_test_without_its_id(searching_connector):
    # Given/When/Then a test message without its id is invalid
    with pytest.raises(HuntRequestError, match="connection_check.id"):
        searching_connector.process_message({**CHECK_EVENT, "connection_check": None})


def test_refuses_a_connection_test_on_a_pycti_without_it(
    searching_connector, hunt_helper
):
    # Given a pycti helper that cannot report connection tests
    del hunt_helper.report_hunt_connection_check

    # When/Then the connector says which pycti it needs
    with pytest.raises(HuntUnsupportedPyctiError, match="connection tests"):
        searching_connector.process_message(dict(CHECK_EVENT))


def test_run_check_turns_a_call_into_a_check(searching_connector):
    # Given/When/Then a passing call is a passed check with its meaning
    assert searching_connector.run_check(
        "Authentication", lambda: None, "The token is valid."
    ) == HuntConnectionCheck(
        name="Authentication", ok=True, message="The token is valid."
    )
