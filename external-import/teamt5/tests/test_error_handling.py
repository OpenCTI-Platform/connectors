"""Unit tests for the error handling of ``teamt5_connector.connector.TeamT5Connector``."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest
import requests
from connectors_sdk import (
    Criticity,
    DataConversionError,
    ProviderApiAuthenticationError,
    ProviderApiAuthorizationError,
    ProviderApiConnectionError,
    ProviderApiInvalidResponseError,
    ProviderApiNotFoundError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
    ProviderApiUnknownError,
)
from pycti import OpenCTIApiClient, OpenCTIApiWork, OpenCTIConnectorHelper
from pydantic import SecretStr
from requests.structures import CaseInsensitiveDict
from teamt5_connector.connector import TeamT5Connector
from teamt5_connector.indicator_bundle_handler import IndicatorBundleHandler
from teamt5_connector.report_handler import ReportHandler
from teamt5_services import Teamt5Client


@pytest.fixture
def config():
    """The connector settings read by ``TeamT5Connector`` and ``Teamt5Client``.

    The client authenticates with the static API key, so it does not exchange
    an OAuth token when it is built.
    """
    return SimpleNamespace(
        connector=SimpleNamespace(name="TeamT5", duration_period=3600),
        teamt5=SimpleNamespace(
            tlp_level="clear",
            first_run_retrieval_timestamp=0,
            api_base_url="https://api.threatvision.org/",
            api_key=SecretStr("test-key"),
            client_id=None,
            client_secret=None,
        ),
    )


@pytest.fixture
def helper():
    """A mock of ``OpenCTIConnectorHelper``, with the attributes it creates in
    ``__init__`` specced explicitly, since ``spec`` cannot see them."""
    helper = MagicMock(spec=OpenCTIConnectorHelper)
    helper.api = MagicMock(spec=OpenCTIApiClient)
    helper.api.work = MagicMock(spec=OpenCTIApiWork)
    helper.connector_logger = MagicMock()
    helper.connect_id = "connector-id"
    helper.connect_name = "TeamT5"
    return helper


@pytest.fixture
def request_session():
    """A mock of ``requests.Session``, with the ``headers`` it creates in
    ``__init__`` set explicitly, since ``spec`` cannot see them."""
    session = MagicMock(spec=requests.Session)
    session.headers = CaseInsensitiveDict()
    return session


@pytest.fixture
def connector(config, helper, request_session):
    """A ``TeamT5Connector`` with a real ``Teamt5Client`` using the ``session`` mock."""
    with patch(
        "teamt5_services.client.requests.Session", return_value=request_session
    ) as session_class:
        connector = TeamT5Connector(config, helper)
    session_class.assert_called_once_with()
    return connector


@pytest.fixture
def teamt5_client():
    """A mock of a ``Teamt5Client`` instance, on which a test sets what
    ``request_data`` returns instead of mocking HTTP responses."""
    return MagicMock(spec=Teamt5Client)


@pytest.fixture
def connector_with_mock_client(config, helper, teamt5_client):
    """A ``TeamT5Connector`` whose client, shared by its handlers, is the
    ``teamt5_client`` mock."""
    with patch(
        "teamt5_connector.connector.Teamt5Client", return_value=teamt5_client
    ) as client_class:
        connector = TeamT5Connector(config, helper)
    client_class.assert_called_once_with(helper, config)
    return connector


def _mock_handler(handler_class):
    """A mock of a handler that finds nothing new, with the attributes it
    creates in ``__init__`` set explicitly, since ``spec`` cannot see them."""
    handler = MagicMock(spec=handler_class)
    handler.name = handler_class.name
    handler.aborted = False
    handler.partial_push = False
    handler.retrieve_bundle_references.return_value = []
    return handler


@pytest.fixture
def connector_with_mock_handler(connector_with_mock_client):
    """The ``connector_with_mock_client`` connector, whose handlers are
    replaced by mocks, reachable as ``connector.report_handler`` and
    ``connector.indicator_bundle_handler``. By default, both find nothing new."""
    connector = connector_with_mock_client
    connector.report_handler = _mock_handler(ReportHandler)
    connector.indicator_bundle_handler = _mock_handler(IndicatorBundleHandler)
    return connector


def _http_error(status_code):
    """An ``HTTPError`` carrying a response with ``status_code``, as
    ``Response.raise_for_status`` raises it."""
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    return requests.HTTPError(f"{status_code} Error", response=response)


@pytest.mark.parametrize(
    "exception, message, expected_error",
    [
        pytest.param(
            requests.ConnectionError("Connection refused"),
            "ConnectionError",
            ProviderApiConnectionError,
            id="connection-error",
        ),
        pytest.param(
            requests.ConnectTimeout("Connect timed out"),
            "ConnectTimeout",
            ProviderApiTimeoutError,
            id="connect-timeout",
        ),
        pytest.param(
            requests.ReadTimeout("Read timed out"),
            "ReadTimeout",
            ProviderApiTimeoutError,
            id="read-timeout",
        ),
        pytest.param(
            _http_error(401),
            "HTTP 401",
            ProviderApiAuthenticationError,
            id="http-401",
        ),
        pytest.param(
            _http_error(403),
            "HTTP 403",
            ProviderApiAuthorizationError,
            id="http-403",
        ),
        pytest.param(
            _http_error(404),
            "HTTP 404",
            ProviderApiNotFoundError,
            id="http-404",
        ),
        pytest.param(
            _http_error(429),
            "HTTP 429",
            ProviderApiRateLimitError,
            id="http-429",
        ),
        pytest.param(
            _http_error(503),
            "HTTP 503",
            ProviderApiServerError,
            id="http-503",
        ),
        pytest.param(
            _http_error(418),
            "HTTP 418",
            ProviderApiUnknownError,
            id="http-418",
        ),
        pytest.param(
            requests.JSONDecodeError("Expecting value", "not json", 0),
            "JSONDecodeError",
            ProviderApiInvalidResponseError,
            id="json-decode-error",
        ),
        pytest.param(
            requests.TooManyRedirects("Exceeded 30 redirects"),
            "TooManyRedirects",
            ProviderApiUnknownError,
            id="other-request-exception",
        ),
    ],
)
def test_request_exception_returns_errors(
    connector, helper, request_session, exception, message, expected_error
):
    helper.get_state.return_value = None
    request_session.get.side_effect = exception

    errors = connector.process_message()

    # Every listing page fails: each handler stops at its first page, whose
    # failure is reported once, by the client, with its cause
    assert isinstance(errors, list)
    assert len(errors) == 2
    for error in errors:
        assert "code" in error
        assert "criticity" in error
        assert message in error["message"]
        assert error["code"] == expected_error.code
        # The URL stays out of the reported message: it may be signed
        assert "threatvision" not in error["message"]


def _response(payload):
    """A successful ``requests.Response`` whose JSON body is ``payload``."""
    response = MagicMock(spec=requests.Response)
    response.json.return_value = payload
    return response


@pytest.mark.parametrize(
    "exception, expected_code, expected_criticity, expected_message",
    [
        pytest.param(
            ProviderApiAuthenticationError("Invalid API key"),
            "api.authentication",
            Criticity.CRITICAL,
            "Invalid API key",
            id="critical-connector-error",
        ),
        pytest.param(
            DataConversionError("Invalid API key"),
            "data.conversion",
            Criticity.WARNING,
            "Invalid API key",
            id="warning-connector-error",
        ),
        pytest.param(
            RuntimeError("Invalid API key"),
            "other.unknown",
            Criticity.CRITICAL,
            "RuntimeError: Invalid API key",
            id="not-a-connector-error",
        ),
    ],
)
def test_error_stopping_the_run_is_returned(
    connector_with_mock_client,
    helper,
    teamt5_client,
    exception,
    expected_code,
    expected_criticity,
    expected_message,
):
    helper.get_state.return_value = None
    teamt5_client.request_data.side_effect = exception

    errors = connector_with_mock_client.process_message()

    # A connector error is reported with its own code, criticity and message,
    # any other exception as an UnknownError whose message names its type
    assert errors == [
        {
            "code": expected_code,
            "message": expected_message,
            "criticity": int(expected_criticity),
        }
    ]
    # The run stopped at the first request: no work was opened, the cursor
    # is not advanced
    teamt5_client.request_data.assert_called_once()
    helper.api.work.initiate_work.assert_not_called()
    helper.set_state.assert_not_called()


LAST_RUN = "2026-11-01T00:00:00+00:00"
REF_1 = {"id": "1", "created_at": 0, "stix_url": "https://example.org/1.stix"}
REF_2 = {"id": "2", "created_at": 0, "stix_url": "https://example.org/2.stix"}


def _handler_outcome(refs=(), pushed=None, aborted=False, partial_push=False):
    """What a mocked handler does in a run: the references it retrieves, how many
    bundles it pushes (all of them by default), and its failure flags."""
    return SimpleNamespace(
        refs=list(refs),
        pushed=len(refs) if pushed is None else pushed,
        aborted=aborted,
        partial_push=partial_push,
    )


def _set_outcome(handler, outcome):
    handler.retrieve_bundle_references.return_value = outcome.refs
    handler.push_objects.return_value = outcome.pushed
    handler.aborted = outcome.aborted
    handler.partial_push = outcome.partial_push


@pytest.mark.parametrize(
    "state, report, indicator_bundle, cursor_advanced",
    [
        pytest.param(
            {"last_run": LAST_RUN},
            _handler_outcome([REF_1]),
            _handler_outcome(),
            True,
            id="new-reports-only",
        ),
        pytest.param(
            {"last_run": LAST_RUN},
            _handler_outcome([REF_1]),
            _handler_outcome([REF_1, REF_2]),
            True,
            id="new-objects-for-both-handlers",
        ),
        pytest.param(
            {"last_run": LAST_RUN},
            _handler_outcome(),
            _handler_outcome(),
            True,
            id="nothing-new",
        ),
        pytest.param(
            None,
            _handler_outcome([REF_1]),
            _handler_outcome([REF_2]),
            True,
            id="first-run-without-state",
        ),
        pytest.param(
            {},
            _handler_outcome(),
            _handler_outcome([REF_2]),
            True,
            id="first-run-with-state-without-last-run",
        ),
        pytest.param(
            {"last_run": LAST_RUN},
            _handler_outcome([REF_1, REF_2], pushed=1, partial_push=True),
            _handler_outcome(),
            False,
            id="partial-push",
        ),
        pytest.param(
            {"last_run": LAST_RUN},
            _handler_outcome(),
            _handler_outcome(aborted=True),
            False,
            id="listing-aborted-without-references",
        ),
        pytest.param(
            {"last_run": LAST_RUN},
            _handler_outcome([REF_1], aborted=True),
            _handler_outcome(),
            False,
            id="listing-aborted-with-references",
        ),
    ],
)
def test_run_ok(
    connector_with_mock_handler,
    helper,
    state,
    report,
    indicator_bundle,
    cursor_advanced,
):
    connector = connector_with_mock_handler
    handlers = [
        (connector.report_handler, report),
        (connector.indicator_bundle_handler, indicator_bundle),
    ]
    for handler, outcome in handlers:
        _set_outcome(handler, outcome)
    helper.get_state.return_value = state
    # One work per handler that retrieved references, in the handlers' order
    helper.api.work.initiate_work.side_effect = ["work-1", "work-2"]

    errors = connector.process_message()

    # Nothing failed in a way that stops the run: no error is reported
    assert errors == []

    # The listing starts from last_run, or from the configured timestamp on the
    # first run
    expected_timestamp = (
        int(datetime.fromisoformat(LAST_RUN).timestamp())
        if state and "last_run" in state
        else connector.config.teamt5.first_run_retrieval_timestamp
    )
    work_ids = iter(["work-1", "work-2"])
    expected_initiate_calls = []
    expected_to_processed_calls = []
    for handler, outcome in handlers:
        handler.retrieve_bundle_references.assert_called_once_with(expected_timestamp)
        if outcome.refs:
            # A handler with references pushes them in a work of its own, closed
            # in error when not every bundle was pushed
            work_id = next(work_ids)
            handler.push_objects.assert_called_once_with(work_id, outcome.refs)
            expected_initiate_calls.append(
                call(helper.connect_id, f"Creating {handler.name}s from TeamT5")
            )
            expected_to_processed_calls.append(
                call(
                    work_id,
                    f"Connector Pushed {outcome.pushed} {handler.name}s",
                    in_error=outcome.partial_push,
                )
            )
        else:
            handler.push_objects.assert_not_called()
    assert helper.api.work.initiate_work.call_args_list == expected_initiate_calls
    assert helper.api.work.to_processed.call_args_list == expected_to_processed_calls

    # last_run is advanced only when every handler completed without failure
    if cursor_advanced:
        helper.set_state.assert_called_once()
        new_state = helper.set_state.call_args.args[0]
        assert datetime.fromisoformat(new_state["last_run"]) > datetime.fromisoformat(
            LAST_RUN
        )
    else:
        helper.set_state.assert_not_called()


@pytest.mark.parametrize(
    "exception, expected_code, expected_message",
    [
        pytest.param(
            ProviderApiServerError("Bundle download failed"),
            "api.server",
            "Bundle download failed",
            id="connector-error",
        ),
        pytest.param(
            RuntimeError("Bundle download failed"),
            "other.unknown",
            "RuntimeError: Bundle download failed",
            id="not-a-connector-error",
        ),
    ],
)
def test_push_failure_closes_work_in_error(
    connector_with_mock_handler, helper, exception, expected_code, expected_message
):
    connector = connector_with_mock_handler
    connector.report_handler.retrieve_bundle_references.return_value = [REF_1]
    connector.report_handler.push_objects.side_effect = exception
    helper.get_state.return_value = {"last_run": LAST_RUN}
    helper.api.work.initiate_work.return_value = "work-1"

    errors = connector.process_message()

    # The work opened for the push is closed in error, with the failure
    connector.report_handler.push_objects.assert_called_once_with("work-1", [REF_1])
    helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Unhandled exception: Bundle download failed", in_error=True
    )
    assert [(error["code"], error["message"]) for error in errors] == [
        (expected_code, expected_message)
    ]
    # The run stopped: the next handler did not run, last_run is not advanced
    connector.indicator_bundle_handler.retrieve_bundle_references.assert_not_called()
    helper.set_state.assert_not_called()


def test_work_close_failure_is_reported(connector_with_mock_handler, helper):
    connector = connector_with_mock_handler
    connector.report_handler.retrieve_bundle_references.return_value = [REF_1]
    connector.report_handler.push_objects.side_effect = RuntimeError(
        "Bundle download failed"
    )
    helper.get_state.return_value = {"last_run": LAST_RUN}
    helper.api.work.initiate_work.return_value = "work-1"
    helper.api.work.to_processed.side_effect = RuntimeError("OpenCTI unreachable")

    errors = connector.process_message()

    # The close was attempted; its failure is reported before the error that
    # stopped the run, instead of crashing the error handling
    helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Unhandled exception: Bundle download failed", in_error=True
    )
    assert [error["code"] for error in errors] == ["octi.unreachable", "other.unknown"]
    assert errors[0]["message"] == (
        "Failed to mark work work-1 as in_error: OpenCTI unreachable"
    )
