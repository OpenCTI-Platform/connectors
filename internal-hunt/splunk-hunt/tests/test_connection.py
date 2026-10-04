from conftest import NAMESPACE, SPLUNK_URL

CONTEXT = f"{SPLUNK_URL}/services/authentication/current-context"
CHECK_EVENT = {
    "event_type": "INTERNAL_HUNT",
    "mode": "check",
    "connection_check": {"id": "check-1"},
}


def _context(capabilities):
    return {
        "entry": [
            {
                "content": {
                    "username": "svc_opencti_hunt",
                    "capabilities": capabilities,
                }
            }
        ]
    }


def _mock_job(requests_mock, rows):
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(
        f"{NAMESPACE}/search/jobs/sid-1",
        json={"entry": [{"content": {"isDone": True, "resultCount": len(rows)}}]},
    )
    requests_mock.get(
        f"{NAMESPACE}/search/v2/jobs/sid-1/results", json={"results": rows}
    )
    requests_mock.delete(f"{NAMESPACE}/search/jobs/sid-1", json={})


def _checks(helper):
    check_id, checks = helper.report_hunt_connection_check.call_args.args
    assert check_id == "check-1"
    return checks


def test_connection_test_checks_the_account_then_searches(
    connector_factory, helper, requests_mock
):
    # Given an account holding the search capability and an index with events
    requests_mock.get(CONTEXT, json=_context(["search", "edit_tokens_own"]))
    _mock_job(requests_mock, [{"_time": "2026-10-04T10:00:00Z", "host": "ws-1"}])

    # When OpenCTI asks for a connection test
    message = connector_factory().process_message(dict(CHECK_EVENT))

    # Then the credentials, the capability and the search pass
    checks = _checks(helper)
    assert [check["name"] for check in checks] == [
        "Authentication",
        "search",
        "Search",
    ]
    assert all(check["ok"] for check in checks)
    assert "svc_opencti_hunt" in checks[1]["message"]
    assert message == "Connection test passed"
    search = requests_mock.request_history[1].text
    assert "head+1" in search


def test_connection_test_names_the_missing_capability(
    connector_factory, helper, requests_mock
):
    # Given an account whose roles lack the search capability
    requests_mock.get(CONTEXT, json=_context(["edit_tokens_own"]))

    # When/Then the test stops on the capability and says where to add it
    connector_factory().process_message(dict(CHECK_EVENT))
    checks = _checks(helper)
    assert checks[-1]["ok"] is False
    assert checks[-1]["message"] == (
        "Access denied: the roles of svc_opencti_hunt lack the search capability: "
        "add it to one of its roles in Settings > Roles."
    )


def test_connection_test_reports_refused_credentials_in_plain_words(
    connector_factory, helper, requests_mock
):
    # Given Splunk refusing the token
    requests_mock.get(CONTEXT, status_code=401)

    # When/Then the only check names the token to fix
    connector_factory().process_message(dict(CHECK_EVENT))
    [check] = _checks(helper)
    assert check["name"] == "Authentication"
    assert check["ok"] is False
    assert check["message"].startswith(
        "Access denied: The Splunk authentication was refused (401): Splunk refused the token"
    )
    assert "Settings > Tokens" in check["message"]


def test_a_refused_search_names_the_role_to_fix(
    connector_factory, helper, requests_mock
):
    # Given an account allowed to search, refused by the app namespace
    requests_mock.get(CONTEXT, json=_context(["search"]))
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", status_code=403)

    # When/Then the search check carries the same sentence as a failed run
    connector_factory().process_message(dict(CHECK_EVENT))
    check = _checks(helper)[-1]
    assert check["ok"] is False
    assert "read access to the app SPLUNK_HUNT_APP" in check["message"]
