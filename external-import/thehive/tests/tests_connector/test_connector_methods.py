"""
Unit tests for connector.connector.TheHive methods.

All tests use a pre-built connector fixture with TheHiveApi patched out (no real HTTP calls).
"""

import time
from unittest.mock import MagicMock, patch

import connector.connector as module
import pytest
from connector.constants import PAP_MAPPINGS, TLP_MAPPINGS

IDENTITY_ID = "identity--a5f78c07-79e2-4e8a-b1dd-fa3e5e5f1a5c"

NOW_MS = int(time.time() * 1000)


def _make_mock_config(
    import_from_date=None,
    import_only_tlp=None,
    import_alerts=False,
    import_attachments=False,
    case_tag_whitelist=None,
    severity_mapping=None,
    case_status_mapping=None,
    task_status_mapping=None,
    user_mapping=None,
):
    cfg = MagicMock()
    cfg.thehive.url = "http://thehive.example.com"
    cfg.thehive.api_key = "test-api-key"
    cfg.thehive.check_ssl = False
    cfg.thehive.organization_name = "TestOrg"
    cfg.thehive.import_from_date = import_from_date
    cfg.thehive.import_only_tlp = import_only_tlp or ["0", "1", "2", "3", "4"]
    cfg.thehive.import_alerts = import_alerts
    cfg.thehive.import_attachments = import_attachments
    cfg.thehive.severity_mapping = severity_mapping or [
        "1:low",
        "2:medium",
        "3:high",
        "4:critical",
    ]
    cfg.thehive.case_status_mapping = case_status_mapping or []
    cfg.thehive.case_tag_whitelist = case_tag_whitelist or []
    cfg.thehive.task_status_mapping = task_status_mapping or []
    cfg.thehive.alert_status_mapping = []
    cfg.thehive.user_mapping = user_mapping or []
    return cfg


@pytest.fixture
def connector():
    with patch.object(module, "TheHiveApi"):
        c = module.TheHive(_make_mock_config(), MagicMock())
        c.current_state = {}
        return c


def _make_case(title="Test Case", tlp=1, pap=0, severity=2, tags=None):
    return {
        "_id": "case-001",
        "title": title,
        "description": "A test case",
        "_createdAt": NOW_MS,
        "_updatedAt": NOW_MS + 1000,
        "tlp": tlp,
        "pap": pap,
        "severity": severity,
        "tags": tags or ["tag1"],
        "extendedStatus": "Open",
        "owner": "user@example.com",
    }


# ---------------------------------------------------------------------------
# Constructor — import_from_date branch
# ---------------------------------------------------------------------------


def test_constructor_with_import_from_date():
    with patch.object(module, "TheHiveApi"):
        c = module.TheHive(
            _make_mock_config(import_from_date="2023-01-01T00:00:00"),
            MagicMock(),
        )
        assert c.thehive_import_from_date > 0


# ---------------------------------------------------------------------------
# construct_query
# ---------------------------------------------------------------------------


def test_construct_query_case_no_whitelist(connector):
    query = connector.construct_query("case", time.time())
    assert query is not None


def test_construct_query_case_with_whitelist():
    with patch.object(module, "TheHiveApi"):
        c = module.TheHive(
            _make_mock_config(case_tag_whitelist=["incident", "malware"]),
            MagicMock(),
        )
        query = c.construct_query("case", time.time())
        assert query is not None


def test_construct_query_alert(connector):
    query = connector.construct_query("alert", time.time())
    assert query is not None


def test_construct_query_invalid_type_raises(connector):
    with pytest.raises(ValueError, match="Unsupported type"):
        connector.construct_query("unknown", time.time())


# ---------------------------------------------------------------------------
# convert_observable
# ---------------------------------------------------------------------------


def test_convert_observable_valid(connector):
    observable = {"dataType": "ipv4", "data": "1.2.3.4", "ioc": False, "tags": []}
    result = connector.convert_observable(observable, [])
    assert result is not None
    assert result.type == "ipv4-addr"


def test_convert_observable_unsupported_type_returns_none(connector):
    observable = {
        "dataType": "totally-unsupported-xyz",
        "data": "somevalue",
        "ioc": False,
        "tags": [],
    }
    result = connector.convert_observable(observable, [])
    assert result is None
    connector.helper.connector_logger.warning.assert_called_once()


# ---------------------------------------------------------------------------
# get_last_date
# ---------------------------------------------------------------------------


def test_get_last_date_from_state(connector):
    connector.current_state = {"last_case_date": 12345.0}
    result = connector.get_last_date("last_case_date", 99999.0)
    assert result == 12345.0


def test_get_last_date_default(connector):
    connector.current_state = {}
    result = connector.get_last_date("last_case_date", 99999.0)
    assert result == 99999.0


# ---------------------------------------------------------------------------
# get_marking
# ---------------------------------------------------------------------------


def test_get_marking_existing_key(connector):
    result = connector.get_marking(TLP_MAPPINGS, 1)
    assert result == TLP_MAPPINGS[1]


def test_get_marking_missing_key_falls_back_to_zero(connector):
    result = connector.get_marking(TLP_MAPPINGS, 99)
    assert result == TLP_MAPPINGS[0]


# ---------------------------------------------------------------------------
# get_updated_date
# ---------------------------------------------------------------------------


def test_get_updated_date_uses_updated_at(connector):
    item = {"_updatedAt": 2000000, "_createdAt": 1000000}
    result = connector.get_updated_date(item, 0)
    assert result == int(2000000 / 1000) + 1


def test_get_updated_date_uses_created_at_when_no_updated(connector):
    item = {"_createdAt": 1000000}
    result = connector.get_updated_date(item, 0)
    assert result == int(1000000 / 1000) + 1


def test_get_updated_date_uses_updated_at_none(connector):
    item = {"_updatedAt": None, "_createdAt": 1000000}
    result = connector.get_updated_date(item, 0)
    assert result == int(1000000 / 1000) + 1


def test_get_updated_date_respects_last_date(connector):
    item = {"_updatedAt": 1000, "_createdAt": 1000}
    # last_date is larger than new_date
    result = connector.get_updated_date(item, 9999.0)
    assert result == 9999.0


# ---------------------------------------------------------------------------
# not_found_items
# ---------------------------------------------------------------------------


def test_not_found_items_raises(connector):
    items = {"message": "Not Found", "type": "404"}
    with pytest.raises(Exception):
        connector.not_found_items(items, "case")


# ---------------------------------------------------------------------------
# process_markings
# ---------------------------------------------------------------------------


def test_process_markings_returns_two_markings(connector):
    item = {"tlp": 1, "pap": 0}
    markings = connector.process_markings(item)
    assert len(markings) == 2
    assert markings[0] == TLP_MAPPINGS[1]
    assert markings[1] == PAP_MAPPINGS[0]


def test_process_markings_unknown_tlp_falls_back(connector):
    item = {"tlp": 99, "pap": 0}
    markings = connector.process_markings(item)
    assert markings[0] == TLP_MAPPINGS[0]


# ---------------------------------------------------------------------------
# generate_sighting
# ---------------------------------------------------------------------------


def test_generate_sighting_sighted_true(connector):
    from stix2 import IPv4Address

    stix_obs = IPv4Address(value="1.2.3.4")
    observable = {"sighted": True, "startDate": NOW_MS}
    sighting = connector.generate_sighting(observable, stix_obs)
    assert sighting is not None
    assert sighting.type == "sighting"


def test_generate_sighting_sighted_false(connector):
    from stix2 import IPv4Address

    stix_obs = IPv4Address(value="5.6.7.8")
    observable = {"sighted": False}
    sighting = connector.generate_sighting(observable, stix_obs)
    assert sighting is None


def test_generate_sighting_missing_sighted(connector):
    from stix2 import IPv4Address

    stix_obs = IPv4Address(value="9.10.11.12")
    observable = {}
    sighting = connector.generate_sighting(observable, stix_obs)
    assert sighting is None


# ---------------------------------------------------------------------------
# create_stix_alert_incident
# ---------------------------------------------------------------------------


def test_create_stix_alert_incident(connector):
    alert = {
        "title": "Phishing attempt",
        "description": "Suspicious email",
        "tags": ["phishing"],
        "source": "email-gateway",
        "severity": 2,
    }
    created = "2023-01-01T00:00:00Z"
    modified = "2023-01-01T01:00:00Z"
    incident = connector.create_stix_alert_incident(alert, [], created, modified)
    assert incident.type == "incident"
    assert incident.name == "Phishing attempt"


# ---------------------------------------------------------------------------
# process_tasks
# ---------------------------------------------------------------------------


def test_process_tasks_empty(connector):
    connector.thehive_api.case.find_tasks.return_value = []
    case = _make_case()
    stix_case = MagicMock()
    stix_case.id = "case-incident--a5f78c07-79e2-4e8a-b1dd-fa3e5e5f1a5c"
    result = connector.process_tasks(case, stix_case)
    assert result == []


def test_process_tasks_with_tasks(connector):
    case = _make_case()
    stix_case = MagicMock()
    stix_case.id = "case-incident--a5f78c07-79e2-4e8a-b1dd-fa3e5e5f1a5c"
    connector.thehive_api.case.find_tasks.return_value = [
        {
            "_id": "task-001",
            "title": "Investigate",
            "description": "Look into logs",
            "_createdAt": NOW_MS,
            "status": "InProgress",
            "assignee": None,
        }
    ]
    result = connector.process_tasks(case, stix_case)
    assert len(result) == 1
    assert result[0].type == "task"


def test_process_tasks_with_status_mapping(connector):
    with patch.object(module, "TheHiveApi"):
        c = module.TheHive(
            _make_mock_config(task_status_mapping=["InProgress:wf-id-1"]),
            MagicMock(),
        )
        c.current_state = {}

    case = _make_case()
    stix_case = MagicMock()
    stix_case.id = "case-incident--a5f78c07-79e2-4e8a-b1dd-fa3e5e5f1a5c"
    c.thehive_api.case.find_tasks.return_value = [
        {
            "_id": "task-002",
            "title": "Contain",
            "description": None,
            "_createdAt": NOW_MS,
            "status": "InProgress",
            "assignee": None,
        }
    ]
    result = c.process_tasks(case, stix_case)
    assert len(result) == 1


def test_process_tasks_with_due_date(connector):
    case = _make_case()
    stix_case = MagicMock()
    stix_case.id = "case-incident--a5f78c07-79e2-4e8a-b1dd-fa3e5e5f1a5c"
    connector.thehive_api.case.find_tasks.return_value = [
        {
            "_id": "task-003",
            "title": "Remediate",
            "description": "Fix it",
            "_createdAt": NOW_MS,
            "dueDate": NOW_MS + 86400000,
            "status": "Waiting",
            "assignee": None,
        }
    ]
    result = connector.process_tasks(case, stix_case)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# process_main_case
# ---------------------------------------------------------------------------


def test_process_main_case_basic(connector):
    case = _make_case()
    markings = [TLP_MAPPINGS[1]]
    stix_case = connector.process_main_case(case, markings, [])
    assert stix_case is not None
    assert stix_case.name == "Test Case"


def test_process_main_case_with_status_mapping(connector):
    with patch.object(module, "TheHiveApi"):
        c = module.TheHive(
            _make_mock_config(case_status_mapping=["Open:wf-status-id-1"]),
            MagicMock(),
        )
        c.current_state = {}

    case = _make_case()
    case["extendedStatus"] = "Open"
    stix_case = c.process_main_case(case, [], [])
    assert stix_case is not None


def test_process_main_case_with_user_mapping(connector):
    with patch.object(module, "TheHiveApi"):
        c = module.TheHive(
            _make_mock_config(user_mapping=["user@example.com:opencti-user-id"]),
            MagicMock(),
        )
        c.current_state = {}

    case = _make_case()
    case["owner"] = "user@example.com"
    stix_case = c.process_main_case(case, [], [])
    assert stix_case is not None


def test_process_main_case_with_severity_mapping(connector):
    case = _make_case(severity=2)
    stix_case = connector.process_main_case(case, [], [])
    assert stix_case is not None
    assert stix_case.severity == "medium"


# ---------------------------------------------------------------------------
# process_comments — missing-createdAt branch
# ---------------------------------------------------------------------------


def test_process_comments_comment_without_created_at(connector):
    case = _make_case()
    stix_case = MagicMock()
    stix_case.id = "x-opencti-case-incident--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    comment = MagicMock()
    comment.get.side_effect = lambda k, d=None: {
        "message": "a comment",
        "_createdAt": None,
        "_id": "c-001",
    }.get(k, d)
    connector.thehive_api.case.find_comments.return_value = [comment]

    result = connector.process_comments(case, stix_case)
    assert len(result) == 1
    assert result[0]["content"] == "a comment"


# ---------------------------------------------------------------------------
# process_observables
# ---------------------------------------------------------------------------


def test_process_observables_empty_response(connector):
    connector.thehive_api.case.find_observables.return_value = []
    case = _make_case()
    observables, refs = connector.process_observables(case, [])
    assert observables == []
    assert refs == []


def test_process_observables_with_valid_observable(connector):
    connector.thehive_api.case.find_observables.return_value = [
        {
            "dataType": "ipv4",
            "data": "1.2.3.4",
            "ioc": False,
            "tags": [],
            "sighted": False,
        }
    ]
    case = _make_case()
    observables, refs = connector.process_observables(case, [])
    assert len(observables) >= 1
    assert len(refs) == 1


def test_process_observables_with_sighted_observable(connector):
    connector.thehive_api.case.find_observables.return_value = [
        {
            "dataType": "ipv4",
            "data": "5.6.7.8",
            "ioc": True,
            "tags": [],
            "sighted": True,
            "startDate": NOW_MS,
        }
    ]
    case = _make_case()
    observables, refs = connector.process_observables(case, [])
    # sighted observable produces stix_obs + sighting = 2 items
    assert len(observables) == 2


def test_process_observables_unsupported_type(connector):
    connector.thehive_api.case.find_observables.return_value = [
        {"dataType": "unknown-xyz", "data": "value", "ioc": False, "tags": []}
    ]
    case = _make_case()
    observables, refs = connector.process_observables(case, [])
    assert observables == []
    assert refs == []


# ---------------------------------------------------------------------------
# process_observables_and_relations
# ---------------------------------------------------------------------------


def test_process_observables_and_relations_valid(connector):

    stix_incident = MagicMock()
    stix_incident.id = "incident--a5f78c07-79e2-4e8a-b1dd-fa3e5e5f1a5c"
    observable = {
        "dataType": "url",
        "data": "https://evil.com",
        "ioc": False,
        "tags": [],
    }
    obs, rel = connector.process_observables_and_relations(
        observable, [], stix_incident
    )
    assert obs is not None
    assert rel is not None
    assert rel.type == "relationship"


def test_process_observables_and_relations_unsupported_returns_none(connector):
    stix_incident = MagicMock()
    stix_incident.id = "incident--a5f78c07-79e2-4e8a-b1dd-fa3e5e5f1a5c"
    observable = {
        "dataType": "totally-unknown-xyz",
        "data": "value",
        "ioc": False,
        "tags": [],
    }
    obs, rel = connector.process_observables_and_relations(
        observable, [], stix_incident
    )
    assert obs is None
    assert rel is None


# ---------------------------------------------------------------------------
# process_items
# ---------------------------------------------------------------------------


def test_process_items_filters_by_tlp(connector):
    bundle_func = MagicMock(return_value={"type": "bundle"})
    connector.helper.api.work.initiate_work.return_value = "work-001"
    connector.current_state = {}

    items = [
        {
            "_id": "a",
            "title": "allowed",
            "tlp": 1,
            "_createdAt": NOW_MS,
            "_updatedAt": NOW_MS,
        },
        {
            "_id": "b",
            "title": "blocked",
            "tlp": 5,
            "_createdAt": NOW_MS,
            "_updatedAt": NOW_MS,
        },
    ]
    connector.process_items("case", items, bundle_func, "last_case_date")

    # Only the TLP-1 item should trigger process_func
    assert bundle_func.call_count == 1
    connector.helper.api.work.to_processed.assert_called_once()


def test_process_items_empty_list(connector):
    bundle_func = MagicMock()
    connector.helper.api.work.initiate_work.return_value = "work-002"
    connector.current_state = {}

    connector.process_items("case", [], bundle_func, "last_case_date")
    bundle_func.assert_not_called()


# ---------------------------------------------------------------------------
# generate_alert_bundle
# ---------------------------------------------------------------------------


def test_generate_alert_bundle(connector):
    alert = {
        "_id": "alert-001",
        "title": "Malware Alert",
        "description": "Detected malware",
        "_createdAt": NOW_MS,
        "_updatedAt": NOW_MS + 1000,
        "tlp": 1,
        "pap": 0,
        "severity": 2,
        "tags": ["malware"],
        "source": "edr",
        "artifacts": [],
    }
    connector.helper.stix2_create_bundle.return_value = {"type": "bundle"}
    result = connector.generate_alert_bundle(alert)
    assert result == {"type": "bundle"}
    connector.helper.stix2_create_bundle.assert_called_once()


def test_generate_alert_bundle_with_observables(connector):
    alert = {
        "_id": "alert-002",
        "title": "Phishing",
        "description": "Phishing email",
        "_createdAt": NOW_MS,
        "_updatedAt": NOW_MS + 1000,
        "tlp": 0,
        "pap": 0,
        "severity": 1,
        "tags": [],
        "source": "email",
        "artifacts": [
            {
                "dataType": "ipv4",
                "data": "9.9.9.9",
                "ioc": True,
                "tags": [],
                "sighted": False,
            }
        ],
    }
    connector.helper.stix2_create_bundle.return_value = {"type": "bundle"}
    result = connector.generate_alert_bundle(alert)
    assert result == {"type": "bundle"}


# ---------------------------------------------------------------------------
# generate_case_bundle
# ---------------------------------------------------------------------------


def test_generate_case_bundle(connector):
    case = _make_case()
    connector.thehive_api.case.find_observables.return_value = []
    connector.thehive_api.case.find_tasks.return_value = []
    connector.thehive_api.case.find_comments.return_value = []
    connector.helper.stix2_create_bundle.return_value = {"type": "bundle"}
    result = connector.generate_case_bundle(case)
    assert result == {"type": "bundle"}


def test_generate_case_bundle_with_attachments():
    with patch.object(module, "TheHiveApi"):
        c = module.TheHive(
            _make_mock_config(import_attachments=True),
            MagicMock(),
        )
        c.current_state = {}

    case = _make_case()
    c.thehive_api.case.find_observables.return_value = []
    c.thehive_api.case.find_tasks.return_value = []
    c.thehive_api.case.find_comments.return_value = []
    c.thehive_api.case.find_attachments.return_value = []
    c.helper.stix2_create_bundle.return_value = {"type": "bundle"}
    result = c.generate_case_bundle(case)
    assert result == {"type": "bundle"}


# ---------------------------------------------------------------------------
# process_message
# ---------------------------------------------------------------------------


def test_process_message_cases_only(connector):
    connector.helper.get_state.return_value = {}
    connector.thehive_api.case.find.return_value = []
    connector.process_logic = MagicMock()
    connector.process_message()
    # process_logic called once for cases (import_alerts=False by default)
    assert connector.process_logic.call_count == 1
    connector.process_logic.assert_called_with(
        "case", "last_case_date", connector.generate_case_bundle
    )


def test_process_message_with_alerts():
    with patch.object(module, "TheHiveApi"):
        c = module.TheHive(
            _make_mock_config(import_alerts=True),
            MagicMock(),
        )
        c.current_state = {}

    c.helper.get_state.return_value = {"last_case_date": 1000.0}
    c.process_logic = MagicMock()
    c.process_message()
    assert c.process_logic.call_count == 2


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def test_run_calls_schedule_iso(connector):
    connector.run()
    connector.helper.schedule_iso.assert_called_once_with(
        message_callback=connector.process_message,
        duration_period=connector.config.connector.duration_period,
    )
