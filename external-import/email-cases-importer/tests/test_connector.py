"""Orchestration tests for connector.connector.EmailCasesConnector.

These exercise the import loop, per-email processing, deterministic Case-Incident
id generation, the OpenCTI-resolution helpers (labels/identities/markings/members),
subject/sender rule matching, vocabulary bootstrap, case templates, and the
timeout wrappers — all against a mocked OpenCTI helper and a fake email client.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pycti
import pytest

import connector.connector as connector_mod
from connector.connector import EmailCasesConnector
from email_client.base import EmailAttachment, EmailMessage


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #
def make_config(**overrides):
    """Build a config whose `.email_cases` matches the runtime settings surface."""
    ec = SimpleNamespace(
        import_interval=300,
        sender_address="alerts@example.com",
        password_prefix="---BEGIN PASSWORD---",
        password_suffix="---END PASSWORD---",
        password_strip_whitespace=False,
        thread_tracking_strategy="provider_thread_id",
        max_attachment_size_mb=25,
        max_emails_per_cycle=50,
        display_sender_names=True,
        email_fetch_timeout=120,
        default_severity="medium",
        default_priority="P3",
        case_prefix="",
        protocol="imap",
    )
    for key in (
        "import_interval",
        "sender_address",
        "thread_tracking_strategy",
        "case_prefix",
        "default_severity",
        "default_priority",
        "display_sender_names",
        "email_fetch_timeout",
        "max_emails_per_cycle",
    ):
        if key in overrides:
            setattr(ec, key, overrides[key])

    ec.get_parsed_subject_filters = lambda: overrides.get("subject_filters", [])
    ec.get_parsed_labels = lambda: overrides.get("labels", [])
    ec.get_parsed_subject_rules = lambda: overrides.get("subject_rules", [])
    ec.get_parsed_sender_rules = lambda: overrides.get("sender_rules", [])
    ec.get_parsed_start_date = lambda: overrides.get("start_date", None)
    return SimpleNamespace(email_cases=ec)


def make_email(**overrides):
    base = dict(
        message_id="<m1@example.com>",
        subject="Security Alert",
        sender="alerts@example.com",
        recipients=["soc@company.com"],
        date=datetime(2026, 4, 8, 12, 30, 0, tzinfo=timezone.utc),
        body_plain="hello body",
        body_html="",
        thread_id="thread-1",
        sender_display="Alerts <alerts@example.com>",
        recipients_display=["SOC <soc@company.com>"],
    )
    base.update(overrides)
    return EmailMessage(**base)


class FakeClient:
    """Context-manager email client returning a fixed list of emails."""

    def __init__(self, emails=None):
        self._emails = emails or []
        self.connected = False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *a):
        self.disconnect()
        return False

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.connected = False

    def fetch_emails(self, sender, since=None, max_results=50):
        return self._emails

    def get_thread_id(self, message):
        return message.thread_id


@pytest.fixture
def helper():
    h = MagicMock()
    h.get_state.return_value = None
    h.connect_id = "connector-id"
    h.api.work.initiate_work.return_value = "work-1"
    h.api.case_incident.create.return_value = {"id": "case-internal-1"}
    h.api.case_incident.list.return_value = []
    h.api.label.create.return_value = {"id": "label-1"}
    h.api.identity.create.return_value = {"id": "identity-1"}
    h.api.marking_definition.read.return_value = {"id": "marking-1"}
    h.api.query.return_value = {"data": {}}
    return h


@pytest.fixture
def conn(helper):
    return EmailCasesConnector(make_config(), helper)


def build(helper, **cfg):
    return EmailCasesConnector(make_config(**cfg), helper)


# --------------------------------------------------------------------------- #
# _create_case — deterministic id (the PR #6164 standard)
# --------------------------------------------------------------------------- #
class TestCreateCaseDeterministicId:
    def test_passes_pycti_generated_stix_id_and_created(self, conn, helper):
        email = make_email(subject="Security Alert")
        normalized = "Security Alert"
        conn._create_case(email, normalized, "<p>content</p>")

        kwargs = helper.api.case_incident.create.call_args.kwargs
        created_iso = email.date.strftime("%Y-%m-%dT%H:%M:%SZ")
        expected_id = pycti.CaseIncident.generate_id(
            name=normalized, created=created_iso
        )
        assert kwargs["stix_id"] == expected_id
        assert kwargs["created"] == created_iso
        assert kwargs["name"] == normalized
        assert kwargs["createdBy"] == conn.converter.identity_id

    def test_same_email_yields_same_id(self, conn, helper):
        email = make_email()
        conn._create_case(email, "Security Alert", "c")
        first = helper.api.case_incident.create.call_args.kwargs["stix_id"]
        helper.api.case_incident.create.reset_mock()
        conn._create_case(email, "Security Alert", "c")
        second = helper.api.case_incident.create.call_args.kwargs["stix_id"]
        assert first == second

    def test_prefix_applied_to_name(self, helper):
        c = build(helper, case_prefix="[IR] ")
        c._create_case(make_email(), "Security Alert", "c")
        assert c.helper.api.case_incident.create.call_args.kwargs["name"] == (
            "[IR] Security Alert"
        )

    def test_optional_kwargs_forwarded(self, conn, helper):
        conn._create_case(
            make_email(),
            "Security Alert",
            "c",
            label_ids=["l1"],
            response_types=["rt"],
            severity="high",
            priority="P1",
            author_id="author-x",
            marking_id="m-x",
            assignee_ids=["a1"],
            participant_ids=["p1"],
        )
        kwargs = helper.api.case_incident.create.call_args.kwargs
        assert kwargs["objectLabel"] == ["l1"]
        assert kwargs["response_types"] == ["rt"]
        assert kwargs["severity"] == "high"
        assert kwargs["priority"] == "P1"
        assert kwargs["createdBy"] == "author-x"
        assert kwargs["objectMarking"] == ["m-x"]
        assert kwargs["objectAssignee"] == ["a1"]
        assert kwargs["objectParticipant"] == ["p1"]


# --------------------------------------------------------------------------- #
# _find_existing_case / _append_to_case
# --------------------------------------------------------------------------- #
class TestFindAndAppend:
    def test_find_returns_id(self, conn, helper):
        helper.api.case_incident.list.return_value = [{"id": "existing-1"}]
        assert conn._find_existing_case("Security Alert") == "existing-1"

    def test_find_returns_none_when_empty(self, conn, helper):
        helper.api.case_incident.list.return_value = []
        assert conn._find_existing_case("Security Alert") is None

    def test_find_returns_none_on_error(self, conn, helper):
        helper.api.case_incident.list.side_effect = RuntimeError("boom")
        assert conn._find_existing_case("Security Alert") is None

    def test_append_concatenates_existing_content(self, conn, helper):
        helper.api.query.return_value = {"data": {"caseIncident": {"content": "OLD"}}}
        conn._append_to_case("case-1", "NEW")
        update = helper.api.stix_domain_object.update_field.call_args.kwargs
        assert update["id"] == "case-1"
        assert update["input"]["value"] == ["OLD\nNEW"]

    def test_append_handles_missing_existing_content(self, conn, helper):
        helper.api.query.return_value = {"data": {"caseIncident": None}}
        conn._append_to_case("case-1", "NEW")
        update = helper.api.stix_domain_object.update_field.call_args.kwargs
        assert update["input"]["value"] == ["\nNEW"]


# --------------------------------------------------------------------------- #
# _resolve_thread_id
# --------------------------------------------------------------------------- #
class TestResolveThreadId:
    def test_provider_thread_id(self, helper):
        c = build(helper, thread_tracking_strategy="provider_thread_id")
        assert c._resolve_thread_id(make_email(thread_id="T9"), FakeClient()) == "T9"

    def test_provider_falls_back_to_subject(self, helper):
        c = build(helper, thread_tracking_strategy="provider_thread_id")
        email = make_email(thread_id="")
        assert c._resolve_thread_id(email, FakeClient()).startswith("subject:")

    def test_message_headers_in_reply_to(self, helper):
        c = build(helper, thread_tracking_strategy="message_headers")
        email = make_email(in_reply_to="<parent@x>")
        assert c._resolve_thread_id(email, FakeClient()) == "<parent@x>"

    def test_message_headers_references(self, helper):
        c = build(helper, thread_tracking_strategy="message_headers")
        email = make_email(in_reply_to="", references=["<root@x>", "<mid@x>"])
        assert c._resolve_thread_id(email, FakeClient()) == "<root@x>"

    def test_message_headers_message_id(self, helper):
        c = build(helper, thread_tracking_strategy="message_headers")
        email = make_email(in_reply_to="", references=[], message_id="<self@x>")
        assert c._resolve_thread_id(email, FakeClient()) == "<self@x>"

    def test_subject_matching(self, helper):
        c = build(helper, thread_tracking_strategy="subject_matching")
        email = make_email(subject="RE: Security Alert")
        assert c._resolve_thread_id(email, FakeClient()) == "subject:Security Alert"


# --------------------------------------------------------------------------- #
# Resolution helpers
# --------------------------------------------------------------------------- #
class TestResolvers:
    def test_label_ids_create_and_cache(self, conn, helper):
        assert conn._resolve_label_ids(["alpha"]) == ["label-1"]
        helper.api.label.create.reset_mock()
        assert conn._resolve_label_ids(["alpha"]) == ["label-1"]  # cache hit
        helper.api.label.create.assert_not_called()

    def test_label_ids_skip_on_error(self, conn, helper):
        helper.api.label.create.side_effect = RuntimeError("x")
        assert conn._resolve_label_ids(["alpha"]) == []

    def test_identity_id_create_and_cache(self, conn, helper):
        assert conn._resolve_identity_id("Vendor") == "identity-1"
        helper.api.identity.create.reset_mock()
        assert conn._resolve_identity_id("Vendor") == "identity-1"
        helper.api.identity.create.assert_not_called()

    def test_identity_id_none_on_error(self, conn, helper):
        helper.api.identity.create.side_effect = RuntimeError("x")
        assert conn._resolve_identity_id("Vendor") is None

    def test_marking_id_found_and_cache(self, conn, helper):
        assert conn._resolve_marking_id("TLP:AMBER") == "marking-1"
        helper.api.marking_definition.read.reset_mock()
        assert conn._resolve_marking_id("TLP:AMBER") == "marking-1"
        helper.api.marking_definition.read.assert_not_called()

    def test_marking_id_not_found(self, conn, helper):
        helper.api.marking_definition.read.return_value = None
        assert conn._resolve_marking_id("TLP:RED") is None

    def test_marking_id_none_on_error(self, conn, helper):
        helper.api.marking_definition.read.side_effect = RuntimeError("x")
        assert conn._resolve_marking_id("TLP:RED") is None

    def test_member_ids_resolved_by_email(self, conn, helper):
        helper.api.query.return_value = {
            "data": {
                "users": {
                    "edges": [{"node": {"id": "u1", "user_email": "SOC@company.com"}}]
                }
            }
        }
        assert conn._resolve_member_ids(["soc@company.com"]) == ["u1"]

    def test_member_ids_not_found(self, conn, helper):
        helper.api.query.return_value = {"data": {"users": {"edges": []}}}
        assert conn._resolve_member_ids(["ghost@x.com"]) == []

    def test_member_ids_error(self, conn, helper):
        helper.api.query.side_effect = RuntimeError("x")
        assert conn._resolve_member_ids(["soc@company.com"]) == []


# --------------------------------------------------------------------------- #
# Rule matching
# --------------------------------------------------------------------------- #
class TestRuleMatching:
    def test_subject_rules_all_match_types(self, helper):
        rules = [
            {"match_type": "exact", "value": "Security Alert", "labels": ["exact"]},
            {"match_type": "contains", "value": "alert", "labels": ["contains"]},
            {"match_type": "starts_with", "value": "Sec", "labels": ["starts"]},
            {"match_type": "regex", "value": r"Alert$", "labels": ["regex"]},
        ]
        c = build(helper, subject_rules=rules)
        out = c._match_subject_rules("Security Alert")
        assert set(out["labels"]) == {"exact", "contains", "starts", "regex"}

    def test_subject_rules_merge_first_wins(self, helper):
        rules = [
            {
                "match_type": "contains",
                "value": "alert",
                "severity": "high",
                "priority": "P1",
                "case_template": "T1",
            },
            {"match_type": "contains", "value": "security", "severity": "low"},
        ]
        c = build(helper, subject_rules=rules)
        out = c._match_subject_rules("Security Alert")
        assert out["severity"] == "high"
        assert out["priority"] == "P1"
        assert out["case_template"] == "T1"

    def test_subject_rules_bad_regex_ignored(self, helper):
        rules = [{"match_type": "regex", "value": "(", "labels": ["x"]}]
        c = build(helper, subject_rules=rules)
        assert c._match_subject_rules("anything")["labels"] == []

    def test_sender_rules_match_and_merge(self, helper):
        rules = [
            {
                "sender": "alerts@example.com",
                "author": "Vendor",
                "marking": "TLP:GREEN",
                "assignees": ["a@x"],
                "participants": ["p@x"],
            },
        ]
        c = build(helper, sender_rules=rules)
        out = c._match_sender_rules("ALERTS@example.com")
        assert out["author"] == "Vendor"
        assert out["marking"] == "TLP:GREEN"
        assert out["assignees"] == ["a@x"]

    def test_sender_rules_no_match(self, helper):
        c = build(helper, sender_rules=[{"sender": "other@x"}])
        out = c._match_sender_rules("alerts@example.com")
        assert out["author"] is None


# --------------------------------------------------------------------------- #
# Case templates
# --------------------------------------------------------------------------- #
class TestCaseTemplates:
    def test_find_template_id(self, conn, helper):
        helper.api.query.return_value = {
            "data": {
                "caseTemplates": {"edges": [{"node": {"id": "tpl-1", "name": "IR"}}]}
            }
        }
        assert conn._find_case_template_id("IR") == "tpl-1"

    def test_apply_template_missing_is_noop(self, conn, helper):
        helper.api.query.return_value = {"data": {"caseTemplates": {"edges": []}}}
        conn._apply_case_template("case-1", "IR")  # should not raise

    def test_apply_template_runs_mutation(self, conn, helper):
        helper.api.query.return_value = {
            "data": {
                "caseTemplates": {"edges": [{"node": {"id": "tpl-1", "name": "IR"}}]}
            }
        }
        conn._apply_case_template("case-1", "IR")
        assert helper.api.query.call_count >= 2  # find + mutation


# --------------------------------------------------------------------------- #
# Vocabulary bootstrap
# --------------------------------------------------------------------------- #
class TestVocabularies:
    def test_creates_missing_values(self, conn, helper):
        helper.api.query.return_value = {"data": {"vocabularies": {"edges": []}}}
        conn._ensure_vocabularies()
        # severity + priority categories each missing one value -> >=2 mutations
        assert helper.api.query.call_count >= 2

    def test_get_vocabulary_values_parses(self, conn, helper):
        helper.api.query.return_value = {
            "data": {
                "vocabularies": {
                    "edges": [{"node": {"name": "medium"}}, {"node": {"name": "high"}}]
                }
            }
        }
        assert conn._get_vocabulary_values("case_severity_ov") == {"medium", "high"}

    def test_get_vocabulary_values_error_returns_empty(self, conn, helper):
        helper.api.query.side_effect = RuntimeError("x")
        assert conn._get_vocabulary_values("case_severity_ov") == set()


# --------------------------------------------------------------------------- #
# _process_email
# --------------------------------------------------------------------------- #
class TestProcessEmail:
    def test_new_case_created(self, conn, helper):
        thread_map = {}
        is_new = conn._process_email(make_email(), thread_map, FakeClient())
        assert is_new is True
        assert thread_map["thread-1"] == "case-internal-1"
        helper.api.case_incident.create.assert_called_once()

    def test_existing_thread_appends(self, conn, helper):
        thread_map = {"thread-1": "case-existing"}
        is_new = conn._process_email(make_email(), thread_map, FakeClient())
        assert is_new is False
        helper.api.case_incident.create.assert_not_called()
        helper.api.stix_domain_object.update_field.assert_called()

    def test_new_thread_finds_existing_case_by_name(self, conn, helper):
        helper.api.case_incident.list.return_value = [{"id": "found-1"}]
        thread_map = {}
        is_new = conn._process_email(make_email(), thread_map, FakeClient())
        assert is_new is True
        assert thread_map["thread-1"] == "found-1"
        helper.api.case_incident.create.assert_not_called()

    def test_attachment_uploaded(self, conn, helper):
        att = EmailAttachment(
            filename="report.txt",
            content_type="text/plain",
            content=b"plain text body",
            size=15,
        )
        conn._process_email(make_email(attachments=[att]), {}, FakeClient())
        helper.api.stix_domain_object.add_file.assert_called()
        names = [
            c.kwargs["file_name"]
            for c in helper.api.stix_domain_object.add_file.call_args_list
        ]
        assert "report.txt" in names

    def test_display_names_disabled(self, helper):
        c = build(helper, display_sender_names=False)
        email = make_email()
        c._process_email(email, {}, FakeClient())
        assert email.sender_display == ""


# --------------------------------------------------------------------------- #
# _import_emails
# --------------------------------------------------------------------------- #
class TestImportEmails:
    def test_no_matching_emails_marks_work_processed(self, conn, helper, monkeypatch):
        monkeypatch.setattr(
            connector_mod, "create_email_client", lambda cfg: FakeClient([])
        )
        conn._import_emails()
        helper.api.work.to_processed.assert_called_with(
            "work-1", "No new matching emails"
        )
        helper.set_state.assert_called()

    def test_processes_new_email_and_sets_state(self, conn, helper, monkeypatch):
        monkeypatch.setattr(
            connector_mod, "create_email_client", lambda cfg: FakeClient([make_email()])
        )
        conn._import_emails()
        helper.api.case_incident.create.assert_called_once()
        state = helper.set_state.call_args.args[0]
        assert "<m1@example.com>" in state["processed_message_ids"]
        assert state["thread_map"]["thread-1"] == "case-internal-1"

    def test_dedup_skips_processed_ids(self, conn, helper, monkeypatch):
        helper.get_state.return_value = {
            "processed_message_ids": ["<m1@example.com>"],
            "thread_map": {},
        }
        monkeypatch.setattr(
            connector_mod, "create_email_client", lambda cfg: FakeClient([make_email()])
        )
        conn._import_emails()
        helper.api.case_incident.create.assert_not_called()

    def test_uses_last_run_as_since(self, conn, helper, monkeypatch):
        captured = {}

        class CapturingClient(FakeClient):
            def fetch_emails(self, sender, since=None, max_results=50):
                captured["since"] = since
                return []

        helper.get_state.return_value = {"last_run": "2026-04-01T00:00:00Z"}
        monkeypatch.setattr(
            connector_mod, "create_email_client", lambda cfg: CapturingClient()
        )
        conn._import_emails()
        assert captured["since"].year == 2026

    def test_failure_marks_work_in_error_and_raises(self, conn, helper, monkeypatch):
        def boom(cfg):
            raise RuntimeError("fetch exploded")

        monkeypatch.setattr(connector_mod, "create_email_client", boom)
        with pytest.raises(RuntimeError, match="fetch exploded"):
            conn._import_emails()
        helper.api.work.to_processed.assert_called_with(
            "work-1", "fetch exploded", in_error=True
        )

    def test_total_processing_failure_errors_work_and_preserves_state(
        self, conn, helper, monkeypatch
    ):
        # A matching email is fetched, but every attempt to process it fails.
        monkeypatch.setattr(
            connector_mod, "create_email_client", lambda cfg: FakeClient([make_email()])
        )
        monkeypatch.setattr(
            conn, "_process_email", MagicMock(side_effect=RuntimeError("process boom"))
        )
        with pytest.raises(RuntimeError):
            conn._import_emails()
        # Work is marked in_error rather than reported as a successful cycle...
        assert helper.api.work.to_processed.call_args.kwargs.get("in_error") is True
        # ...and the state watermark is NOT advanced, so the email is retried.
        helper.set_state.assert_not_called()


# --------------------------------------------------------------------------- #
# Connector author identity (default createdBy)
# --------------------------------------------------------------------------- #
class TestConnectorAuthor:
    def test_ensure_connector_author_resolves_internal_id(self, conn, helper):
        helper.api.identity.create.return_value = {"id": "author-internal-1"}
        conn._ensure_connector_author()
        # A real OpenCTI internal id is cached, not the converter's STIX id.
        assert conn._connector_author_id == "author-internal-1"
        assert not conn._connector_author_id.startswith("identity--")

    def test_create_case_uses_connector_author_fallback(self, conn, helper):
        # With no sender-rule author, the case is authored by the connector's
        # created internal identity (not the never-created STIX id).
        conn._connector_author_id = "author-internal-1"
        conn._create_case(make_email(), "Security Alert", "c")
        kwargs = helper.api.case_incident.create.call_args.kwargs
        assert kwargs["createdBy"] == "author-internal-1"


# --------------------------------------------------------------------------- #
# Timeout wrappers + run()
# --------------------------------------------------------------------------- #
class TestTimeoutsAndRun:
    def test_fetch_with_timeout_returns_emails(self, conn):
        emails = conn._fetch_with_timeout(FakeClient([make_email()]), None)
        assert len(emails) == 1

    def test_fetch_with_timeout_propagates_error(self, conn):
        class BoomClient(FakeClient):
            def fetch_emails(self, *a, **k):
                raise ValueError("nope")

        with pytest.raises(ValueError, match="nope"):
            conn._fetch_with_timeout(BoomClient(), None)

    def test_test_connection_propagates_error(self, conn, helper, monkeypatch):
        class BoomClient(FakeClient):
            def connect(self):
                raise ConnectionError("refused")

        monkeypatch.setattr(
            connector_mod, "create_email_client", lambda cfg: BoomClient()
        )
        with pytest.raises(ConnectionError, match="refused"):
            conn._test_connection_with_timeout()

    def test_run_exits_on_connection_failure(self, conn, monkeypatch):
        monkeypatch.setattr(
            conn,
            "_test_connection_with_timeout",
            MagicMock(side_effect=RuntimeError("down")),
        )
        with pytest.raises(SystemExit):
            conn.run()

    def test_run_loops_then_stops(self, conn, monkeypatch):
        monkeypatch.setattr(conn, "_test_connection_with_timeout", MagicMock())
        monkeypatch.setattr(conn, "_ensure_vocabularies", MagicMock())
        monkeypatch.setattr(
            conn, "_import_emails", MagicMock(side_effect=KeyboardInterrupt())
        )
        monkeypatch.setattr(connector_mod.time, "sleep", MagicMock())
        conn.run()  # KeyboardInterrupt breaks the loop cleanly
        conn._import_emails.assert_called_once()
