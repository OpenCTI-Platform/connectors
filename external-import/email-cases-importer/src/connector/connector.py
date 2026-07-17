import re
import threading
import time
from datetime import datetime, timezone

import pycti
from pycti import OpenCTIConnectorHelper

from attachment_handler.registry import HandlerRegistry
from connector.converter_to_stix import ConverterToStix
from connector.utils import (
    collapse_blank_lines,
    extract_passwords,
    matches_subject_filter,
    normalize_subject,
    sanitize_html,
)
from email_client.base import EmailMessage
from email_client.factory import create_email_client


class EmailCasesConnector:
    def __init__(self, config, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.converter = ConverterToStix(helper, config)
        self.handler_registry = HandlerRegistry()
        self._interval = self._resolve_poll_interval()
        self._subject_filters = config.email_cases.get_parsed_subject_filters()
        self._sender = config.email_cases.sender_address
        self._password_prefix = config.email_cases.password_prefix
        self._password_suffix = config.email_cases.password_suffix
        self._password_strip_ws = config.email_cases.password_strip_whitespace
        self._thread_strategy = config.email_cases.thread_tracking_strategy
        self._max_att_size = config.email_cases.max_attachment_size_mb
        self._max_emails = config.email_cases.max_emails_per_cycle
        self._static_labels = config.email_cases.get_parsed_labels()
        self._subject_rules = config.email_cases.get_parsed_subject_rules()
        self._sender_rules = config.email_cases.get_parsed_sender_rules()
        self._display_names = config.email_cases.display_sender_names
        self._fetch_timeout = config.email_cases.email_fetch_timeout
        self._label_cache: dict[str, str] = {}  # label name -> OpenCTI ID
        self._entity_cache: dict[str, str] = {}  # cache for resolved entity IDs
        # OpenCTI internal id of the connector's own author identity, created at
        # startup (see _ensure_connector_author) and used as the default case
        # author when no sender-rule author applies.
        self._connector_author_id: str | None = None

    def _ensure_connector_author(self) -> None:
        """Create/resolve the connector's own author Identity in OpenCTI and
        cache its internal id.

        Used as the default ``createdBy`` for cases with no sender-rule author.
        The converter's STIX id references an Identity that is never created in
        the platform, so resolve a real internal id here instead.
        """
        connector_cfg = getattr(self.config, "connector", None)
        author_name = getattr(connector_cfg, "name", None) or "Email Cases Importer"
        self._connector_author_id = self._resolve_identity_id(author_name)

    def _resolve_poll_interval(self) -> int:
        """Seconds between poll cycles.

        ``CONNECTOR_DURATION_PERIOD`` (ISO-8601, e.g. ``PT5M``) is the single
        source of truth for the polling cadence, consistent with the OpenCTI
        connectors-sdk (it is a ``datetime.timedelta`` on the connector config).
        ``EMAIL_CASES_IMPORT_INTERVAL`` is retained only as a deprecated
        fallback for existing deployments and is ignored whenever a valid
        duration period is configured.
        """
        connector_cfg = getattr(self.config, "connector", None)
        period = getattr(connector_cfg, "duration_period", None)
        try:
            if period is not None:
                seconds = int(period.total_seconds())
                if seconds > 0:
                    return seconds
        except (AttributeError, TypeError, ValueError):
            pass
        return int(self.config.email_cases.import_interval)

    def run(self):
        # Startup: test email connection (with timeout)
        try:
            self._test_connection_with_timeout()
        except Exception as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] Email connection failed — stopping",
                {"error": str(exc)},
            )
            exit(1)

        # Startup: ensure vocabulary values exist
        self._ensure_vocabularies()

        # Startup: ensure the connector's author identity exists in OpenCTI
        self._ensure_connector_author()

        self.helper.connector_logger.info(
            "[CONNECTOR] Starting email import loop",
            {
                "interval_seconds": self._interval,
                "sender": self._sender,
                "protocol": self.config.email_cases.protocol,
            },
        )
        while True:
            try:
                self._import_emails()
            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info("[CONNECTOR] Stopping")
                break
            except Exception as e:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Import cycle failed", {"error": str(e)}
                )
            time.sleep(self._interval)

    def _import_emails(self):
        state = self.helper.get_state() or {}
        last_run = state.get("last_run")
        thread_map = state.get("thread_map", {})
        processed_ids = set(state.get("processed_message_ids", []))

        # Resolve `since`: prefer prior state; otherwise fall back to configured
        # start_date (first-run backfill floor); otherwise None (server returns
        # most recent emails).
        since = None
        since_source = "none"
        if last_run:
            since = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
            since_source = "last_run"
        else:
            configured_start = self.config.email_cases.get_parsed_start_date()
            if configured_start:
                since = configured_start
                since_source = "start_date"

        self.helper.connector_logger.info(
            "[CONNECTOR] Import cycle starting",
            {
                "since": since.isoformat() if since else None,
                "since_source": since_source,
                "sender_filter": self._sender,
                "subject_filters_count": len(self._subject_filters),
                "max_emails_per_cycle": self._max_emails,
            },
        )

        friendly_name = f"Email IR import @ {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        try:
            client = create_email_client(self.config)
            with client:
                emails = self._fetch_with_timeout(client, since)

                # Per-email debug trace: subjects + senders + dates. Only emitted
                # when CONNECTOR_LOG_LEVEL=debug so production output stays quiet.
                for idx, e in enumerate(emails, start=1):
                    self.helper.connector_logger.debug(
                        "[CONNECTOR] Fetched email",
                        {
                            "idx": idx,
                            "subject": e.subject,
                            "sender": e.sender,
                            "date": e.date.isoformat() if e.date else None,
                            "thread_id": e.thread_id,
                            "attachments": len(e.attachments),
                        },
                    )

                # Strict sender sanity check — protocol-level filters can be
                # loose (IMAP SEARCH FROM is substring, Gmail q="from:" is fuzzy),
                # so cross-check against the configured sender here.
                sender_lower = (self._sender or "").lower().strip()
                sender_exact = [
                    e
                    for e in emails
                    if (e.sender or "").lower().strip() == sender_lower
                ]

                # Subject filter stage
                subject_matched = [
                    e
                    for e in emails
                    if matches_subject_filter(e.subject, self._subject_filters)
                ]

                # Dedup stage — drop anything we've already imported
                new_matched = [
                    e for e in subject_matched if e.message_id not in processed_ids
                ]
                already_processed = len(subject_matched) - len(new_matched)

                self.helper.connector_logger.info(
                    "[CONNECTOR] Fetch/filter breakdown",
                    {
                        "fetched": len(emails),
                        "exact_sender_match": len(sender_exact),
                        "other_senders": len(emails) - len(sender_exact),
                        "subject_matched": len(subject_matched),
                        "subject_skipped": len(emails) - len(subject_matched),
                        "already_processed": already_processed,
                        "to_process": len(new_matched),
                    },
                )

                # Debug subject list of what will actually be processed
                for e in new_matched:
                    self.helper.connector_logger.debug(
                        "[CONNECTOR] Will process email",
                        {
                            "subject": e.subject,
                            "sender": e.sender,
                            "date": e.date.isoformat() if e.date else None,
                            "message_id": e.message_id,
                        },
                    )

                matched = new_matched

                if not matched:
                    self.helper.api.work.to_processed(work_id, "No new matching emails")
                    self.helper.set_state(
                        {
                            "last_run": datetime.now(timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                            "thread_map": thread_map,
                            "processed_message_ids": list(processed_ids),
                        }
                    )
                    return

                cases_created = 0
                cases_updated = 0
                emails_processed = 0
                emails_failed = 0

                for email_msg in matched:
                    try:
                        is_new = self._process_email(email_msg, thread_map, client)
                        processed_ids.add(email_msg.message_id)
                        emails_processed += 1
                        if is_new:
                            cases_created += 1
                            self.helper.connector_logger.debug(
                                "[CONNECTOR] Created new case",
                                {
                                    "subject": email_msg.subject,
                                    "message_id": email_msg.message_id,
                                },
                            )
                        else:
                            cases_updated += 1
                            self.helper.connector_logger.debug(
                                "[CONNECTOR] Updated existing case",
                                {
                                    "subject": email_msg.subject,
                                    "message_id": email_msg.message_id,
                                },
                            )
                    except Exception as e:
                        emails_failed += 1
                        self.helper.connector_logger.error(
                            "[CONNECTOR] Failed to process email",
                            {"subject": email_msg.subject, "error": str(e)},
                        )

            # Total-failure guard (audit #5): if there were emails to process
            # but every one failed, do NOT report the Work as successful or
            # advance the state watermark. Raising here routes to the handler
            # below, which marks the Work in_error; set_state is skipped so the
            # same emails are retried next cycle instead of being silently lost.
            if emails_processed == 0 and emails_failed > 0:
                raise RuntimeError(
                    f"All {emails_failed} matching email(s) failed to process; "
                    "no cases created this cycle"
                )

            msg = (
                f"Processed {emails_processed} emails "
                f"({cases_created} new cases, {cases_updated} updates, "
                f"{emails_failed} failed)"
            )
            self.helper.connector_logger.info(
                "[CONNECTOR] Import done",
                {
                    "emails_processed": emails_processed,
                    "cases_created": cases_created,
                    "cases_updated": cases_updated,
                    "emails_failed": emails_failed,
                    "msg": msg,
                },
            )
            self.helper.api.work.to_processed(work_id, msg)
            self.helper.set_state(
                {
                    "last_run": datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "thread_map": thread_map,
                    "processed_message_ids": list(processed_ids),
                }
            )

        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] Import failed", {"error": str(e)}
            )
            self.helper.api.work.to_processed(work_id, str(e), in_error=True)
            raise

    def _process_email(
        self,
        email_msg: EmailMessage,
        thread_map: dict,
        client,
    ) -> bool:
        """Process a single email: create/update case, upload attachments.

        Returns True if a new case was created.
        """
        thread_id = self._resolve_thread_id(email_msg, client)
        normalized_subject = normalize_subject(email_msg.subject)
        is_new_case = thread_id not in thread_map

        # Extract passwords from email body. Normalize blank-line runs so
        # nested-<div> HTML emails and plain-text emails with padded signatures
        # both render cleanly in the case content.
        body_text = email_msg.body_plain or sanitize_html(email_msg.body_html) or ""
        body_text = collapse_blank_lines(body_text)
        passwords = extract_passwords(
            body_text,
            self._password_prefix,
            self._password_suffix,
            strip_whitespace=self._password_strip_ws,
        )
        if passwords:
            self.helper.connector_logger.info(
                "[CONNECTOR] Passwords extracted from email body",
                {"count": len(passwords), "subject": email_msg.subject},
            )

        # Process attachments (decrypt/extract). Keep originals plus any
        # extracted/decrypted content, de-duplicated by (filename, bytes): a
        # passthrough handler can surface an inner file that is byte-identical to
        # its parent (e.g. an unencrypted CSV inside a plain zip), which would
        # otherwise be uploaded twice.
        attachment_files = []
        attachment_names = []
        seen_attachments: set[tuple[str, bytes]] = set()

        def _add_attachment(fn: str, data: bytes, ctype: str | None) -> None:
            key = (fn, data)
            if key in seen_attachments:
                return
            seen_attachments.add(key)
            attachment_files.append((fn, data, ctype))
            attachment_names.append(fn)

        for att in email_msg.attachments:
            # Always include the original attachment as-is
            _add_attachment(att.filename, att.content, att.content_type)

            # Try to extract/decrypt — add results alongside the original
            try:
                extracted = self.handler_registry.process_attachment(
                    filename=att.filename,
                    content=att.content,
                    passwords=passwords,
                    max_size_mb=self._max_att_size,
                )
                for ef in extracted:
                    _add_attachment(ef.filename, ef.content, ef.content_type)
                    for inner in ef.inner_files:
                        _add_attachment(
                            inner.filename, inner.content, inner.content_type
                        )
            except Exception as e:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] Attachment processing failed",
                    {"filename": att.filename, "error": str(e)},
                )

        # Clear display names if feature is disabled
        if not self._display_names:
            email_msg.sender_display = ""
            email_msg.recipients_display = []

        # Build content block for this email
        is_reply = not is_new_case or bool(email_msg.in_reply_to)
        content_block = self.converter.format_email_content_block(
            email_msg=email_msg,
            body_text=body_text,
            attachment_names=attachment_names,
            is_reply=is_reply,
            passwords_found=len(passwords),
        )

        # Resolve labels and subject rules
        all_labels = list(self._static_labels)
        rule_result = self._match_subject_rules(email_msg.subject)
        all_labels.extend(rule_result["labels"])
        # Deduplicate labels preserving order
        seen = set()
        unique_labels = []
        for lbl in all_labels:
            if lbl not in seen:
                seen.add(lbl)
                unique_labels.append(lbl)
        label_ids = self._resolve_label_ids(unique_labels) if unique_labels else []
        response_types = rule_result["response_types"] or None
        case_template = rule_result["case_template"]
        rule_severity = rule_result["severity"]
        rule_priority = rule_result["priority"]

        # Resolve sender rules
        sender_result = self._match_sender_rules(email_msg.sender)
        author_id = None
        if sender_result["author"]:
            author_id = self._resolve_identity_id(sender_result["author"])
        marking_id = None
        if sender_result["marking"]:
            marking_id = self._resolve_marking_id(sender_result["marking"])
        assignee_ids = (
            self._resolve_member_ids(sender_result["assignees"])
            if sender_result["assignees"]
            else None
        )
        participant_ids = (
            self._resolve_member_ids(sender_result["participants"])
            if sender_result["participants"]
            else None
        )

        if is_new_case:
            # Check if a case with this name already exists (e.g. after state reset)
            existing_id = self._find_existing_case(normalized_subject)
            if existing_id:
                case_id = existing_id
                self._append_to_case(case_id, content_block)
                thread_map[thread_id] = case_id
                self.helper.connector_logger.info(
                    "[CONNECTOR] Found existing case, appending",
                    {"case_id": case_id, "subject": normalized_subject},
                )
            else:
                case_id = self._create_case(
                    email_msg,
                    normalized_subject,
                    content_block,
                    label_ids=label_ids,
                    response_types=response_types,
                    severity=rule_severity,
                    priority=rule_priority,
                    author_id=author_id,
                    marking_id=marking_id,
                    assignee_ids=assignee_ids,
                    participant_ids=participant_ids,
                )
                if case_template:
                    self._apply_case_template(case_id, case_template)
                thread_map[thread_id] = case_id
                self.helper.connector_logger.info(
                    "[CONNECTOR] Created new case",
                    {"case_id": case_id, "subject": normalized_subject},
                )
        else:
            case_id = thread_map[thread_id]
            self._append_to_case(case_id, content_block)
            self.helper.connector_logger.info(
                "[CONNECTOR] Updated existing case",
                {"case_id": case_id, "subject": email_msg.subject},
            )

        # Upload attachments to the case
        for filename, content, content_type in attachment_files:
            try:
                self.helper.api.stix_domain_object.add_file(
                    id=case_id,
                    file_name=filename,
                    data=content,
                    mime_type=content_type or "application/octet-stream",
                    no_trigger_import=True,
                )
                self.helper.connector_logger.info(
                    "[CONNECTOR] Uploaded attachment",
                    {"filename": filename, "case_id": case_id},
                )
            except Exception as e:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] Failed to upload attachment",
                    {"filename": filename, "error": str(e)},
                )

        return is_new_case

    def _resolve_label_ids(self, label_names: list[str]) -> list[str]:
        """Resolve label names to OpenCTI IDs, creating labels if needed."""
        ids = []
        for name in label_names:
            if name in self._label_cache:
                ids.append(self._label_cache[name])
                continue
            try:
                result = self.helper.api.label.create(value=name)
                label_id = result["id"]
                self._label_cache[name] = label_id
                ids.append(label_id)
            except Exception as e:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] Failed to create/find label",
                    {"label": name, "error": str(e)},
                )
        return ids

    def _resolve_identity_id(self, name: str) -> str | None:
        """Resolve an organization identity by name, creating if needed."""
        cache_key = f"identity:{name}"
        if cache_key in self._entity_cache:
            return self._entity_cache[cache_key]
        try:
            result = self.helper.api.identity.create(
                type="Organization",
                name=name,
            )
            identity_id = result["id"]
            self._entity_cache[cache_key] = identity_id
            return identity_id
        except Exception as e:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Failed to resolve identity",
                {"name": name, "error": str(e)},
            )
            return None

    def _resolve_marking_id(self, marking_name: str) -> str | None:
        """Resolve a marking definition by name (e.g. 'TLP:AMBER')."""
        cache_key = f"marking:{marking_name}"
        if cache_key in self._entity_cache:
            return self._entity_cache[cache_key]
        try:
            result = self.helper.api.marking_definition.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "definition", "values": [marking_name]}],
                    "filterGroups": [],
                }
            )
            if result:
                self._entity_cache[cache_key] = result["id"]
                return result["id"]
            self.helper.connector_logger.warning(
                "[CONNECTOR] Marking definition not found",
                {"name": marking_name},
            )
        except Exception as e:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Failed to resolve marking",
                {"name": marking_name, "error": str(e)},
            )
        return None

    def _resolve_member_ids(self, emails: list[str]) -> list[str]:
        """Resolve user emails to OpenCTI user IDs."""
        ids = []
        for email in emails:
            cache_key = f"member:{email}"
            if cache_key in self._entity_cache:
                ids.append(self._entity_cache[cache_key])
                continue
            try:
                result = self.helper.api.query(
                    """
                    query Users($search: String) {
                        users(search: $search) {
                            edges { node { id name user_email } }
                        }
                    }
                    """,
                    {"search": email},
                )
                edges = result.get("data", {}).get("users", {}).get("edges", [])
                for edge in edges:
                    node = edge["node"]
                    if node.get("user_email", "").lower() == email.lower():
                        self._entity_cache[cache_key] = node["id"]
                        ids.append(node["id"])
                        break
                else:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] User not found for assignee/participant",
                        {"email": email},
                    )
            except Exception as e:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] Failed to resolve user",
                    {"email": email, "error": str(e)},
                )
        return ids

    def _match_subject_rules(self, subject: str) -> dict:
        """Match subject against configured rules. Returns merged result."""
        result = {
            "labels": [],
            "response_types": [],
            "case_template": None,
            "severity": None,
            "priority": None,
        }
        for rule in self._subject_rules:
            match_type = rule["match_type"]
            value = rule["value"]
            matched = False
            if match_type == "exact" and subject == value:
                matched = True
            elif match_type == "contains" and value.lower() in subject.lower():
                matched = True
            elif match_type == "starts_with" and subject.lower().startswith(
                value.lower()
            ):
                matched = True
            elif match_type == "regex":
                try:
                    if re.search(value, subject):
                        matched = True
                except re.error:
                    pass
            if matched:
                result["labels"].extend(rule.get("labels", []))
                result["response_types"].extend(rule.get("response_types", []))
                if rule.get("case_template") and not result["case_template"]:
                    result["case_template"] = rule["case_template"]
                if rule.get("severity") and not result["severity"]:
                    result["severity"] = rule["severity"]
                if rule.get("priority") and not result["priority"]:
                    result["priority"] = rule["priority"]
        return result

    def _match_sender_rules(self, sender: str) -> dict:
        """Match sender against configured sender rules. Returns merged result."""
        result = {
            "author": None,
            "marking": None,
            "assignees": [],
            "participants": [],
        }
        for rule in self._sender_rules:
            if rule["sender"].lower() == sender.lower():
                if rule.get("author") and not result["author"]:
                    result["author"] = rule["author"]
                if rule.get("marking") and not result["marking"]:
                    result["marking"] = rule["marking"]
                result["assignees"].extend(rule.get("assignees", []))
                result["participants"].extend(rule.get("participants", []))
        return result

    def _find_case_template_id(self, template_name: str) -> str | None:
        """Look up a case template by name. Returns ID or None."""
        query = """
            query CaseTemplates($search: String) {
                caseTemplates(search: $search) {
                    edges {
                        node {
                            id
                            name
                        }
                    }
                }
            }
        """
        try:
            result = self.helper.api.query(query, {"search": template_name})
            edges = result.get("data", {}).get("caseTemplates", {}).get("edges", [])
            for edge in edges:
                if edge["node"]["name"] == template_name:
                    return edge["node"]["id"]
        except Exception as e:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Failed to find case template",
                {"name": template_name, "error": str(e)},
            )
        return None

    def _apply_case_template(self, case_id: str, template_name: str):
        """Apply a case template to a case via GraphQL mutation."""
        template_id = self._find_case_template_id(template_name)
        if not template_id:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Case template not found",
                {"name": template_name},
            )
            return
        mutation = """
            mutation ApplyTemplate($id: ID!, $caseTemplatesId: [ID]!) {
                caseSetTemplate(id: $id, caseTemplatesId: $caseTemplatesId) {
                    id
                }
            }
        """
        try:
            self.helper.api.query(
                mutation,
                {
                    "id": case_id,
                    "caseTemplatesId": [template_id],
                },
            )
            self.helper.connector_logger.info(
                "[CONNECTOR] Applied case template",
                {"template": template_name, "case_id": case_id},
            )
        except Exception as e:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Failed to apply case template",
                {"template": template_name, "error": str(e)},
            )

    def _create_case(
        self,
        email_msg: EmailMessage,
        normalized_subject: str,
        content: str,
        label_ids: list[str] | None = None,
        response_types: list[str] | None = None,
        severity: str | None = None,
        priority: str | None = None,
        author_id: str | None = None,
        marking_id: str | None = None,
        assignee_ids: list[str] | None = None,
        participant_ids: list[str] | None = None,
    ) -> str:
        """Create a new Case-Incident via the OpenCTI API. Returns internal ID."""
        prefix = self.config.email_cases.case_prefix
        name = f"{prefix}{normalized_subject}" if prefix else normalized_subject
        description = self.converter.format_case_description(email_msg)

        # Deterministic STIX id via the pycti generator, keyed on the case name
        # and the first email's received time. This makes re-runs upsert the same
        # Case-Incident instead of creating duplicates. The `created` value passed
        # to create() MUST match the generate_id seed, so derive both from one
        # string.
        created = email_msg.date or datetime.now(timezone.utc)
        created_iso = created.strftime("%Y-%m-%dT%H:%M:%SZ")
        case_stix_id = pycti.CaseIncident.generate_id(name=name, created=created_iso)

        kwargs = dict(
            stix_id=case_stix_id,
            name=name,
            created=created_iso,
            description=description,
            content=content,
            severity=severity or self.config.email_cases.default_severity,
            priority=priority or self.config.email_cases.default_priority,
            createdBy=author_id
            or self._connector_author_id
            or self.converter.identity_id,
        )
        if label_ids:
            kwargs["objectLabel"] = label_ids
        if response_types:
            kwargs["response_types"] = response_types
        if marking_id:
            kwargs["objectMarking"] = [marking_id]
        if assignee_ids:
            kwargs["objectAssignee"] = assignee_ids
        if participant_ids:
            kwargs["objectParticipant"] = participant_ids

        result = self.helper.api.case_incident.create(**kwargs)

        return result["id"]

    def _append_to_case(self, case_id: str, new_content_block: str):
        """Append a new email content block to an existing case's Content tab."""
        query = """
            query CaseIncidentContent($id: String!) {
                caseIncident(id: $id) {
                    content
                }
            }
        """
        result = self.helper.api.query(query, {"id": case_id})
        existing_content = ""
        if result and result.get("data", {}).get("caseIncident"):
            existing_content = result["data"]["caseIncident"].get("content") or ""

        updated_content = existing_content + "\n" + new_content_block

        self.helper.api.stix_domain_object.update_field(
            id=case_id,
            input={"key": "content", "value": [updated_content]},
        )

    def _find_existing_case(self, normalized_subject: str) -> str | None:
        """Look up an existing Case-Incident by name. Returns internal ID or None."""
        prefix = self.config.email_cases.case_prefix
        name = f"{prefix}{normalized_subject}" if prefix else normalized_subject
        try:
            result = self.helper.api.case_incident.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [name]}],
                    "filterGroups": [],
                },
                first=1,
            )
            if result and len(result) > 0:
                return result[0]["id"]
        except Exception as e:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Failed to look up existing case",
                {"name": name, "error": str(e)},
            )
        return None

    def _resolve_thread_id(self, email_msg: EmailMessage, client) -> str:
        """Resolve thread ID based on configured strategy."""
        if self._thread_strategy == "provider_thread_id":
            tid = client.get_thread_id(email_msg)
            if tid:
                return tid
            return f"subject:{normalize_subject(email_msg.subject)}"

        if self._thread_strategy == "message_headers":
            if email_msg.in_reply_to:
                return email_msg.in_reply_to
            if email_msg.references:
                return email_msg.references[0]
            return email_msg.message_id

        if self._thread_strategy == "subject_matching":
            return f"subject:{normalize_subject(email_msg.subject)}"

        # Default fallback
        return client.get_thread_id(email_msg) or email_msg.message_id

    def _ensure_vocabularies(self):
        """Ensure all configured vocabulary values exist in OpenCTI.

        Creates missing severity, priority, and response_types entries
        so they are not silently dropped on case creation.
        """
        all_severities = [self.config.email_cases.default_severity]
        all_priorities = [self.config.email_cases.default_priority]
        all_response_types = []
        for rule in self._subject_rules:
            all_response_types.extend(rule.get("response_types", []))
            if rule.get("severity"):
                all_severities.append(rule["severity"])
            if rule.get("priority"):
                all_priorities.append(rule["priority"])

        checks = [
            ("case_severity_ov", all_severities),
            ("case_priority_ov", all_priorities),
        ]
        if all_response_types:
            checks.append(("incident_response_types_ov", all_response_types))

        for category, values in checks:
            existing = self._get_vocabulary_values(category)
            for value in values:
                if value not in existing:
                    self._create_vocabulary_entry(category, value)

    def _get_vocabulary_values(self, category: str) -> set[str]:
        """Fetch existing vocabulary values for a category."""
        query = """
            query Vocabularies($category: VocabularyCategory!) {
                vocabularies(category: $category) {
                    edges { node { name } }
                }
            }
        """
        try:
            result = self.helper.api.query(query, {"category": category})
            edges = result.get("data", {}).get("vocabularies", {}).get("edges", [])
            return {e["node"]["name"] for e in edges}
        except Exception as e:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Failed to fetch vocabularies",
                {"category": category, "error": str(e)},
            )
            return set()

    def _create_vocabulary_entry(self, category: str, value: str):
        """Create a vocabulary entry if it doesn't exist."""
        mutation = """
            mutation VocabularyAdd($input: VocabularyAddInput!) {
                vocabularyAdd(input: $input) { id name }
            }
        """
        try:
            self.helper.api.query(
                mutation,
                {
                    "input": {"name": value, "category": category},
                },
            )
            self.helper.connector_logger.info(
                "[CONNECTOR] Created vocabulary entry",
                {"category": category, "value": value},
            )
        except Exception as e:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Failed to create vocabulary entry",
                {"category": category, "value": value, "error": str(e)},
            )

    def _test_connection_with_timeout(self):
        """Test email connection with a timeout."""
        error_holder: list[Exception] = []

        def _do_connect():
            try:
                c = create_email_client(self.config)
                with c:
                    pass
            except Exception as exc:
                error_holder.append(exc)

        thread = threading.Thread(target=_do_connect, daemon=True)
        thread.start()
        thread.join(timeout=self._fetch_timeout)

        if thread.is_alive():
            raise TimeoutError(
                f"Email connection test did not complete within {self._fetch_timeout}s"
            )
        if error_holder:
            raise error_holder[0]

        self.helper.connector_logger.info(
            "[CONNECTOR] Email connection verified",
            {"protocol": self.config.email_cases.protocol},
        )

    def _fetch_with_timeout(self, client, since) -> list[EmailMessage]:
        """Fetch emails with a timeout to prevent the connector from hanging."""
        result_holder: list[EmailMessage] = []
        error_holder: list[Exception] = []

        def _do_fetch():
            try:
                result_holder.extend(
                    client.fetch_emails(
                        sender=self._sender,
                        since=since,
                        max_results=self._max_emails,
                    )
                )
            except Exception as exc:
                error_holder.append(exc)

        thread = threading.Thread(target=_do_fetch, daemon=True)
        thread.start()
        thread.join(timeout=self._fetch_timeout)

        if thread.is_alive():
            self.helper.connector_logger.error(
                "[CONNECTOR] Email fetch timed out",
                {"timeout_seconds": self._fetch_timeout},
            )
            raise TimeoutError(
                f"Email fetch did not complete within {self._fetch_timeout}s"
            )

        if error_holder:
            raise error_holder[0]

        return result_holder
