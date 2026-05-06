"""
Sublime Security OpenCTI Connector
Simplified implementation following OpenCTI connector patterns
"""

import json
import sys
from datetime import datetime, timedelta, timezone

import isodate
import requests
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.utils import lookup_MDM_value, map_attack_score_to_level, sanitize_email
from pycti import OpenCTIConnectorHelper
from sublime_client import SublimeClient


class SublimeConnector:
    """
    Sublime external import connector for OpenCTI
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `SublimeConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.verdicts = [
            v.strip().lower() for v in self.config.sublime.verdicts if v.strip()
        ]

        # Track first run of this connector session (not persisted)
        self._first_run_completed = False

        self.client = SublimeClient(
            helper=self.helper,
            base_url=self.config.sublime.url,
            api_key=self.config.sublime.token,
        )

        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.sublime.tlp_level,
        )

        # Create Sublime Identity for STIX objects
        self.sublime_identity = self.converter_to_stix.author

    def get_last_run(self, current_state: dict):
        """
        Get the last processed timestamp from OpenCTI connector state.

        If force_historical is enabled, always uses first_run_duration (ignores state).
        Otherwise, uses state if exists, or first_run_duration on first run.

        Returns:
            str: ISO 8601 timestamp string of last processed message,
                 or calculated based on first_run_duration if no previous state exists or force_historical is enabled
        """
        # If force_historical is enabled and this is the first run, ignore state
        # After first run, use state for incremental polling
        use_state = (
            not self.config.sublime.force_historical or self._first_run_completed
        )

        if use_state and current_state and "last_timestamp" in current_state:
            return current_state["last_timestamp"]

        # First run or forced historical: use configured duration for initial data fetch
        try:
            default_time = (
                datetime.now(timezone.utc) - self.config.sublime.first_run_duration
            )

            if self.config.sublime.force_historical:
                mode = "Forced historical"
            else:
                mode = "First run"

            self.helper.connector_logger.info(
                "[Sublime Connector] Fetch historical data.",
                {
                    "mode": mode,
                    "first_run_duration": self.config.sublime.first_run_duration,
                },
            )
        except (isodate.ISO8601Error, ValueError) as e:
            self.helper.connector_logger.warning(
                "[Sublime Connector] Invalid first run duration format. Using default 8 hours.",
                {
                    "first_run_duration": self.config.sublime.first_run_duration,
                    "error": e,
                },
            )

            # Fallback to 1 day
            default_time = datetime.now(timezone.utc) - timedelta(hours=8)

        # Format for Sublime API: 2025-12-31T05:00:00.000Z
        return default_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _fetch_messages(self, since_timestamp):
        """
        Fetch malicious message groups from Sublime API since provided time.

        Uses a two-step process with batch processing:
        1. Fetch list of flagged group IDs within time range
        2. Process groups in batches for quicker access and easier troubleshooting
        3. Yield batches of message groups for incremental processing

        Args:
            since_timestamp (str): ISO 8601 timestamp to fetch messages since

        Yields:
            list: Batches of message group dictionaries with 'malicious' verdict
        """
        if since_timestamp:
            start_time = since_timestamp
        else:
            # Default to 5 mins ago for frequent polling
            start_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )

        # End time is now (to avoid missing messages created during the fetch)
        end_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        try:
            group_ids = self.client.get_group_ids(start_time, end_time)
            if not group_ids:
                self.helper.connector_logger.debug(
                    "No flagged message groups found in time range"
                )
                return

            self.helper.connector_logger.info(
                "[Sublime Connector] Flagged group IDs found. Processing in batches",
                {
                    "length_group_ids": len(group_ids),
                    "batch_size": self.config.sublime.batch_size,
                },
            )

            total_fetched = 0
            for i in range(0, len(group_ids), self.config.sublime.batch_size):
                batch_ids = group_ids[i : i + self.config.sublime.batch_size]
                batch_messages = []

                for group_id in batch_ids:
                    message_group = self.client.get_single_group(group_id)
                    if message_group:
                        attack_score_raw = message_group.get("attack_score_verdict")
                        if not attack_score_raw:
                            continue

                        attack_score = attack_score_raw.lower()
                        if attack_score in self.verdicts:
                            batch_messages.append(message_group)
                        else:
                            self.helper.connector_logger.debug(
                                "[Sublime Connector] Skipping group",
                                {
                                    "group_id": group_id,
                                    "attack_score": attack_score,
                                    "verdicts": self.verdicts,
                                },
                            )

                if batch_messages:
                    total_fetched += len(batch_messages)
                    self.helper.connector_logger.info(
                        "[Sublime Connector] Batch yielding messages",
                        {
                            "length_batch_messages": len(batch_messages),
                            "verdicts": self.verdicts,
                        },
                    )

                    yield batch_messages

            self.helper.connector_logger.info(
                "[*] Completed: {}/{} flagged groups matched verdicts {}".format(
                    total_fetched, len(group_ids), self.verdicts
                )
            )

        except requests.exceptions.RequestException as e:
            raise Exception("Network error: {}".format(e))
        except json.JSONDecodeError as e:
            raise Exception("Invalid JSON response: {}".format(e))

    def _validate_message(self, message_group):
        """
        Validate that message group has required fields for STIX conversion.

        Checks for:
        - Group ID
        - Subjects list
        - Data model with sender email

        Args:
            message_group (dict): Message group data from Sublime API

        Returns:
            bool: True if message group is valid, False otherwise
        """
        # Check for basic message group structure
        if "id" not in message_group:
            self.helper.connector_logger.warning(
                "[Sublime Connector] Message group missing id field"
            )
            return False

        # Check for subjects
        if not message_group.get("subjects"):
            self.helper.connector_logger.warning(
                "[Sublime Connector] Message group missing subjects"
            )
            return False

        # Check for MDM (where the detailed email data is)
        if "MDM" not in message_group:
            self.helper.connector_logger.warning(
                "[Sublime Connector] Message group missing MDM"
            )
            return False

        MDM = message_group["MDM"]

        # Check for sender in MDM
        if (
            "sender" not in MDM
            or "email" not in MDM.get("sender", {})
            or "email" not in MDM.get("sender", {}).get("email", {})
        ):
            self.helper.connector_logger.warning(
                "[Sublime Connector] Message group MDM missing sender email"
            )
            return False

        return True

    def _create_stix_objects(self, message_group):
        """
        Create STIX objects from Sublime message group.

        Creates:
        - One detailed EmailMessage from MDM (primary email)
        - Basic EmailMessage objects from preview data
        - Incident object representing the group
        - Observables (URLs, domains, IPs, email addresses)
        - Indicators generated from observables
        - Relationships linking all objects to the incident

        Note: Case creation is handled separately via OpenCTI API

        Args:
            message_group (dict): Message group data from Sublime API

        Returns:
            tuple: (list of STIX objects ready for bundling, incident object)
        """
        objects = [self.sublime_identity]
        previews = message_group.get("previews", [])

        # Create detailed email from MDM
        primary_email, observables, additional_emails = self._create_primary_email(
            message_group
        )
        # Add observables (email-addr, urls, etc.) BEFORE email-message so
        # that referenced objects are ingested first by OpenCTI.
        objects.extend(observables)
        if primary_email:
            objects.append(primary_email)
        objects.extend(additional_emails)  # Add any additional EmailMessage objects

        # Create basic emails from previews of other emails in group
        preview_emails = self._create_preview_emails(previews)
        objects.extend(preview_emails)

        # Create group event Incident
        incident = self._create_group_incident(message_group)
        objects.append(incident)

        # Create indicators from observables
        indicators = []

        for observable in observables:
            try:
                indicator = self._create_indicator_for_observable(observable)
                if indicator:
                    indicators.append(indicator)
            except Exception as e:
                # Log the problematic observable value for debugging
                obs_value = getattr(observable, "value", "Unknown")
                self.helper.connector_logger.warning(
                    "[Sublime Connector] Failed to create indicator",
                    {"obs_type": observable._type, "obs_value": obs_value, "error": e},
                )

        objects.extend(indicators)

        # Link everything to incident (include additional_emails from MDM)
        all_emails = preview_emails + additional_emails
        relationships = self._create_relationships(
            incident, primary_email, all_emails, observables, indicators
        )
        objects.extend(relationships)

        return objects, incident

    def _create_primary_email(self, message_group):
        """
        Create detailed EmailMessage from group's primary Message Data Model (MDM).

        Args:
            message_group (dict): Message group data from Sublime API

        Returns:
            tuple: (EmailMessage object, list of observable objects, list of additional EmailMessage objects)
        """
        MDM = message_group.get("MDM", {})
        if not MDM:
            return None, [], []

        observables = []

        sender_email = lookup_MDM_value(MDM, "sender.email.email")
        sender = None
        if sender_email:
            sender_email = sanitize_email(sender_email)
            sender = self.converter_to_stix.create_email_address(value=sender_email)
        recipients = self._extract_recipients(MDM)
        if sender:
            observables.append(sender)
        observables.extend(recipients)

        observables.extend(self._extract_urls(MDM))
        observables.extend(self._extract_domains(MDM))
        observables.extend(self._extract_ips(MDM))
        observables.extend(self._extract_attachments(MDM))

        # Build email message (STIX2: is_multipart requires body)
        body_text = lookup_MDM_value(MDM, "body.plain.raw")

        # raw text makes things easier, but option is here for HTML
        # html_content = lookup_MDM_value(MDM, 'body.html.raw')

        # Edge case. Sometimes the raw body doesn't exist. In that case, use HTML
        # e.g. html.raw = <span style="display: none"></p></html>
        if not body_text:
            html_text = lookup_MDM_value(MDM, "body.html.raw")
            body_text = html_text

        # Use first subject if exists and not empty, otherwise default
        # This should likely never occur, but just being safe.
        subjects = message_group.get("subjects", [])
        subject = (
            subjects[0]
            if subjects and subjects[0] and subjects[0].strip()
            else "Subject unknown. Email processed by Sublime Security."
        )

        email_data = {
            "subject": subject,
            "is_multipart": False,
            "body": body_text
            or "Email content not provided due to Sublime Security access controls.",
        }

        email = self.converter_to_stix.create_email_message(email_data)
        return email, observables, []  # No additional emails in single email case

    def _create_preview_emails(self, previews):
        """
        Creates simplified EmailMessage objects

        Args:
            previews (list): List of preview email dictionaries

        Returns:
            list: List of STIX objects (EmailMessage, EmailAddress, File)
        """
        all_objects = []

        for i, preview in enumerate(previews):
            if not preview:
                continue

            sender = None
            recipients = []

            if preview.get("sender_email_address"):
                sender_email = sanitize_email(preview["sender_email_address"])
                sender = self.converter_to_stix.create_email_address(value=sender_email)
                all_objects.append(sender)

            # Create recipient email addresses
            for recipient_addr in preview.get("recipients") or []:
                if recipient_addr:
                    recipient_addr = sanitize_email(recipient_addr)
                    recipient = self.converter_to_stix.create_email_address(
                        value=recipient_addr
                    )
                    recipients.append(recipient)
                    all_objects.append(recipient)

            # Create file objects from attachments
            attachment_hashes = preview.get("attachment_sha256s") or []
            for hash_value in attachment_hashes:
                if hash_value:
                    file_obj = self.converter_to_stix.create_file(
                        hashes={"SHA-256": hash_value},
                        file_name=None,
                        file_size=None,
                        mime_type=None,
                    )
                    all_objects.append(file_obj)

            # Note: Not creating preview EmailMessage objects to avoid noise
            # Preview emails don't have full body/URL data, only the MDM email has complete data
            # We extract sender/recipient EmailAddresses and File attachments above

        return all_objects

    def _create_description(self, message_group):
        """
        Create detailed description with alert labels, subject, and recipient details.
        Args:
            base_description (str): Basic description to start with
            message_group (dict): Original message group data from Sublime API

        Returns:
            str: Rich description with alert labels, subject, and recipients
        """
        try:
            subjects = message_group.get("subjects", [])
            subject = subjects[0] if subjects else "Unknown Subject"
            flagged_rules = message_group.get("flagged_rules", [])
            attack_score = message_group.get("attack_score_verdict") or "unknown"
            email_count = len(message_group.get("previews", []))
            email_plural = "email" if email_count == 1 else "emails"
            description = "{} email group with {} {} detected by Sublime.".format(
                attack_score.capitalize(), email_count, email_plural
            )

            attack_score = message_group.get("attack_score_verdict") or "unknown"
            flagged_rules = message_group.get("flagged_rules", [])

            description += "\n\n**Sublime Alert Labels:**\n"
            description += "- email-threat\n"
            description += "- sublime-attack-score-{}\n".format(attack_score)

            if flagged_rules:
                rule_names = [
                    rule.get("rule_meta", {}).get("name", "Unknown")
                    for rule in flagged_rules
                ]
                for rule_name in rule_names:
                    description += "- rule-{}\n".format(
                        rule_name.lower().replace(" ", "-")
                    )

            subjects = message_group.get("subjects", [])
            subject = subjects[0] if subjects else "Unknown Subject"
            description += "\n**Subject:** {}\n".format(subject)

            # Collect unique recipients from both MDM and previews
            recipients = set()
            MDM = message_group.get("MDM", {})

            if MDM:
                to_list = lookup_MDM_value(MDM, "recipients.to") or []
                for recipient in to_list:
                    email = lookup_MDM_value(recipient, "email.email")
                    if email:
                        recipients.add(email)

            for preview in message_group.get("previews", []):
                if not preview:
                    continue
                recipient_list = preview.get("recipients", []) or []
                for recipient in recipient_list:
                    if recipient:
                        recipients.add(recipient)

            if recipients:
                description += "\n**Recipients ({}):**\n".format(len(recipients))
                sorted_recipients = sorted(list(recipients))
                for recipient in sorted_recipients:
                    description += "- {}\n".format(recipient)
            else:
                description += "\n**Recipients:** None identified\n"

            return description

        except Exception as e:
            self.helper.connector_logger.warning(
                "[Sublime Connector] Failed to create description", {"error": e}
            )
            return "Malicious email group detected by Sublime Security. Description unavailable."

    def _create_group_incident(self, message_group):
        """
        Creates a STIX Incident bundle to ingest as Event Incident

        Args:
            message_group (dict): Message group data from Sublime API

        Returns:
            stix2.Incident: STIX Incident object
        """
        group_id = message_group.get("id", "unknown")
        attack_score_verdict = message_group.get("attack_score_verdict", "unknown")

        # Generate incident name with same structure as case name
        incident_name = self._generate_incident_name(message_group)

        incident_description = self._create_description(message_group)

        # Get created timestamp from message group (use last_created_at for most recent activity)
        created_timestamp = message_group.get("last_created_at") or message_group.get(
            "first_created_at"
        )

        # Create Event Incident with deterministic ID
        incident = self.converter_to_stix.create_incident(
            name=incident_name,
            created_timestamp=created_timestamp,
            description=incident_description,
            group_id=group_id,
            incident_type=self.config.sublime.incident_type,
            url=f"{self.config.sublime.url.unicode_string()}/messages/{group_id or 'unknown'}",
            severity=map_attack_score_to_level(
                self.config.sublime.set_priority,
                self.config.sublime.set_severity,
                attack_score_verdict,
                "severity",
            ),
        )

        return incident

    def _generate_incident_name(self, message_group):
        """
        Generate incident name with same structure as case name.
        This all allows for aggregate values within the name.

        Args:
            message_group (dict): Original message group data from Sublime API

        Returns:
            str: Incident name with sender, count, and recipient details
        """
        try:
            sender_email = "Unknown Sender"
            MDM = message_group.get("MDM", {})
            if MDM and lookup_MDM_value(MDM, "sender.email.email"):
                sender_email = sanitize_email(
                    lookup_MDM_value(MDM, "sender.email.email")
                )
            elif message_group.get("previews"):
                for preview in message_group.get("previews", []):
                    if not preview:
                        continue
                    if preview.get("sender_email_address"):
                        sender_email = sanitize_email(
                            preview.get("sender_email_address")
                        )
                        break

            preview_count = len(message_group.get("previews", []))
            has_primary = bool(MDM and lookup_MDM_value(MDM, "sender.email.email"))
            email_count = max(preview_count, 1) if has_primary else preview_count

            recipients = set()
            if MDM:
                to_list = lookup_MDM_value(MDM, "recipients.to") or []
                for recipient in to_list:
                    email = lookup_MDM_value(recipient, "email.email")
                    if email:
                        recipients.add(email)

            for preview in message_group.get("previews", []):
                if not preview:
                    continue
                recipient_list = preview.get("recipients", []) or []
                for recipient in recipient_list:
                    if recipient:
                        recipients.add(recipient)

            recipient_count = len(recipients)

            # Get message group subject
            subjects = message_group.get("subjects", [])
            subject = subjects[0] if subjects else "Unknown Subject"
            if len(subject) > 10:
                subject_abbreviated = "[{}...{}]".format(subject[:7], subject[-3:])
            elif not subject:
                subject_abbreviated = ""
            else:
                subject_abbreviated = "[{}]".format(subject)

            email_plural = "Email" if email_count == 1 else "Emails"
            recipient_plural = "Recipient" if recipient_count == 1 else "Recipients"

            if email_count == 0:
                incident_name = "{} {} Sent {} to {} {}. {}".format(
                    self.config.sublime.incident_prefix,
                    sender_email,
                    email_plural,
                    recipient_count,
                    recipient_plural,
                    subject_abbreviated,
                )
            else:
                count_display = (
                    "{}".format(email_count) if preview_count > 0 else str(email_count)
                )
                incident_name = "{} {} Sent {} {} to {} {}. {}".format(
                    self.config.sublime.incident_prefix,
                    sender_email,
                    count_display,
                    email_plural,
                    recipient_count,
                    recipient_plural,
                    subject_abbreviated,
                )

            return incident_name

        except Exception as e:
            self.helper.connector_logger.warning(
                "[Sublime Connector] Failed to generate incident name. Using fallback.",
                {"error": e},
            )
            # Fallback to simple incident naming
            return f"{self.config.sublime.incident_prefix} {subject}"

    def _create_opencti_case(self, incident, stix_objects, message_group):
        """
        Create a CaseIncident STIX object for the incident.

        Args:
            incident (stix2.Incident): The main incident object
            stix_objects (list): All STIX objects created for this message group
            message_group (dict): Original message group data from Sublime API

        Returns:
            CustomObjectCaseIncident or None: The case STIX object, or None on failure.
        """
        group_id = message_group.get("id", "unknown")

        try:
            MDM = message_group.get("MDM", {})
            sender_email = (
                sanitize_email(lookup_MDM_value(MDM, "sender.email.email"))
                if lookup_MDM_value(MDM, "sender.email.email")
                else sanitize_email(
                    next(
                        (
                            p.get("sender_email_address")
                            for p in message_group.get("previews", [])
                            if p and p.get("sender_email_address")
                        ),
                        "Unknown Sender",
                    )
                )
            )

            preview_count = len(message_group.get("previews", []))
            has_primary = bool(MDM and lookup_MDM_value(MDM, "sender.email.email"))
            email_count = max(preview_count, 1) if has_primary else preview_count

            recipients = set()
            if MDM:
                to_list = lookup_MDM_value(MDM, "recipients.to") or []
                for recipient in to_list:
                    email = lookup_MDM_value(recipient, "email.email")
                    if email:
                        recipients.add(email)

            for preview in message_group.get("previews", []):
                if not preview:
                    continue
                recipient_list = preview.get("recipients", []) or []
                for recipient in recipient_list:
                    if recipient:
                        recipients.add(recipient)

            recipient_count = len(recipients)

            # Create case name with plural handling
            email_plural = "Email" if email_count == 1 else "Emails"
            recipient_plural = "Recipient" if recipient_count == 1 else "Recipients"

            # Abbreviate subject for case name. Adjust if you'd like
            subjects = message_group.get("subjects", [])
            subject = subjects[0] if subjects else ""
            subject_abbreviated = (
                "[{}...{}]".format(subject[:11], subject[-3:])
                if len(subject) > 15
                else "[{}]".format(subject) if subject else ""
            )

            # Build case name
            case_name = "{} {} Sent {} {} to {} {}. {}".format(
                self.config.sublime.case_prefix,
                sender_email,
                email_count,
                email_plural,
                recipient_count,
                recipient_plural,
                subject_abbreviated,
            )
            object_refs = [incident.id] + [
                obj.id
                for obj in stix_objects
                if hasattr(obj, "id")
                and obj.id not in [self.sublime_identity.id, incident.id]
            ]

            # Use incident's external references for the case
            external_refs = [
                {
                    "source_name": ref.source_name,
                    "description": ref.description,
                    "url": ref.url,
                    "external_id": ref.external_id,
                }
                for ref in incident.external_references
            ]

            case_description = self._create_description(message_group)

            # Use incident's created timestamp for deterministic ID generation
            created_timestamp = incident.created

            # Add priority and severity if configured
            attack_score_verdict = message_group.get("attack_score_verdict")

            priority = map_attack_score_to_level(
                self.config.sublime.set_priority,
                self.config.sublime.set_severity,
                attack_score_verdict,
                "priority",
            )
            severity = map_attack_score_to_level(
                self.config.sublime.set_priority,
                self.config.sublime.set_severity,
                attack_score_verdict,
                "severity",
            )

            self.helper.connector_logger.info(
                "[Sublime Connector] Creating case incident STIX object for group",
                {"group_id": group_id},
            )

            case = self.converter_to_stix.create_case_incident(
                name=case_name,
                created=created_timestamp,
                description=case_description,
                object_refs=object_refs,
                external_references=external_refs,
                severity=severity,
                priority=priority,
            )

            self.helper.connector_logger.info(
                "[Sublime Connector] Successfully created case incident",
                {"case_id": case.id},
            )
            return case

        except Exception as e:
            self.helper.connector_logger.error(
                "[Sublime Connector] Failed to create case for incident",
                {"incident_id": incident.id, "error": e},
            )
            return None

    def _create_indicator_for_observable(self, observable):
        """
        Create a single STIX indicator from an observable using pycti utilities.

        Uses OpenCTIStix2Utils to generate proper STIX patterns and creates
        Indicator objects with malicious-activity labels.

        Args:
            observable (stix2.SDO): STIX observable object

        Returns:
            stix2.Indicator: STIX Indicator object, or None if type not supported
        """
        from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils

        # Argument can be made to make Indicators out of files. For now, they will remain as simple observables.
        if observable._type == "file":
            return None

        # Use pycti utility to create STIX pattern
        pattern = OpenCTIStix2Utils.create_stix_pattern(
            observable._type, observable.value
        )
        if not pattern:
            return None

        # Log pattern generation for troubleshooting if needed
        # self.helper.connector_logger.debug("Generated STIX pattern for {}: {}".format(observable._type, pattern))

        # Create indicator with proper metadata
        indicator = self.converter_to_stix.create_indicator(pattern=pattern)

        return indicator

    def _create_relationships(
        self, incident, primary_email, all_emails, observables, indicators
    ):
        """
        Create relationships between incident and all related objects.

        Args:
            incident (stix2.Incident): Main incident object
            primary_email (stix2.EmailMessage): Primary detailed email
            all_emails (list): List of all email objects (preview + additional)
            observables (list): List of observable objects (excludes EmailMessage objects)
            indicators (list): List of indicator objects (unused in current implementation)

        Returns:
            list: List of STIX Relationship objects
        """
        relationships = []

        if primary_email and hasattr(primary_email, "id"):
            relationships.append(
                self.converter_to_stix.create_relationship(
                    source_id=incident.id,
                    target_id=primary_email.id,
                    relationship_type="related-to",
                )
            )

        for observable in observables:
            if observable and hasattr(observable, "id"):
                relationships.append(
                    self.converter_to_stix.create_relationship(
                        source_id=incident.id,
                        target_id=observable.id,
                        relationship_type="related-to",
                    )
                )

        for obj in all_emails:
            if (
                obj
                and hasattr(obj, "_type")
                and obj._type == "email-message"
                and hasattr(obj, "id")
            ):
                relationships.append(
                    self.converter_to_stix.create_relationship(
                        source_id=incident.id,
                        target_id=obj.id,
                        relationship_type="related-to",
                    )
                )

        for indicator in indicators:
            if indicator and hasattr(indicator, "id"):
                relationships.append(
                    self.converter_to_stix.create_relationship(
                        source_id=incident.id,
                        target_id=indicator.id,
                        relationship_type="related-to",
                    )
                )

        return relationships

    def _extract_recipients(self, MDM):
        """
        Extract recipient email addresses from message data model.

        Args:
            MDM (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.EmailAddress objects for recipients
        """
        recipients = []
        to_list = lookup_MDM_value(MDM, "recipients.to") or []
        for recipient in to_list:
            email = lookup_MDM_value(recipient, "email.email")
            if email:
                email = sanitize_email(email)
                recipients.append(
                    self.converter_to_stix.create_email_address(value=email)
                )
        return recipients

    def _extract_urls(self, MDM):
        """
        Extract URLs from email body links.

        Args:
            MDM (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.URL objects
        """
        urls = []
        links = lookup_MDM_value(MDM, "body.links") or []
        for link in links:
            url = lookup_MDM_value(link, "href_url.url")
            if url:
                if "://" not in url:
                    scheme = lookup_MDM_value(link, "href_url.scheme") or "http"
                    url = "{}://{}".format(scheme, url)
                urls.append(self.converter_to_stix.create_url(url=url))
        return urls

    def _extract_domains(self, MDM):
        """
        Extract domains from email headers. Deduplicates based on lowercase domain names.

        Args:
            MDM (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.DomainName objects
        """
        domains = []
        seen = set()

        header_domains = lookup_MDM_value(MDM, "headers.domains") or []
        for domain_info in header_domains:
            domain = domain_info.get("domain")
            if domain and domain.lower() not in seen:
                seen.add(domain.lower())
                domains.append(self.converter_to_stix.create_domain_name(value=domain))

        return domains

    def _extract_ips(self, MDM):
        """
        Extract IP addresses from email headers.
        Differentiates IPv4 vs IPv6 based on presence of colons.

        Args:
            MDM (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.IPv4Address or stix2.IPv6Address objects
        """
        ips = []
        header_ips = lookup_MDM_value(MDM, "headers.ips") or []
        for ip_info in header_ips:
            ip = ip_info.get("ip")
            if ip:
                ips.append(self.converter_to_stix.create_ip_address(ip_value=ip))
        return ips

    def _extract_attachments(self, MDM):
        """
        Extract file attachments with complete metadata.

        Args:
            MDM (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.File objects
        """
        files = []
        attachments = lookup_MDM_value(MDM, "attachments") or []

        for attachment in attachments:
            filename = attachment.get("file_name")
            if not filename:
                continue

            sha256 = attachment.get("sha256")
            if not sha256:
                continue

            hashes = {"SHA-256": sha256}
            file_size = attachment.get("size")

            # Only use MIME type if provided and not generic
            mime_type = (
                content_type
                if (content_type := attachment.get("content_type"))
                and content_type != "application/octet-stream"
                else None
            )

            files.append(
                self.converter_to_stix.create_file(
                    hashes=hashes,
                    file_name=filename,
                    file_size=file_size,
                    mime_type=mime_type,
                )
            )

        return files

    def _process_message_batch(self, messages, work_id):
        """
        Process a single batch of messages and send to OpenCTI.

        For each message in the batch:
        * Validates message structure
        * Creates STIX objects
        * Creates STIX bundle
        * Sends bundle to OpenCTI

        Args:
            messages (list): List of message group dictionaries from Sublime API
            work_id (str): OpenCTI work ID for tracking progress

        Returns:
            tuple: (processed_count, latest_timestamp)
        """
        processed_count = 0
        latest_timestamp = None

        if not hasattr(self, "_existing_group_ids"):
            self._existing_group_ids = self._get_existing_group_ids()

        for message in messages:
            try:
                group_id = message.get("id", "unknown")

                if not self._validate_message(message):
                    self.helper.connector_logger.warning(
                        "[Sublime Connector] Skipping group - failed basic validation",
                        {"group_id": group_id},
                    )
                    continue

                # Check if this message group already exists in OpenCTI using temp cache
                if group_id in self._existing_group_ids:
                    self.helper.connector_logger.debug(
                        "[Sublime Connector] Skipping existing group",
                        {"group_id": group_id},
                    )
                    continue

                existing_incident = None
                try:
                    all_incidents = self.helper.api.incident.list()
                    self.helper.connector_logger.debug(
                        "[Sublime Connector] Checking incidents for external reference match",
                        {"length_incident": len(all_incidents) if all_incidents else 0},
                    )

                    if all_incidents:
                        for incident_obj in all_incidents:
                            incident_ext_refs = incident_obj.get(
                                "externalReferences", []
                            )
                            for ext_ref in incident_ext_refs:
                                if ext_ref.get("external_id") == group_id:
                                    existing_incident = incident_obj
                                    self.helper.connector_logger.info(
                                        "[Sublime Connector] Found existing event incident by external_id",
                                        {
                                            "incident_id": incident_obj.get("id"),
                                            "group_id": group_id,
                                        },
                                    )
                                    break
                            if existing_incident:
                                break

                        if existing_incident:
                            self.helper.connector_logger.debug(
                                "[Sublime Connector] Skipping group - event incident already exists",
                                {
                                    "group_id": group_id,
                                    "incident_id": existing_incident.get("id"),
                                },
                            )
                            continue
                        else:
                            self.helper.connector_logger.debug(
                                "[Sublime Connector] No existing event incident found for group",
                                {
                                    "group_id": group_id,
                                    "length_incident": (
                                        len(all_incidents) if all_incidents else 0
                                    ),
                                },
                            )

                except Exception as incident_check_error:
                    self.helper.connector_logger.warning(
                        "[Sublime Connector] Event incident existence check failed",
                        {"error": incident_check_error},
                    )

                # Create STIX objects
                stix_objects, incident = self._create_stix_objects(message)

                # Ensure stix_objects is a flat list of individual STIX objects
                flattened_objects = []
                for obj in stix_objects:
                    if isinstance(obj, list):
                        # Flatten nested lists (can happen with observables from _create_primary_email)
                        flattened_objects.extend(obj)
                    else:
                        flattened_objects.append(obj)
                stix_objects = flattened_objects

                # Deduplicate objects by ID to avoid "single ref" conflicts
                seen_ids = set()
                unique_objects = []
                for obj in stix_objects:
                    obj_id = getattr(obj, "id", None)
                    if obj_id and obj_id in seen_ids:
                        continue
                    if obj_id:
                        seen_ids.add(obj_id)
                    unique_objects.append(obj)
                stix_objects = unique_objects

                # Create case incident STIX object if enabled
                if self.config.sublime.auto_create_cases:
                    case = self._create_opencti_case(incident, stix_objects, message)
                    if case:
                        stix_objects.append(case)

                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)

                # Send to OpenCTI
                self.helper.connector_logger.debug(
                    "[Sublime Connector] About to send STIX Bundle for incident",
                    {"incident_id": incident.id},
                )

                try:
                    self.helper.send_stix2_bundle(
                        stix_objects_bundle,
                        work_id=work_id,
                        update=True,
                        cleanup_inconsistent_bundle=True,
                    )
                    self.helper.connector_logger.debug(
                        "[Sublime Connector] Bundle sent successfully for incident",
                        {"incident_id": incident.id},
                    )
                except Exception as bundle_error:
                    self.helper.connector_logger.warning(
                        "[Sublime Connector] Failed to send STIX bundle for incident",
                        {"incident_id": incident.id, "error": bundle_error},
                    )

                processed_count += 1

                # Track latest timestamp (use last_created_at for most recent activity in group)
                msg_timestamp = message.get("last_created_at") or message.get(
                    "first_created_at"
                )
                if msg_timestamp and (
                    not latest_timestamp or msg_timestamp > latest_timestamp
                ):
                    latest_timestamp = msg_timestamp

            except Exception as e:
                canonical_id = message.get("id", "unknown")
                self.helper.connector_logger.error(
                    "[Sublime Connector] Failed to process message",
                    {"canonical_id": canonical_id, "error": e},
                )

        return processed_count, latest_timestamp

    def _get_existing_group_ids(self):
        """
        Get existing Sublime group IDs from OpenCTI incidents and cases.
        Retrieve most recent N cases to build temp cache in memory.
        Parse cache for external references from each case to ensure there's no duplicate incidents or cases.

        Returns:
            set: Set of existing group IDs
        """
        num_cases_for_external_lookups = 1000
        existing_group_ids = set()

        try:
            # Get group IDs from incidents and cases using shared method
            incidents = self.helper.api.incident.list(
                first=num_cases_for_external_lookups
            )
            cases = self.helper.api.case_incident.list(
                first=num_cases_for_external_lookups
            )

            # Extract group IDs from incidents
            for obj in incidents:
                ext_refs = obj.get("externalReferences", [])
                for ext_ref in ext_refs:
                    if ext_ref.get("source_name") == "Sublime" and ext_ref.get(
                        "external_id"
                    ):
                        existing_group_ids.add(ext_ref["external_id"])

            # Extract group IDs from cases
            for obj in cases:
                ext_refs = obj.get("externalReferences", [])
                for ext_ref in ext_refs:
                    if ext_ref.get("source_name") == "Sublime" and ext_ref.get(
                        "external_id"
                    ):
                        existing_group_ids.add(ext_ref["external_id"])

            self.helper.connector_logger.info(
                "[Sublime Connector] Found existing Sublime group IDs in OpenCTI",
                {"length_group_ids": len(existing_group_ids)},
            )
            return existing_group_ids

        except Exception as e:
            self.helper.connector_logger.warning(
                "[Sublime Connector] Error fetching existing group IDs", {"error": e}
            )
            return set()

    def _process_messages(self):
        """
        Process messages using batch processing with incremental state updates.

        Returns:
            int: Total number of messages processed
        """
        work_id = None
        current_state = self.helper.get_state() or {}

        # Get last processed timestamp
        since_timestamp = self.get_last_run(current_state)
        self.helper.connector_logger.debug(
            "[Sublime Connector] Fetching messages",
            {"since_timestamp": since_timestamp},
        )

        # Mark first run as completed after getting timestamp
        if not self._first_run_completed:
            self._first_run_completed = True

        try:
            total_processed = 0
            global_latest_timestamp = None

            for batch_messages in self._fetch_messages(since_timestamp):
                if not batch_messages:
                    continue

                if not work_id and batch_messages:
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, "Sublime Import"
                    )

                self.helper.connector_logger.info(
                    "[Sublime Connector] Processing batch of messages",
                    {"length_batch_messages": len(batch_messages)},
                )

                batch_processed, batch_latest_timestamp = self._process_message_batch(
                    batch_messages, work_id
                )

                total_processed += batch_processed

                if batch_latest_timestamp and (
                    not global_latest_timestamp
                    or batch_latest_timestamp > global_latest_timestamp
                ):
                    global_latest_timestamp = batch_latest_timestamp

                if global_latest_timestamp:
                    current_state["last_timestamp"] = global_latest_timestamp
                    self.helper.set_state(current_state)
                    self.helper.connector_logger.debug(
                        "Batch complete: {} processed this batch, {} total processed, state updated to {}".format(
                            batch_processed, total_processed, global_latest_timestamp
                        )
                    )

            if not global_latest_timestamp:
                current_time = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z"
                )
                current_state["last_timestamp"] = current_time
                self.helper.set_state(current_state)

            self.helper.connector_logger.info(
                "[Sublime Connector] Processed messages",
                {
                    "total_processed": total_processed,
                },
            )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[Sublime Connector] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(
                "[Sublime Connector] Batch processing failed",
                {"total_processed": total_processed, "error": e},
            )
        finally:
            if work_id:
                message = f"{self.helper.connect_name} connector successfully run"
                self.helper.api.work.to_processed(work_id, message)

    def run(self):
        """
        Run the main process using OpenCTI scheduler
        """
        self.helper.schedule_iso(
            message_callback=self._process_messages,
            duration_period=self.config.connector.duration_period,
        )
