"""
Sublime Security OpenCTI Connector
Simplified implementation following OpenCTI connector patterns
"""

import json
import os
import sys
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone

import isodate
import requests
import stix2
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class SublimeConnector:
    """
    Sublime Security external import connector for OpenCTI
    """

    def __init__(self):
        """
        Initialize the Sublime Security OpenCTI connector.

        Configuration Sources (in priority order):
        1. Environment variables
        2. config.yml file (if exists)
        3. Default values

        Environment Variables:
            Required:
                OPENCTI_URL, OPENCTI_TOKEN,
                CONNECTOR_ID, CONNECTOR_NAME, CONNECTOR_SCOPE,
                SUBLIME_TOKEN, SUBLIME_URL

            Optional:
                SUBLIME_INCIDENT_PREFIX (default: 'Sublime Alert: ')
                SUBLIME_CASE_PREFIX (default: 'Case: ')
                SUBLIME_AUTO_CREATE_CASES (default: True)
                SUBLIME_VERDICTS (default: 'malicious')
                SUBLIME_CONFIDENCE_LEVEL (default: 80)
                SUBLIME_INCIDENT_TYPE (default: 'phishing')
                SUBLIME_HISTORICAL_INGEST (default: False)
                SUBLIME_HISTORICAL_INGEST_DAYS (default: 14)

        Raises:
            ValueError: If required environment variables are missing
        """
        # Load configuration from config.yml if it exists
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config_dict = {}

        if os.path.isfile(config_file_path):
            try:
                with open(config_file_path, "r", encoding="utf-8") as config_file:
                    config_dict = yaml.safe_load(config_file)
                print("[*] Loaded configuration from {}".format(config_file_path))
            except Exception as e:
                print(
                    "[WARNING] Failed to load config.yml: {}. Default values may be used.".format(
                        e
                    )
                )
                config_dict = {}

        # Initialize configuration for OpenCTI connector pattern
        config = {
            "opencti": {
                "url": get_config_variable(
                    "OPENCTI_URL", ["opencti", "url"], config_dict, False
                ),
                "token": get_config_variable(
                    "OPENCTI_TOKEN", ["opencti", "token"], config_dict, False
                ),
            },
            "connector": {
                "id": get_config_variable(
                    "CONNECTOR_ID", ["connector", "id"], config_dict, False
                ),
                "type": "EXTERNAL_IMPORT",
                "name": get_config_variable(
                    "CONNECTOR_NAME", ["connector", "name"], config_dict, False
                ),
                "scope": get_config_variable(
                    "CONNECTOR_SCOPE", ["connector", "scope"], config_dict, False
                ),
                "log_level": get_config_variable(
                    "CONNECTOR_LOG_LEVEL",
                    ["connector", "log_level"],
                    config_dict,
                    False,
                    "info",
                ),
                "duration_period": get_config_variable(
                    "CONNECTOR_DURATION_PERIOD",
                    ["connector", "duration_period"],
                    config_dict,
                    False,
                    "PT10M",
                ),
            },
        }

        # Validate required configuration
        if not config["opencti"]["url"]:
            raise ValueError("OPENCTI_URL environment variable is required")
        if not config["opencti"]["token"]:
            raise ValueError("OPENCTI_TOKEN environment variable is required")
        if not config["connector"]["id"]:
            raise ValueError("CONNECTOR_ID environment variable is required")
        if not config["connector"]["name"]:
            raise ValueError("CONNECTOR_NAME environment variable is required")
        if not config["connector"]["scope"]:
            raise ValueError("CONNECTOR_SCOPE environment variable is required")

        # Initialize OpenCTI helper
        self.helper = OpenCTIConnectorHelper(config)

        # Get Sublime specific config from environment variables or config.yml
        self.api_token = get_config_variable(
            "SUBLIME_TOKEN", ["sublime", "token"], config_dict, False
        )
        self.api_base_url = get_config_variable(
            "SUBLIME_URL",
            ["sublime", "url"],
            config_dict,
            False,
            "https://platform.sublime.security",
        )

        # Configurable naming and case creation. Making double sure we get data in them
        self.incident_name_prefix = get_config_variable(
            "SUBLIME_INCIDENT_PREFIX",
            ["sublime", "incident_prefix"],
            config_dict,
            False,
            "Sublime Incident - ",
        )
        self.case_name_prefix = get_config_variable(
            "SUBLIME_CASE_PREFIX",
            ["sublime", "case_prefix"],
            config_dict,
            False,
            "Case - ",
        )
        self.auto_create_cases = get_config_variable(
            "SUBLIME_AUTO_CREATE_CASES",
            ["sublime", "auto_create_cases"],
            config_dict,
            False,
            False,
        )

        # Processing and STIX configuration
        verdicts_config = get_config_variable(
            "SUBLIME_VERDICTS", ["sublime", "verdicts"], config_dict, False, "malicious"
        )
        self.verdicts = [
            v.strip().lower() for v in verdicts_config.split(",") if v.strip()
        ]

        self.confidence_level = int(
            get_config_variable(
                "SUBLIME_CONFIDENCE_LEVEL",
                ["sublime", "confidence_level"],
                config_dict,
                True,
                80,
            )
        )
        self.incident_type = get_config_variable(
            "SUBLIME_INCIDENT_TYPE",
            ["sublime", "incident_type"],
            config_dict,
            False,
            "phishing",
        )

        self.historical_ingest = get_config_variable(
            "SUBLIME_HISTORICAL_INGEST",
            ["sublime", "historical_ingest"],
            config_dict,
            False,
            False,
        )
        self.historical_ingest_days = get_config_variable(
            "SUBLIME_HISTORICAL_INGEST_DAYS",
            ["sublime", "historical_ingest_days"],
            config_dict,
            True,
            14,
        )

        if not self.api_token:
            raise ValueError("SUBLIME_TOKEN environment variable is required")

        # Interval pause between polling in seconds
        duration_period = config["connector"]["duration_period"]
        try:
            duration_obj = isodate.parse_duration(duration_period)
            self.poll_interval = int(duration_obj.total_seconds())

        except (isodate.ISO8601Error, ValueError) as e:
            self.helper.log_warning(
                '[!] Invalid duration format "{}": {}. Using default 5 minutes'.format(
                    duration_period, e
                )
            )
            self.poll_interval = 300  # 5 minutes default

        # Set default options
        self.update_existing_data = False

        # Create session for API requests
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": "Bearer {}".format(self.api_token),
                "Accept": "application/json",
                "User-Agent": "OpenCTI-SublimeConnector/1.0",
            }
        )

        # Create Sublime Identity for STIX objects
        self.sublime_identity = stix2.Identity(
            name="Sublime Security",
            identity_class="organization",
            description="Email Security Platform",
            custom_properties={"x_opencti_type": "Organization"},
            allow_custom=True,
        )

        self.helper.log_info("[*] Sublime connector initialized")
        self.helper.log_info(
            "[*] Configuration: verdicts={}, confidence={}, incident_type={}, duration_period:{}, historical_ingest: {}".format(
                self.verdicts,
                self.confidence_level,
                self.incident_type,
                duration_period,
                self.historical_ingest,
            )
        )

    def _make_deterministic_id(self, stix_type, unique_value):
        """Generate deterministic STIX ID to prevent duplicates"""
        namespace = uuid.uuid5(uuid.NAMESPACE_DNS, "sublime-security-opencti")
        deterministic_uuid = uuid.uuid5(
            namespace, "{}:{}".format(stix_type, unique_value)
        )
        return "{}--{}".format(stix_type, deterministic_uuid)

    def _get_last_timestamp(self):
        """
        Get the last processed timestamp from OpenCTI connector state.

        Returns:
            str: ISO 8601 timestamp string of last processed message,
                 or 5 minutes ago if no previous state exists
        """
        current_state = self.helper.get_state()
        if current_state and "last_timestamp" in current_state:
            return current_state["last_timestamp"]

        # Default to 5 minutes ago with Sublime API timestamp format
        default_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        # Format for Sublime API: 2025-06-07T05:00:00.000Z
        return default_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _set_last_timestamp(self, timestamp):
        """
        Update the last processed timestamp in OpenCTI connector state.

        Args:
            timestamp (str): ISO 8601 timestamp string to save as last processed
        """
        current_state = self.helper.get_state() or {}
        current_state["last_timestamp"] = timestamp
        self.helper.set_state(current_state)

    def _fetch_group_ids(self, start_time, end_time):
        """
        Fetch list of flagged group IDs within time range from Sublime API.

        Args:
            start_time (str): ISO 8601 timestamp for range start
            end_time (str): ISO 8601 timestamp for range end

        Returns:
            list: List of group canonical IDs that are flagged

        Raises:
            Exception: API request failures or authentication errors
        """
        # Build query parameters for flagged message groups
        params = {
            "created_at__gte": start_time,
            "created_at__lt": end_time,
            "fetch_all_ids": True,
            "stats_limit": 100000,
            "flagged__eq": True,
        }

        api_url = self.api_base_url.rstrip("/")
        if not api_url.endswith("/v1"):
            api_url = api_url + "/v1"

        full_url = "{}/messages/groups".format(api_url)

        # Debug logging for API requests
        self.helper.log_info(
            "[*] Fetch Time range: {} to {}".format(start_time, end_time)
        )
        self.helper.log_debug("[DEBUG] API Request parameters: {}".format(params))

        response = self.session.get(full_url, params=params, timeout=30)

        # Debug response details
        if not response.ok:
            self.helper.log_error(
                "[!] API request failed - Status: {}, Response: {}".format(
                    response.status_code, response.text[:500]
                )
            )
            raise Exception(
                "API request failed: {} {}".format(response.status_code, response.text)
            )

        data = response.json()
        group_ids = data.get("all_group_canonical_ids")

        # Handle case where API returns None or doesn't include the field
        if group_ids is None:
            self.helper.log_warning(
                "[!] API response missing all_group_canonical_ids field"
            )
            self.helper.log_warning("[*] Response data: {}".format(data))
            group_ids = []

        self.helper.log_info("[*] Found {} flagged group IDs".format(len(group_ids)))
        return group_ids

    def _fetch_single_group(self, group_id):
        """
        Fetch individual message group by ID from Sublime API.

        Args:
            group_id (str): Canonical ID of the message group to fetch

        Returns:
            dict: Message group data dictionary, or None if fetch fails
        """
        api_url = self.api_base_url.rstrip("/")
        if not api_url.endswith("/v1"):
            api_url = api_url + "/v1"

        full_url = "{}/messages/groups/{}".format(api_url, group_id)

        self.helper.log_debug("Fetching group: {}".format(full_url))

        response = self.session.get(full_url, timeout=30)

        if not response.ok:
            self.helper.log_warning(
                "[!] Failed to fetch group {}: {} {}".format(
                    group_id, response.status_code, response.text[:200]
                )
            )
            return None

        return response.json()

    def _fetch_messages(self, since_timestamp):
        """
        Fetch malicious message groups from Sublime API since provided time.

        Uses a two-step process:
        1. Fetch list of flagged group IDs within time range
        2. Fetch individual groups and filter by 'malicious' attack score verdict

        Args:
            since_timestamp (str): ISO 8601 timestamp to fetch messages since

        Returns:
            list: List of message group dictionaries with 'malicious' verdict

        Raises:
            Exception: Network errors or JSON parsing failures
        """
        # Calculate time boundaries for this fetch
        if since_timestamp:
            start_time = since_timestamp
        else:
            # Default to 5 mins ago for frequent polling
            # TODO This hasn't been fully tested
            start_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )

        # End time is now (to avoid missing messages created during the fetch)
        end_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        try:
            # Step 1: Get list of flagged group IDs
            group_ids = self._fetch_group_ids(start_time, end_time)
            if not group_ids:
                self.helper.log_debug(
                    "[DEBUG] No flagged message groups found in time range"
                )
                return []

            # Step 2: Fetch individual message groups and filter by malicious verdict
            all_messages = []
            for group_id in group_ids:
                message_group = self._fetch_single_group(group_id)
                if message_group:
                    # Filter by attack score verdict (skip null/None verdicts)
                    attack_score_raw = message_group.get("attack_score_verdict")
                    if attack_score_raw is None:
                        self.helper.log_debug(
                            "[DEBUG] Skipping group {} with null verdict (no score assigned)".format(
                                group_id
                            )
                        )
                        continue

                    attack_score = attack_score_raw.lower()
                    if attack_score in self.verdicts:
                        all_messages.append(message_group)
                    else:
                        self.helper.log_debug(
                            "[DEBUG] Skipping group {} with verdict: {} (not in {})".format(
                                group_id, attack_score, self.verdicts
                            )
                        )

            self.helper.log_info(
                "[*] Fetched {} message groups (verdicts: {}) from {} total flagged groups".format(
                    len(all_messages), self.verdicts, len(group_ids)
                )
            )
            return all_messages

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
            self.helper.log_warning("[!] Message group missing id field")
            return False

        # Check for subjects
        if "subjects" not in message_group or not message_group.get("subjects"):
            self.helper.log_warning("[!] Message group missing subjects")
            return False

        # Check for data_model (where the detailed email data is)
        if "data_model" not in message_group:
            self.helper.log_warning("[!] Message group missing data_model")
            return False

        data_model = message_group["data_model"]

        # Check for sender in data_model
        if (
            "sender" not in data_model
            or "email" not in data_model.get("sender", {})
            or "email" not in data_model.get("sender", {}).get("email", {})
        ):
            self.helper.log_warning("[!] Message group data_model missing sender email")
            return False

        return True

    def _create_stix_objects(self, message_group):
        """
        Create STIX objects from Sublime message group.

        Creates:
        - One detailed EmailMessage from MDM (primary email)
        - Basic EmailMessage objects from preview data
        - Incident object representing the group
        - Cyber observables (URLs, domains, IPs, email addresses)
        - Indicators generated from observables
        - Relationships linking all objects to the incident

        Note: Case creation is handled separately via OpenCTI API

        Args:
            message_group (dict): Message group data from Sublime API

        Returns:
            tuple: (list of STIX objects ready for bundling, incident object)
        """
        objects = [self.sublime_identity]
        group_id = message_group.get("id", "unknown")
        previews = message_group.get("previews", [])

        self.helper.log_debug(
            "[DEBUG] Creating STIX bundle for group {} with {} emails".format(
                group_id, len(previews)
            )
        )

        # Create detailed email from MDM
        primary_email, observables = self._create_primary_email(message_group)
        if primary_email:
            objects.append(primary_email)
        objects.extend(observables)

        # Create basic emails from previews of other emails in group
        preview_emails = self._create_preview_emails(previews, group_id)
        objects.extend(preview_emails)

        # Create group event Incident
        incident = self._create_group_incident(message_group)
        objects.append(incident)

        # Create indicators from observables
        indicators = self._create_indicators(observables)
        objects.extend(indicators)

        # Link everything to incident
        relationships = self._create_relationships(
            incident, primary_email, preview_emails, observables, indicators
        )
        objects.extend(relationships)

        # Optional: Create detailed email-to-observable relationships
        # Comment out this section if not needed for simpler relationship model
        email_relationships = self._create_email_observable_relationships(
            primary_email, observables, message_group
        )
        objects.extend(email_relationships)

        self.helper.log_debug(
            "[DEBUG] Created {} total STIX objects".format(len(objects))
        )
        return objects, incident

    def _create_primary_email(self, message_group):
        """
        Create detailed EmailMessage from group's primary Message Data Model (MDM).

        Extracts rich threat intelligence including:
        - Email addresses (sender, recipients)
        - URLs from email body
        - Domains from headers
        - IP addresses from headers
        - Email content and metadata

        Args:
            message_group (dict): Message group data from Sublime API

        Returns:
            tuple: (EmailMessage object, list of observable objects)
        """
        data_model = message_group.get("data_model", {})
        if not data_model:
            return None, []

        observables = []

        # Extract email addresses
        sender = self._extract_sender(data_model)
        recipients = self._extract_recipients(data_model)
        if sender:
            observables.append(sender)
        observables.extend(recipients)

        # Extract threat indicators
        observables.extend(self._extract_urls(data_model))
        observables.extend(self._extract_domains(data_model))
        observables.extend(self._extract_ips(data_model))

        # Build email message (STIX2: is_multipart requires body)
        body_text = self._get_nested(data_model, "body.plain.raw")

        # To make an analyst's life easier, only use raw text and not HTML
        # But leave option.
        # html_content = self._get_nested(data_model, 'body.html.raw')

        # Edge case. Sometimes the raw body doesn't exist. In that case, use HTML
        # e.g. html.raw = <span style="display: none"></p></html>
        if not body_text:
            html_text = self._get_nested(data_model, "body.html.raw")
            body_text = html_text

        # Debug logging to understand the data structure
        # self.helper.log_info('[*] Body text: {} (type: {})'.format(
        #    'Present' if body_text else 'None', type(body_text).__name__))
        # self.helper.log_info('[*] HTML content: {} (type: {})'.format(
        #    'Present' if html_content else 'None', type(html_content).__name__))

        email_data = {
            "subject": self._get_nested(data_model, "subject.subject"),
            "from_ref": sender.id if sender else None,
            "to_refs": [r.id for r in recipients] if recipients else None,
            "date": self._get_nested(data_model, "headers.date"),
            "message_id": self._get_nested(data_model, "headers.message_id"),
        }

        if body_text and isinstance(body_text, str) and body_text.strip():
            # Use plain text body
            email_data["body"] = body_text
            """
        elif html_content:
            # Extract HTML content as string
            if isinstance(html_content, dict):
                html_text = html_content.get('raw') or str(html_content)
            elif isinstance(html_content, str):
                html_text = html_content
            else:
                html_text = str(html_content)

            if html_text and html_text.strip():
                email_data['body'] = html_text
            else:
                email_data['body'] = 'No content available'
            """
        else:
            # Fallback body
            email_data["body"] = "No content available"

        # Always set is_multipart to False to avoid complex STIX constraints
        email_data["is_multipart"] = False

        # Remove None values
        email_data = {k: v for k, v in email_data.items() if v is not None}

        # Final debug check
        self.helper.log_debug(
            "[DEBUG] Final email_data keys. : {}".format(list(email_data.keys()))
        )
        self.helper.log_debug("[DEBUG] Final email_data: {}".format(email_data))

        # Validate before leaving
        has_body = "body" in email_data
        has_is_multipart = "is_multipart" in email_data
        # self.helper.log_info('[*] Has body: {}, Has is_multipart: {}'.format(has_body, has_is_multipart))

        if has_is_multipart and not has_body:
            self.helper.log_error(
                "[!] Relationship error: is_multipart set but no body!"
            )
            self.helper.log_error("[!] Removing is_multipart to prevent error")
            email_data.pop("is_multipart", None)

        # Create EmailMessage with deterministic ID (is_multipart and body are now always provided)
        group_id = message_group.get("id", "unknown")
        email_data["id"] = self._make_deterministic_id(
            "email-message", "{}:primary".format(group_id)
        )
        email = stix2.EmailMessage(**email_data)
        return email, observables

    def _create_preview_emails(self, previews, group_id):
        """
        Create basic EmailMessage objects from preview data.

        Creates simplified EmailMessage objects with:
        - Subject and basic metadata
        - Email addresses (sender, recipients)
        - File objects from attachment hashes

        Args:
            previews (list): List of preview email dictionaries
            group_id (str): Group ID for deterministic ID generation

        Returns:
            list: List of STIX objects (EmailMessage, EmailAddress, File)
        """
        all_objects = []

        for i, preview in enumerate(previews):
            # Skip if preview is None or empty
            if not preview:
                self.helper.log_debug("[*] Skipping None or empty preview")
                continue

            # Debug logging for preview structure
            self.helper.log_debug(
                "[*] Processing preview: {}".format(
                    preview.keys()
                    if isinstance(preview, dict)
                    else type(preview).__name__
                )
            )

            # Create email addresses
            sender = None
            recipients = []

            if preview.get("sender_email_address"):
                sender_email = preview["sender_email_address"]
                sender = stix2.EmailAddress(
                    id=self._make_deterministic_id("email-addr", sender_email),
                    value=sender_email,
                )
                all_objects.append(sender)

            recipients_list = preview.get("recipients") or []
            for recipient_addr in recipients_list:
                if recipient_addr:
                    recipient = stix2.EmailAddress(
                        id=self._make_deterministic_id("email-addr", recipient_addr),
                        value=recipient_addr,
                    )
                    recipients.append(recipient)
                    all_objects.append(recipient)

            # Create file objects from attachments
            attachment_hashes = preview.get("attachment_sha256s") or []
            for hash_value in attachment_hashes:
                if hash_value:
                    file_obj = stix2.File(
                        id=self._make_deterministic_id("file", hash_value),
                        hashes={"SHA-256": hash_value},
                    )
                    all_objects.append(file_obj)

            # Create EmailMessage with required fields
            email_data = {
                "subject": preview.get("subject", "Unknown Subject"),
                "from_ref": sender.id if sender else None,
                "to_refs": [r.id for r in recipients] if recipients else None,
                "date": preview.get("created_at"),
                "body": preview.get("body_text"),  # Required field
                "is_multipart": False,  # Required field
            }

            # Remove None values and create if we have data
            email_data = {k: v for k, v in email_data.items() if v is not None}
            if email_data:
                email_data["id"] = self._make_deterministic_id(
                    "email-message", "{}:preview:{}".format(group_id, i)
                )
                email = stix2.EmailMessage(**email_data)
                all_objects.append(email)

        return all_objects

    def _create_group_incident(self, message_group):
        """
        Create incident representing the entire message group.

        Creates a STIX Incident with:
        - Descriptive name and details
        - Attack score and rule information
        - External reference to Sublime platform
        - Appropriate labels and metadata

        Args:
            message_group (dict): Message group data from Sublime API

        Returns:
            stix2.Incident: STIX Incident object
        """
        group_id = message_group.get("id", "unknown")
        subjects = message_group.get("subjects", [])
        subject = subjects[0] if subjects else "Unknown Subject"
        email_count = len(message_group.get("previews", []))
        flagged_rules = message_group.get("flagged_rules", [])
        attack_score = message_group.get("attack_score_verdict") or "unknown"

        # Build description
        description = (
            "Email threat group with {} emails detected by Sublime Security.\n".format(
                email_count
            )
        )
        description += 'Subject: "{}".\n Attack score: {}.'.format(
            subject, attack_score
        )

        labels = ["email-threat", "sublime-attack-score-{}".format(attack_score)]

        if flagged_rules:
            description += " Triggered rules:"
            rule_names = [
                rule.get("rule_meta", {}).get("name", "Unknown")
                for rule in flagged_rules
            ]
            for rule_name in rule_names:
                description += " {}.".format(rule_name)
                labels.append("rule-{}".format(rule_name.lower().replace(" ", "-")))

        # Create incident with deterministic ID
        incident = stix2.Incident(
            id=self._make_deterministic_id("incident", group_id),
            name="{} {}".format(self.incident_name_prefix, subject),
            description=description,
            labels=labels,
            created_by_ref=self.sublime_identity.id,
            object_marking_refs=[stix2.TLP_AMBER],
            external_references=[
                {
                    "source_name": "Sublime Security",
                    "description": "View this message group in Sublime Security platform",
                    "url": "{}/messages/{}".format(self.api_base_url, group_id),
                    "external_id": group_id,
                }
            ],
            custom_properties={
                "x_opencti_type": "Incident",
                "x_opencti_incident_type": self.incident_type,
                "x_sublime_security_canonical_id": group_id,
            },
            allow_custom=True,
            incident_type=self.incident_type.capitalize(),
            source="Sublime Security",
            confidence=self.confidence_level,
        )

        return incident

    def _create_opencti_case(self, incident, stix_objects, message_group):
        """
        Create a Case using OpenCTI API for the incident.

        Creates a case that references the incident and all related objects,
        following OpenCTI case management patterns.

        Args:
            incident (stix2.Incident): The main incident object
            stix_objects (list): All STIX objects created for this message group
            message_group (dict): Original message group data from Sublime API
        """
        try:
            # Extract case information from incident
            # Extract subject from incident name and apply case prefix
            subject = incident.name.replace(self.incident_name_prefix, "")
            case_name = "{} {}".format(self.case_name_prefix, subject)
            case_description = "Investigation case for {}\n\n{}".format(
                incident.name, incident.description
            )

            # Build list of object IDs for the case - include all objects from this message group
            object_ids = [incident.id]

            # Add all STIX objects from this specific message group (excluding identity)
            for obj in stix_objects:
                if (
                    hasattr(obj, "id")
                    and obj.id != self.sublime_identity.id
                    and obj.id != incident.id
                ):
                    object_ids.append(obj.id)

            # Convert STIX external references to dictionary format for OpenCTI API
            external_refs = []
            for ref in incident.external_references:
                external_refs.append(
                    {
                        "source_name": ref.source_name,
                        "description": ref.description,
                        "url": ref.url,
                        "external_id": ref.external_id,
                    }
                )

            # Create case data following the sample pattern
            case_data = {
                "name": case_name,
                "description": case_description,
                "objects": object_ids,
                "created_by": self.sublime_identity.id,
                "object_marking_refs": [stix2.TLP_AMBER.id],
                "external_references": external_refs,
            }

            # Create the case using OpenCTI helper's API
            case = self.helper.api.case_incident.create(**case_data)

            if case:
                self.helper.log_info(
                    "[*] Successfully created case with ID: {}".format(
                        case.get("id", "unknown")
                    )
                )
            else:
                self.helper.log_error("[!] Case creation returned None")

        except Exception as e:
            self.helper.log_error(
                "[!] Failed to create case for incident {}: {}".format(incident.id, e)
            )

    def _create_indicators(self, observables):
        """
        Create STIX indicators from cyber observables.

        Generates Indicator objects with appropriate STIX patterns for:
        - Email addresses
        - URLs
        - Domain names
        - IP addresses
        - File hashes

        Args:
            observables (list): List of STIX cyber observable objects

        Returns:
            list: List of STIX Indicator objects
        """
        indicators = []

        for observable in observables:
            try:
                indicator = self._create_indicator_for_observable(observable)
                if indicator:
                    indicators.append(indicator)
            except Exception as e:
                # Log the problematic observable value for debugging
                obs_value = getattr(observable, "value", "Unknown")
                self.helper.log_warning(
                    "[!] Failed to create indicator for {}: {}".format(
                        observable._type, e
                    )
                )
                self.helper.log_debug(
                    "[DEBUG] Problematic {} value: {}".format(
                        observable._type, obs_value
                    )
                )

        return indicators

    def _create_indicator_for_observable(self, observable):
        """
        Create a single STIX indicator from a cyber observable.

        Maps observable types to appropriate STIX patterns and creates
        Indicator objects with malicious-activity labels.

        Args:
            observable (stix2.SDO): STIX cyber observable object

        Returns:
            stix2.Indicator: STIX Indicator object, or None if type not supported
        """
        patterns = {
            "email-addr": lambda obs: f"[email-addr:value = '{self._escape_stix_value(obs.value)}']",
            "url": lambda obs: f"[url:value = '{self._escape_stix_value(obs.value)}']",
            "domain-name": lambda obs: f"[domain-name:value = '{self._escape_stix_value(obs.value)}']",
            "ipv4-addr": lambda obs: f"[ipv4-addr:value = '{self._escape_stix_value(obs.value)}']",
            "ipv6-addr": lambda obs: f"[ipv6-addr:value = '{self._escape_stix_value(obs.value)}']",
            "file": lambda obs: (
                f"[file:hashes.SHA-256 = '{self._escape_stix_value(list(obs.hashes.values())[0])}']"
                if obs.hashes
                else None
            ),
        }

        pattern_func = patterns.get(observable._type)
        if not pattern_func:
            return None

        pattern = pattern_func(observable)
        if not pattern:
            return None

        # Debug log the generated pattern for troubleshooting
        self.helper.log_debug(
            "[DEBUG] Generated STIX pattern for {}: {}".format(
                observable._type, pattern
            )
        )

        # Create indicator with proper metadata
        indicator = stix2.Indicator(
            pattern=pattern,
            pattern_type="stix",
            labels=["malicious-activity"],
            created_by_ref=self.sublime_identity.id,
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties={
                "x_opencti_type": "Indicator",
                "x_sublime_security_source": "email-threat",
            },
            allow_custom=True,
        )

        return indicator

    def _escape_stix_value(self, value):
        """
        Escape special characters in STIX pattern values to prevent syntax errors.

        STIX patterns use single quotes to delimit string values and backslashes
        for escaping. Both must be properly escaped to avoid parser errors.

        Args:
            value (str): The value to escape

        Returns:
            str: Escaped value safe for use in STIX patterns
        """
        if not isinstance(value, str):
            value = str(value)

        # Escape backslashes first (must be done before escaping single quotes)
        value = value.replace("\\", "\\\\")

        # Then escape single quotes
        value = value.replace("'", "\\'")

        return value

    def _create_relationships(
        self, incident, primary_email, preview_emails, observables, indicators
    ):
        """
        Create relationships between incident and all related objects.

        Links the incident to:
        - Primary email message
        - All cyber observables
        - Preview email messages

        Args:
            incident (stix2.Incident): Main incident object
            primary_email (stix2.EmailMessage): Primary detailed email
            preview_emails (list): List of preview email objects
            observables (list): List of cyber observable objects
            indicators (list): List of indicator objects (unused in current implementation)

        Returns:
            list: List of STIX Relationship objects
        """
        relationships = []

        # Link primary email to incident
        if primary_email:
            relationships.append(self._create_relationship(incident, primary_email))

        # Link observables to incident
        for observable in observables:
            relationships.append(self._create_relationship(incident, observable))

        # Link preview emails to incident
        for obj in preview_emails:
            if hasattr(obj, "_type") and obj._type == "email-message":
                relationships.append(self._create_relationship(incident, obj))

        return relationships

    def _create_email_observable_relationships(
        self, primary_email, observables, message_group
    ):
        """
        Create detailed relationships between EmailMessage and observables.

        Creates specific relationships showing which email contained which indicators:
        - EmailMessage -> URL (contains)
        - EmailMessage -> File (contains)
        - EmailMessage -> IPv4Address (originates-from)
        - EmailMessage -> DomainName (originates-from)
        - EmailAddress -> DomainName (belongs-to)

        This section can be easily commented out if simpler relationships are preferred.

        Args:
            primary_email (stix2.EmailMessage): Primary detailed email
            observables (list): List of cyber observable objects
            message_group (dict): Original message group data from Sublime API

        Returns:
            list: List of STIX Relationship objects
        """
        relationships = []

        if not primary_email:
            return relationships

        # Group observables by type for targeted relationship creation
        urls = [
            obs for obs in observables if hasattr(obs, "_type") and obs._type == "url"
        ]
        domains = [
            obs
            for obs in observables
            if hasattr(obs, "_type") and obs._type == "domain-name"
        ]
        ips = [
            obs
            for obs in observables
            if hasattr(obs, "_type") and obs._type in ["ipv4-addr", "ipv6-addr"]
        ]
        email_addresses = [
            obs
            for obs in observables
            if hasattr(obs, "_type") and obs._type == "email-addr"
        ]
        files = [
            obs for obs in observables if hasattr(obs, "_type") and obs._type == "file"
        ]

        # EmailMessage -> URL (contains) - URLs found in email body
        for url in urls:
            relationships.append(
                self._create_relationship(primary_email, url, "contains")
            )

        # EmailMessage -> File (contains) - File attachments
        for file_obj in files:
            relationships.append(
                self._create_relationship(primary_email, file_obj, "contains")
            )

        # EmailMessage -> IP (originates-from) - IPs from email headers showing message path
        for ip in ips:
            relationships.append(
                self._create_relationship(primary_email, ip, "originates-from")
            )

        # EmailMessage -> Domain (originates-from) - Domains from email headers showing message path
        for domain in domains:
            relationships.append(
                self._create_relationship(primary_email, domain, "originates-from")
            )

        # EmailAddress -> DomainName (belongs-to) - Link email addresses to their domains
        for email_addr in email_addresses:
            email_value = getattr(email_addr, "value", "")
            if "@" in email_value:
                domain_part = email_value.split("@")[1].lower()
                # Find matching domain observable
                for domain in domains:
                    if hasattr(domain, "value") and domain.value.lower() == domain_part:
                        relationships.append(
                            self._create_relationship(email_addr, domain, "belongs-to")
                        )
                        break

        if relationships:
            self.helper.log_debug(
                "[DEBUG] Created {} email-to-observable relationships".format(
                    len(relationships)
                )
            )

        return relationships

    def _create_relationship(self, source, target, relationship_type="related-to"):
        """
        Create a single relationship between two STIX objects.

        Uses deterministic ID generation for consistent relationships.

        Args:
            source (stix2.SDO): Source STIX object
            target (stix2.SDO): Target STIX object
            relationship_type (str): Type of relationship (default: 'related-to')

        Returns:
            stix2.Relationship: STIX Relationship object
        """
        from pycti import StixCoreRelationship

        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source.id, target.id
            ),
            relationship_type=relationship_type,
            source_ref=source.id,
            target_ref=target.id,
            created_by_ref=self.sublime_identity.id,
            confidence=self.confidence_level,
            object_marking_refs=[stix2.TLP_AMBER],
        )

    # Helper methods for data extraction
    def _get_nested(self, data, path):
        """
        Get nested dictionary value using dot notation.

        Args:
            data (dict): Dictionary to search
            path (str): Dot-separated path (e.g., 'sender.email.email')

        Returns:
            Any: Value at the path, or None if path doesn't exist
        """
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value

    def _extract_sender(self, data_model):
        """
        Extract sender email address from message data model.

        Args:
            data_model (dict): Message data model from Sublime API

        Returns:
            stix2.EmailAddress: Sender email address object, or None if not found
        """
        email = self._get_nested(data_model, "sender.email.email")
        if email:
            return stix2.EmailAddress(
                id=self._make_deterministic_id("email-addr", email), value=email
            )
        return None

    def _extract_recipients(self, data_model):
        """
        Extract recipient email addresses from message data model.

        Args:
            data_model (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.EmailAddress objects for recipients
        """
        recipients = []
        to_list = self._get_nested(data_model, "recipients.to") or []
        for recipient in to_list:
            email = self._get_nested(recipient, "email.email")
            if email:
                recipients.append(
                    stix2.EmailAddress(
                        id=self._make_deterministic_id("email-addr", email), value=email
                    )
                )
        return recipients

    def _extract_urls(self, data_model):
        """
        Extract URLs from email body links.

        Processes links from the email body and constructs full URLs
        with appropriate schemes if missing.

        Args:
            data_model (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.URL objects
        """
        urls = []
        links = self._get_nested(data_model, "body.links") or []
        for link in links:
            url = self._get_nested(link, "href_url.url")
            if url:
                if "://" not in url:
                    scheme = self._get_nested(link, "href_url.scheme") or "http"
                    url = "{}://{}".format(scheme, url)
                urls.append(
                    stix2.URL(id=self._make_deterministic_id("url", url), value=url)
                )
        return urls

    def _extract_domains(self, data_model):
        """
        Extract domains from email headers.
        Deduplicates based on lowercase domain names.

        Args:
            data_model (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.DomainName objects
        """
        domains = []
        seen = set()

        header_domains = self._get_nested(data_model, "headers.domains") or []
        for domain_info in header_domains:
            domain = domain_info.get("domain")
            if domain and domain.lower() not in seen:
                seen.add(domain.lower())
                domains.append(
                    stix2.DomainName(
                        id=self._make_deterministic_id("domain-name", domain.lower()),
                        value=domain,
                    )
                )

        return domains

    def _extract_ips(self, data_model):
        """
        Extract IP addresses from email headers.

        Automatically detects IPv4 vs IPv6 addresses based on presence of colons.

        Args:
            data_model (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.IPv4Address or stix2.IPv6Address objects
        """
        ips = []
        header_ips = self._get_nested(data_model, "headers.ips") or []
        for ip_info in header_ips:
            ip = ip_info.get("ip")
            if ip:
                ip_class = stix2.IPv6Address if ":" in ip else stix2.IPv4Address
                ip_type = "ipv6-addr" if ":" in ip else "ipv4-addr"
                ips.append(
                    ip_class(id=self._make_deterministic_id(ip_type, ip), value=ip)
                )
        return ips

    def _process_messages(self, messages):
        """
        Process messages and send to OpenCTI.

        For each message:
        1. Validates message structure
        2. Creates STIX objects
        3. Bundles objects
        4. Sends to OpenCTI
        5. Updates state with latest timestamp

        Args:
            messages (list): List of message group dictionaries from Sublime API
        """
        if not messages:
            return

        # Initialize work
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Sublime Security Import"
        )

        try:
            processed_count = 0
            latest_timestamp = None

            for message in messages:
                try:
                    if not self._validate_message(message):
                        continue

                    # Create STIX objects
                    stix_objects, incident = self._create_stix_objects(message)

                    # Create bundle with custom properties allowed
                    bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)

                    # For serious debugging, uncomment out this section. It is a lot of content
                    # self.helper.log_debug('[*] === COMPLETE STIX BUNDLE ===')
                    # self.helper.log_debug(bundle.serialize(pretty=True))
                    # self.helper.log_debug('[*] === END STIX BUNDLE ===')

                    # Send to OpenCTI
                    self.helper.log_debug("[*] Sending STIX Bundle to OpenCTI ...")
                    self.helper.send_stix2_bundle(
                        bundle.serialize(),
                        work_id=work_id,
                        update=self.update_existing_data,
                    )

                    # Create case for the incident using OpenCTI API (if enabled)
                    if self.auto_create_cases:
                        self._create_opencti_case(incident, stix_objects, message)

                    processed_count += 1

                    # Track latest timestamp
                    msg_timestamp = message.get("_meta", {}).get("created_at")
                    if msg_timestamp and (
                        not latest_timestamp or msg_timestamp > latest_timestamp
                    ):
                        latest_timestamp = msg_timestamp

                except Exception as e:
                    canonical_id = message.get("_meta", {}).get(
                        "canonical_id", "unknown"
                    )
                    self.helper.log_error(
                        "[!] Failed to process message {}: {}".format(canonical_id, e)
                    )

            # Update state with latest timestamp
            if latest_timestamp:
                self._set_last_timestamp(latest_timestamp)

            # Mark work as completed
            message = "Processed {} messages".format(processed_count)
            self.helper.log_info(message)
            self.helper.api.work.to_processed(work_id, message)

        except Exception as e:
            self.helper.log_error("[!] Batch processing failed: {}".format(e))
            raise

    def run(self):
        """
        Main connector loop.
        """
        while True:
            try:
                # Check if it's time to run
                timestamp = int(time.time())
                current_state = self.helper.get_state()

                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    time_diff = timestamp - last_run

                    if time_diff < self.poll_interval:
                        next_run = self.poll_interval - time_diff
                        self.helper.log_info(
                            "[*] Next run in {} seconds".format(next_run)
                        )
                        time.sleep(next_run)
                        continue

                # Get last processed timestamp
                since_timestamp = self._get_last_timestamp()
                self.helper.log_debug(
                    "[DEBUG] Fetching messages since {}".format(since_timestamp)
                )

                # Fetch and process messages
                messages = self._fetch_messages(since_timestamp)
                self._process_messages(messages)

                # Update last run timestamp
                current_state = self.helper.get_state() or {}
                current_state["last_run"] = timestamp
                self.helper.set_state(current_state)

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("[*] Connector stopping...")
                break
            except Exception as e:
                self.helper.log_error("[!] Connector error: {}".format(e))

                if self.helper.connect_run_and_terminate:
                    break

                # Error occurred. Wait 10 mins before retrying
                time.sleep(10 * 60)

        self.helper.log_info("[*] Connector stopped")


if __name__ == "__main__":
    try:
        connector = SublimeConnector()
        connector.run()
    except Exception as e:
        print("Error: {}".format(e))
        traceback.print_exc()
        sys.exit(1)
