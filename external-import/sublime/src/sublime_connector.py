"""
Sublime Security OpenCTI Connector
Simplified implementation following OpenCTI connector patterns
"""

import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import isodate
import requests
import stix2
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class SublimeConnector:
    """
    Sublime external import connector for OpenCTI
    """

    def __init__(self):
        """
        Initialize the Sublime OpenCTI connector.

        Configuration Sources (in priority order):
        1. Environment variables
        2. config.yml file (if exists)
        3. Default values
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
                self.helper.log_info(
                    "[*] Loaded configuration from {}".format(config_file_path)
                )
            except Exception as e:
                self.helper.log_warning(
                    "[*] Failed to load config.yml: {}. Default values may be used.".format(
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
                    "PT3M",
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

        self.first_run_duration = get_config_variable(
            "SUBLIME_FIRST_RUN_DURATION",
            ["sublime", "first_run_duration"],
            config_dict,
            False,
            "PT8H",
        )
        self.force_historical = get_config_variable(
            "SUBLIME_FORCE_HISTORICAL",
            ["sublime", "force_historical"],
            config_dict,
            False,
            False,
        )

        # Case priority and severity configuration
        self.set_priority = get_config_variable(
            "SUBLIME_SET_PRIORITY",
            ["sublime", "set_priority"],
            config_dict,
            False,
            True,
        )
        self.set_severity = get_config_variable(
            "SUBLIME_SET_SEVERITY",
            ["sublime", "set_severity"],
            config_dict,
            False,
            True,
        )

        # Batch processing configuration
        self.batch_size = int(
            get_config_variable(
                "SUBLIME_BATCH_SIZE",
                ["sublime", "batch_size"],
                config_dict,
                True,
                100,
            )
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

        # Value for if to update an existing bundle.
        # Currently set to False as placeholder for potental future logic
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
            id=self._make_deterministic_id("identity", "sublime-security-organization"),
            name="Sublime",
            identity_class="organization",
            description="Email Security Platform",
            custom_properties={"x_opencti_type": "Organization"},
            allow_custom=True,
        )

        self.helper.log_info("[*] Sublime connector initialized")
        self.helper.log_info(
            "[*] Configuration: verdicts={}, confidence={}, incident_type={}, duration_period={}, first_run_duration={}, force_historical={}, incident_prefix='{}', case_prefix='{}', auto_create_cases={}, set_priority={}, set_severity={}, batch_size={}, platform_url={}".format(
                self.verdicts,
                self.confidence_level,
                self.incident_type,
                duration_period,
                self.first_run_duration,
                self.force_historical,
                self.incident_name_prefix,
                self.case_name_prefix,
                self.auto_create_cases,
                self.set_priority,
                self.set_severity,
                self.batch_size,
                self.api_base_url,
            )
        )

    def _make_deterministic_id(self, stix_type, unique_value):
        """Generate deterministic UUIDs for STIX values"""
        safe_stix_type = str(stix_type or "unknown")
        safe_unique_value = str(unique_value or "unknown")

        namespace = uuid.uuid5(uuid.NAMESPACE_DNS, "sublime-security-opencti")
        deterministic_uuid = uuid.uuid5(
            namespace, "{}:{}".format(safe_stix_type, safe_unique_value)
        )
        return "{}--{}".format(safe_stix_type, deterministic_uuid)

    def _get_last_timestamp(self):
        """
        Get the last processed timestamp from OpenCTI connector state.

        On first run (no existing state), fetches data from first_run_duration ago.
        Subsequent runs are delta-based from the last processed timestamp.

        If force_historical is enabled, ignores existing state once and then disables itself.

        Returns:
            str: ISO 8601 timestamp string of last processed message,
                 or calculated based on first_run_duration if no previous state exists or force_historical is enabled
        """
        current_state = self.helper.get_state() or {}

        # Check for force historical ingest flag
        # A bit of logic here as OpenCTI will store these flags. This can prevent future historical
        # So we clear the flag if it's enabled in config
        if self.force_historical:
            self.helper.log_info(
                "[*] Force historical mode enabled - clearing previous state"
            )
            current_state.pop("force_historical_used", None)
            current_state.pop("last_timestamp", None)
            current_state["force_historical_used"] = True
            self.helper.set_state(current_state)
        elif current_state and "last_timestamp" in current_state:
            return current_state["last_timestamp"]

        # First run or forced historical: use configured duration for initial data fetch
        try:
            duration_obj = isodate.parse_duration(self.first_run_duration)
            default_time = datetime.now(timezone.utc) - duration_obj

            if self.force_historical:
                mode = "Forced historical"
            else:
                mode = "First run"

            self.helper.log_info(
                "[*] {}: fetching {} of historical data".format(
                    mode, self.first_run_duration
                )
            )
        except (isodate.ISO8601Error, ValueError) as e:
            self.helper.log_warning(
                '[!] Invalid first run duration format "{}": {}. Using default 14 days'.format(
                    self.first_run_duration, e
                )
            )
            # Fallback to 14 days
            default_time = datetime.now(timezone.utc) - timedelta(days=14)

        # Format for Sublime API: 2025-06-07T05:00:00.000Z
        return default_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _sanitize_email(self, email):
        """
        Sanitize email address by removing Unicode BOM and other problematic characters.

        Args:
            email (str): Raw email address

        Returns:
            str: Sanitized email address
        """
        if not email:
            return email

        # Remove Unicode BOM (Byte Order Mark) characters
        sanitized = (
            email.replace("\ufeff", "")
            .replace("\ufffe", "")
            .replace("\u00ef\u00bb\u00bf", "")
        )

        # Strip leading/trailing whitespace
        sanitized = sanitized.strip()

        return sanitized

    def _map_attack_score_to_level(self, attack_score_verdict, mapping_type):
        """
        Map Sublime attack score verdict to OpenCTI priority or severity level.

        Attack score verdicts: benign, unknown, graymail, suspicious, malicious, spam

        Args:
            attack_score_verdict (str): Sublime attack score verdict
            mapping_type (str): Either 'priority' or 'severity'

        Returns:
            str: Mapped level (low, medium, high, critical) or None if not configured
        """
        if mapping_type == "priority" and not self.set_priority:
            return None
        if mapping_type == "severity" and not self.set_severity:
            return None

        # Verdict to level mapping - OpenCTI expects different values for priority vs severity
        if mapping_type == "priority":
            # Priority uses P1/P2/P3/P4 format (P1 = highest priority)
            verdict_mapping = {
                "malicious": "P1",  # Highest priority
                "suspicious": "P2",  # High priority
                "spam": "P3",  # Medium priority
                "graymail": "P3",  # Medium priority
                "unknown": "P4",  # Low priority
                "benign": "P4",  # Low priority
            }
        else:
            # Severity mapping - confirmed to work with: critical, high, medium, low
            verdict_mapping = {
                "malicious": "high",
                "suspicious": "medium",
                "spam": "low",
                "graymail": "low",
                "unknown": "low",
                "benign": "low",
            }

        verdict = (attack_score_verdict or "unknown").lower()
        default_value = "P4" if mapping_type == "priority" else "low"
        return verdict_mapping.get(verdict, default_value)

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

        self.helper.log_info(
            "[*] Fetch Time range: {} to {}".format(start_time, end_time)
        )
        self.helper.log_debug(
            "API request: {} with {} parameters".format(full_url, len(params))
        )
        response = self.session.get(full_url, params=params, timeout=30)

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
        if not group_ids:
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

        self.helper.log_debug("Fetching group: {}".format(group_id))

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

        Uses a two-step process with batch processing:
        1. Fetch list of flagged group IDs within time range
        2. Process groups in batches to prevent memory exhaustion
        3. Yield batches of message groups for incremental processing

        Args:
            since_timestamp (str): ISO 8601 timestamp to fetch messages since

        Yields:
            list: Batches of message group dictionaries with 'malicious' verdict

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
            group_ids = self._fetch_group_ids(start_time, end_time)
            if not group_ids:
                self.helper.log_debug("No flagged message groups found in time range")
                return

            self.helper.log_info(
                "[*] Found {} flagged group IDs. Processing in batches of {}".format(
                    len(group_ids), self.batch_size
                )
            )

            total_fetched = 0
            for i in range(0, len(group_ids), self.batch_size):
                batch_ids = group_ids[i : i + self.batch_size]
                batch_messages = []

                self.helper.log_info(
                    "[*] Processing batch {}/{}: groups {} to {} ({} total)".format(
                        (i // self.batch_size) + 1,
                        (len(group_ids) + self.batch_size - 1) // self.batch_size,
                        i + 1,
                        min(i + self.batch_size, len(group_ids)),
                        len(batch_ids),
                    )
                )

                for group_id in batch_ids:
                    message_group = self._fetch_single_group(group_id)
                    if message_group:
                        attack_score_raw = message_group.get("attack_score_verdict")
                        if not attack_score_raw:
                            continue

                        attack_score = attack_score_raw.lower()
                        if attack_score in self.verdicts:
                            batch_messages.append(message_group)
                        else:
                            self.helper.log_debug(
                                "Skipping group {} with verdict '{}' (not in {})".format(
                                    group_id, attack_score, self.verdicts
                                )
                            )

                if batch_messages:
                    total_fetched += len(batch_messages)
                    self.helper.log_info(
                        "[*] Batch yielding {} messages (verdicts: {})".format(
                            len(batch_messages), self.verdicts
                        )
                    )
                    yield batch_messages

            self.helper.log_info(
                "[*] Completed fetching {} total message groups from {} flagged groups".format(
                    total_fetched, len(group_ids)
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

        # Create detailed email from MDM
        primary_email, observables, additional_emails = self._create_primary_email(
            message_group
        )
        if primary_email:
            objects.append(primary_email)
        objects.extend(observables)
        objects.extend(additional_emails)  # Add any additional EmailMessage objects

        # Create basic emails from previews of other emails in group
        preview_emails = self._create_preview_emails(previews, group_id)
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
                self.helper.log_warning(
                    "[!] Failed to create indicator for {}: {}".format(
                        observable._type, e
                    )
                )
                self.helper.log_warning(
                    "[!] Problematic {} value: {}".format(observable._type, obs_value)
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
        data_model = message_group.get("data_model", {})
        if not data_model:
            return None, [], []

        observables = []

        sender_email = self._lookup_MDM_value(data_model, "sender.email.email")
        sender = None
        if sender_email:
            sender_email = self._sanitize_email(sender_email)
            sender = stix2.EmailAddress(
                id=self._make_deterministic_id("email-addr", sender_email),
                value=sender_email,
            )
        recipients = self._extract_recipients(data_model)
        if sender:
            observables.append(sender)
        observables.extend(recipients)

        observables.extend(self._extract_urls(data_model))
        observables.extend(self._extract_domains(data_model))
        observables.extend(self._extract_ips(data_model))

        # Build email message (STIX2: is_multipart requires body)
        body_text = self._lookup_MDM_value(data_model, "body.plain.raw")

        # raw text makes things easier, but option is here for HTML
        # html_content = self._lookup_MDM_value(data_model, 'body.html.raw')

        # Edge case. Sometimes the raw body doesn't exist. In that case, use HTML
        # e.g. html.raw = <span style="display: none"></p></html>
        if not body_text:
            html_text = self._lookup_MDM_value(data_model, "body.html.raw")
            body_text = html_text

        # Get actual subject from message group
        subjects = message_group.get("subjects", [])
        subject = subjects[0] if subjects else "Email processed by Sublime"

        if not subject or subject.strip() == "":
            subject = "Email processed by Sublime"

        group_id = message_group.get("id", "unknown")
        email_data = {
            "id": self._make_deterministic_id(
                "email-message", "{}:primary".format(group_id)
            ),
            "subject": subject,
            "is_multipart": False,
            "body": body_text or "Email content processed by Sublime",
        }

        if sender:
            email_data["from_ref"] = sender.id

        if recipients:
            email_data["to_refs"] = [recipient.id for recipient in recipients]

        email = stix2.EmailMessage(**email_data)
        return email, observables, []  # No additional emails in single email case

    def _create_preview_emails(self, previews, group_id):
        """
        Creates simplified EmailMessage objects

        Args:
            previews (list): List of preview email dictionaries
            group_id (str): Group ID for deterministic ID generation

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
                sender_email = self._sanitize_email(preview["sender_email_address"])
                sender = stix2.EmailAddress(
                    id=self._make_deterministic_id("email-addr", sender_email),
                    value=sender_email,
                )
                all_objects.append(sender)

            # Create recipient email addresses
            for recipient_addr in preview.get("recipients") or []:
                if recipient_addr:
                    recipient_addr = self._sanitize_email(recipient_addr)
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

            # Simplified EmailMessage - minimal fields only
            email_data = {
                "id": self._make_deterministic_id(
                    "email-message", "{}:preview:{}".format(group_id, i)
                ),
                "subject": str(preview.get("subject") or "Unknown Subject"),
                "is_multipart": False,
                "body": "Email preview processed by Sublime",
            }
            email = stix2.EmailMessage(**email_data)
            all_objects.append(email)

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

            # Collect unique recipients from both data_model and previews
            recipients = set()
            data_model = message_group.get("data_model", {})

            if data_model:
                to_list = self._lookup_MDM_value(data_model, "recipients.to") or []
                for recipient in to_list:
                    email = self._lookup_MDM_value(recipient, "email.email")
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
            self.helper.log_warning("[!] Failed to create description: {}".format(e))
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

        # Create Event Incident with deterministic ID
        incident = stix2.Incident(
            id=self._make_deterministic_id("incident", group_id),
            name=incident_name,
            description=incident_description,
            created_by_ref=self.sublime_identity.id,
            object_marking_refs=[stix2.TLP_AMBER],
            confidence=self.confidence_level,
            external_references=[
                {
                    "source_name": "Sublime",
                    "description": "View this message group in Sublime platform",
                    "url": "{}/messages/{}".format(
                        self.api_base_url, str(group_id or "unknown")
                    ),
                    "external_id": str(group_id or "unknown"),
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
            severity=self._map_attack_score_to_level(attack_score_verdict, "severity"),
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
            data_model = message_group.get("data_model", {})
            if data_model and self._lookup_MDM_value(data_model, "sender.email.email"):
                sender_email = self._sanitize_email(
                    self._lookup_MDM_value(data_model, "sender.email.email")
                )
            elif message_group.get("previews"):
                for preview in message_group.get("previews", []):
                    if not preview:
                        continue
                    if preview.get("sender_email_address"):
                        sender_email = self._sanitize_email(
                            preview.get("sender_email_address")
                        )
                        break

            preview_count = len(message_group.get("previews", []))
            has_primary = bool(
                data_model and self._lookup_MDM_value(data_model, "sender.email.email")
            )
            email_count = max(preview_count, 1) if has_primary else preview_count

            recipients = set()
            if data_model:
                to_list = self._lookup_MDM_value(data_model, "recipients.to") or []
                for recipient in to_list:
                    email = self._lookup_MDM_value(recipient, "email.email")
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
                    self.incident_name_prefix,
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
                    self.incident_name_prefix,
                    sender_email,
                    count_display,
                    email_plural,
                    recipient_count,
                    recipient_plural,
                    subject_abbreviated,
                )

            return incident_name

        except Exception as e:
            self.helper.log_warning(
                "[!] Failed to generate incident name: {}. Using fallback.".format(e)
            )
            # Fallback to simple incident naming
            return "{} {}".format(self.incident_name_prefix, subject)

    def _create_opencti_case(self, incident, stix_objects, message_group):
        """
        Create a Case using OpenCTI API for the incident.

        Args:
            incident (stix2.Incident): The main incident object
            stix_objects (list): All STIX objects created for this message group
            message_group (dict): Original message group data from Sublime API
        """
        group_id = message_group.get("id", "unknown")

        try:
            data_model = message_group.get("data_model", {})
            sender_email = (
                self._sanitize_email(
                    self._lookup_MDM_value(data_model, "sender.email.email")
                )
                if self._lookup_MDM_value(data_model, "sender.email.email")
                else self._sanitize_email(
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
            has_primary = bool(
                data_model and self._lookup_MDM_value(data_model, "sender.email.email")
            )
            email_count = max(preview_count, 1) if has_primary else preview_count

            recipients = set()
            if data_model:
                to_list = self._lookup_MDM_value(data_model, "recipients.to") or []
                for recipient in to_list:
                    email = self._lookup_MDM_value(recipient, "email.email")
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
                self.case_name_prefix,
                sender_email,
                email_count,
                email_plural,
                recipient_count,
                recipient_plural,
                subject_abbreviated,
            )
            object_ids = [incident.id] + [
                obj.id
                for obj in stix_objects
                if hasattr(obj, "id")
                and obj.id not in [self.sublime_identity.id, incident.id]
            ]

            # Convert STIX external references to dictionary format for OpenCTI API
            external_refs = [
                {
                    "source_name": ref.source_name,
                    "description": ref.description,
                    "url": ref.url,
                    "external_id": ref.external_id,
                }
                for ref in incident.external_references
            ]

            # Create case data without external references. They're added separately
            group_id = message_group.get("id", "unknown")
            case_description = self._create_description(message_group)

            case_data = {
                # Removed as OpenCTI ignores and creates its own id regardless
                # "id": deterministic_case_id,
                "name": case_name,
                "description": case_description,
                "objects": object_ids,
                "created_by": self.sublime_identity.id,
                "object_marking_refs": [stix2.TLP_AMBER.id],
            }

            # Add priority and severity if configured
            attack_score_verdict = message_group.get("attack_score_verdict")

            priority = self._map_attack_score_to_level(attack_score_verdict, "priority")
            severity = self._map_attack_score_to_level(attack_score_verdict, "severity")

            if priority:
                case_data["priority"] = priority

            if severity:
                case_data["severity"] = severity

            self.helper.log_info("[*] Creating new case for group: {}".format(group_id))
            case = self.helper.api.case_incident.create(**case_data)

            # Add external references after case creation (for all cases to ensure proper linking)
            if case and isinstance(case, dict) and case.get("id") and external_refs:
                try:
                    # Get existing external references to avoid duplicates
                    existing_ext_refs = case.get("externalReferences", [])
                    existing_ext_ids = {
                        ref.get("external_id") for ref in existing_ext_refs
                    }

                    for ext_ref in external_refs:
                        # Skip if external reference already exists on this case
                        if ext_ref["external_id"] in existing_ext_ids:
                            self.helper.log_info("*" * 100)
                            continue

                        ext_ref_result = self.helper.api.external_reference.create(
                            source_name=ext_ref["source_name"],
                            description=ext_ref["description"],
                            url=ext_ref["url"],
                            external_id=ext_ref["external_id"],
                        )

                        if (
                            ext_ref_result
                            and isinstance(ext_ref_result, dict)
                            and ext_ref_result.get("id")
                        ):
                            self.helper.api.stix_domain_object.add_external_reference(
                                id=case["id"],
                                external_reference_id=ext_ref_result["id"],
                            )
                except Exception as ext_ref_error:
                    self.helper.log_error(
                        "[!] Failed to add external references to case {}: {}".format(
                            case.get("id", "unknown"), ext_ref_error
                        )
                    )

            if case:
                self.helper.log_info(
                    "[*] Successfully processed case with ID: {}".format(
                        case.get("id", "unknown")
                    )
                )
            else:
                self.helper.log_error("[!] Case creation returned None")

        except Exception as e:
            self.helper.log_error(
                "[!] Failed to create case for incident {}: {}".format(incident.id, e)
            )

    def _create_indicator_for_observable(self, observable):
        """
        Create a single STIX indicator from a cyber observable using pycti utilities.

        Uses OpenCTIStix2Utils to generate proper STIX patterns and creates
        Indicator objects with malicious-activity labels.

        Args:
            observable (stix2.SDO): STIX cyber observable object

        Returns:
            stix2.Indicator: STIX Indicator object, or None if type not supported
        """
        from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils

        # Use pycti utility to create STIX pattern
        pattern = OpenCTIStix2Utils.create_stix_pattern(
            observable._type, observable.value
        )
        if not pattern:
            return None

        # Log pattern generation for troubleshooting if needed
        # self.helper.log_debug("Generated STIX pattern for {}: {}".format(observable._type, pattern))

        # Create indicator with proper metadata
        indicator = stix2.Indicator(
            id=self._make_deterministic_id("indicator", pattern),
            pattern=pattern,
            pattern_type="stix",
            labels=["malicious-activity"],
            created_by_ref=self.sublime_identity.id,
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties={
                "x_opencti_type": "Indicator",
            },
            allow_custom=True,
        )

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
            observables (list): List of cyber observable objects (excludes EmailMessage objects)
            indicators (list): List of indicator objects (unused in current implementation)

        Returns:
            list: List of STIX Relationship objects
        """
        relationships = []

        if primary_email and hasattr(primary_email, "id"):
            relationships.append(self._create_relationship(incident, primary_email))

        for observable in observables:
            if observable and hasattr(observable, "id"):
                relationships.append(self._create_relationship(incident, observable))

        for obj in all_emails:
            if (
                obj
                and hasattr(obj, "_type")
                and obj._type == "email-message"
                and hasattr(obj, "id")
            ):
                relationships.append(self._create_relationship(incident, obj))

        for indicator in indicators:
            if indicator and hasattr(indicator, "id"):
                relationships.append(self._create_relationship(incident, indicator))

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

    def _lookup_MDM_value(self, data, path):
        """
        Lookup values in MDM based on their rule structure
        This makes it easier to correlate values to MQL rules

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

    def _extract_recipients(self, data_model):
        """
        Extract recipient email addresses from message data model.

        Args:
            data_model (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.EmailAddress objects for recipients
        """
        recipients = []
        to_list = self._lookup_MDM_value(data_model, "recipients.to") or []
        for recipient in to_list:
            email = self._lookup_MDM_value(recipient, "email.email")
            if email:
                email = self._sanitize_email(email)
                recipients.append(
                    stix2.EmailAddress(
                        id=self._make_deterministic_id("email-addr", email), value=email
                    )
                )
        return recipients

    def _extract_urls(self, data_model):
        """
        Extract URLs from email body links.

        Args:
            data_model (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.URL objects
        """
        urls = []
        links = self._lookup_MDM_value(data_model, "body.links") or []
        for link in links:
            url = self._lookup_MDM_value(link, "href_url.url")
            if url:
                if "://" not in url:
                    scheme = self._lookup_MDM_value(link, "href_url.scheme") or "http"
                    url = "{}://{}".format(scheme, url)
                urls.append(
                    stix2.URL(id=self._make_deterministic_id("url", url), value=url)
                )
        return urls

    def _extract_domains(self, data_model):
        """
        Extract domains from email headers. Deduplicates based on lowercase domain names.

        Args:
            data_model (dict): Message data model from Sublime API

        Returns:
            list: List of stix2.DomainName objects
        """
        domains = []
        seen = set()

        header_domains = self._lookup_MDM_value(data_model, "headers.domains") or []
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
        header_ips = self._lookup_MDM_value(data_model, "headers.ips") or []
        for ip_info in header_ips:
            ip = ip_info.get("ip")
            if ip:
                ip_class = stix2.IPv6Address if ":" in ip else stix2.IPv4Address
                ip_type = "ipv6-addr" if ":" in ip else "ipv4-addr"
                ips.append(
                    ip_class(id=self._make_deterministic_id(ip_type, ip), value=ip)
                )
        return ips

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
                    self.helper.log_warning(
                        "[!] Skipping group {} - failed basic validation".format(
                            group_id
                        )
                    )
                    continue

                # Check if this message group already exists in OpenCTI
                if group_id in self._existing_group_ids:
                    self.helper.log_debug(
                        "[DEBUG] Skipping existing group: {}".format(group_id)
                    )
                    continue

                # Check if event incident already exists for this group_id
                existing_incident = None
                try:
                    all_incidents = self.helper.api.incident.list()
                    self.helper.log_debug(
                        "[DEBUG] Checking {} total incidents for external reference match".format(
                            len(all_incidents) if all_incidents else 0
                        )
                    )

                    if all_incidents:
                        for incident_obj in all_incidents:
                            incident_ext_refs = incident_obj.get(
                                "externalReferences", []
                            )
                            for ext_ref in incident_ext_refs:
                                if ext_ref.get("external_id") == group_id:
                                    existing_incident = incident_obj
                                    self.helper.log_info(
                                        "[*] Found existing event incident by external_id: {} for group: {}".format(
                                            incident_obj.get("id"), group_id
                                        )
                                    )
                                    break
                            if existing_incident:
                                break

                        if existing_incident:
                            self.helper.log_debug(
                                "[DEBUG] Skipping group {} - event incident already exists: {}".format(
                                    group_id, existing_incident.get("id")
                                )
                            )
                            continue
                        else:
                            self.helper.log_debug(
                                "[DEBUG] No existing event incident found for group: {} (checked {} incidents)".format(
                                    group_id, len(all_incidents) if all_incidents else 0
                                )
                            )

                except Exception as incident_check_error:
                    self.helper.log_warning(
                        "[!] Event incident existence check failed: {}".format(
                            incident_check_error
                        )
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

                bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)

                # Send to OpenCTI
                self.helper.log_debug(
                    "[DEBUG] About to send STIX Bundle for incident: {}".format(
                        incident.id
                    )
                )
                try:
                    self.helper.send_stix2_bundle(
                        bundle.serialize(),
                        work_id=work_id,
                        update=self.update_existing_data,
                    )
                    self.helper.log_debug(
                        "[DEBUG] Bundle sent successfully for incident: {}".format(
                            incident.id
                        )
                    )
                except Exception as bundle_error:
                    self.helper.log_warning(
                        "[!] Failed to send STIX bundle for incident {}: {}".format(
                            incident.id, bundle_error
                        )
                    )

                # Create OpenCTI case if enabled
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
                canonical_id = message.get("_meta", {}).get("canonical_id", "unknown")
                self.helper.log_error(
                    "[!] Failed to process message {}: {}".format(canonical_id, e)
                )

        return processed_count, latest_timestamp

    def _get_existing_group_ids(self):
        """
        Get all existing Sublime group IDs from OpenCTI incidents and cases.

        Returns:
            set: Set of existing group IDs
        """
        existing_group_ids = set()

        try:
            # Get group IDs from incidents and cases using shared method
            incidents = self.helper.api.incident.list(first=1000)
            cases = self.helper.api.case_incident.list(first=1000)

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

            self.helper.log_info(
                "[*] Found {} existing Sublime group IDs in OpenCTI".format(
                    len(existing_group_ids)
                )
            )
            return existing_group_ids

        except Exception as e:
            self.helper.log_warning(
                "[!] Error fetching existing group IDs: {}".format(e)
            )
            return set()

    def _process_messages(self):
        """
        Process messages using batch processing with incremental state updates.

        Returns:
            int: Total number of messages processed
        """
        # Get last processed timestamp
        since_timestamp = self._get_last_timestamp()
        self.helper.log_debug("Fetching messages since {}".format(since_timestamp))

        # Initialize work tracking
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Sublime Import"
        )

        try:
            total_processed = 0
            global_latest_timestamp = None

            for batch_messages in self._fetch_messages(since_timestamp):
                if not batch_messages:
                    continue

                self.helper.log_info(
                    "[*] Processing batch of {} messages".format(len(batch_messages))
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
                    current_state = self.helper.get_state() or {}
                    current_state["last_timestamp"] = global_latest_timestamp
                    self.helper.set_state(current_state)
                    self.helper.log_info(
                        "[*] Batch complete: {} processed this batch, {} total processed, state updated to {}".format(
                            batch_processed, total_processed, global_latest_timestamp
                        )
                    )

            if not global_latest_timestamp:
                current_time = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z"
                )
                current_state = self.helper.get_state() or {}
                current_state["last_timestamp"] = current_time
                self.helper.set_state(current_state)
                self.helper.log_info(
                    "[*] No messages processed. Updated state to current time: {}".format(
                        current_time
                    )
                )

            completion_message = "Processed {} messages in batches".format(
                total_processed
            )
            self.helper.log_info("[*] {}".format(completion_message))
            self.helper.api.work.to_processed(work_id, completion_message)

            return total_processed

        except Exception as e:
            error_message = "Batch processing failed after {} messages: {}".format(
                total_processed, e
            )
            self.helper.log_error("[!] {}".format(error_message))
            self.helper.api.work.to_received(work_id, error_message)
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

                if current_state and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    time_diff = timestamp - last_run

                    if time_diff < self.poll_interval:
                        next_run = self.poll_interval - time_diff
                        self.helper.log_info(
                            "[*] Next run in {} seconds".format(next_run)
                        )
                        time.sleep(next_run)
                        continue

                # Process messages using batch processing
                self._process_messages()

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
    connector = SublimeConnector()
    connector.run()
