import json
from datetime import datetime, timezone
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, field_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = Field(default="Email Cases Importer")


class SubjectFilter:
    def __init__(self, filter_type: str, value: str):
        self.filter_type = filter_type
        self.value = value


class EmailCasesConfig(BaseConfigModel):
    # Protocol selection
    protocol: Literal["imap", "microsoft_graph", "gmail", "ews"] = Field(
        default="imap",
        description="Email protocol to use.",
    )

    # IMAP settings
    imap_host: str = Field(default="", description="IMAP server hostname.")
    imap_port: int = Field(default=993, description="IMAP server port.")
    imap_username: str = Field(default="", description="IMAP username.")
    imap_password: str = Field(default="", description="IMAP password.")
    imap_folder: str = Field(default="INBOX", description="IMAP folder to monitor.")
    imap_use_ssl: bool = Field(default=True, description="Use SSL/TLS for IMAP.")

    # Microsoft Graph settings
    graph_tenant_id: str = Field(default="", description="Azure AD tenant ID.")
    graph_client_id: str = Field(default="", description="Azure AD client ID.")
    graph_client_secret: str = Field(default="", description="Azure AD client secret.")
    graph_user_id: str = Field(default="", description="Mailbox user ID or UPN.")

    # Gmail settings
    gmail_credentials_file: str = Field(
        default="", description="Path to Google service account credentials JSON."
    )
    gmail_user_id: str = Field(
        default="me", description="Gmail user ID (default: 'me')."
    )

    # EWS settings
    ews_server: str = Field(default="", description="Exchange server URL.")
    ews_username: str = Field(default="", description="Exchange username.")
    ews_password: str = Field(default="", description="Exchange password.")
    ews_auth_type: Literal["NTLM", "OAuth2"] = Field(
        default="NTLM", description="EWS auth type."
    )

    # Email filtering
    sender_address: str = Field(description="Sender email address to monitor.")
    subject_filters: str = Field(
        description=(
            'JSON array of subject filters. An empty array ("[]") means "accept '
            'any subject" (no subject-level filtering). '
            'Example: [{"type":"exact","value":"Security Alert"},'
            '{"type":"regex","value":"INC-\\\\d+"}]'
        ),
    )

    # Thread tracking
    thread_tracking_strategy: Literal[
        "provider_thread_id", "message_headers", "subject_matching"
    ] = Field(
        default="provider_thread_id",
        description="Thread tracking strategy.",
    )

    # First-run starting date
    start_date: str = Field(
        default="",
        description=(
            "Optional ISO 8601 starting date used ONLY on the first fetch cycle "
            "(when no prior state exists). Later cycles resume from the last run "
            "timestamp stored in state. Formats accepted: 'YYYY-MM-DD' or "
            "'YYYY-MM-DDTHH:MM:SSZ'. Example: '2026-04-01'. Leave empty to let "
            "the email server return the most recent N emails on first run."
        ),
    )

    @field_validator("start_date")
    @classmethod
    def validate_start_date(cls, v: str) -> str:
        if not v:
            return v
        try:
            if len(v) == 10:
                datetime.strptime(v, "%Y-%m-%d")
            else:
                datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(
                f"start_date must be ISO-8601 or YYYY-MM-DD: {exc}"
            ) from exc
        return v

    def get_parsed_start_date(self) -> datetime | None:
        if not self.start_date:
            return None
        if len(self.start_date) == 10:
            return datetime.strptime(self.start_date, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
        return datetime.fromisoformat(self.start_date.replace("Z", "+00:00"))

    # Password extraction
    password_prefix: str = Field(
        default="---BEGIN PASSWORD---",
        description="Prefix marker for password in email body.",
    )
    password_suffix: str = Field(
        default="---END PASSWORD---",
        description="Suffix marker for password in email body.",
    )
    password_strip_whitespace: bool = Field(
        default=False,
        description=(
            "Strip all spaces, tabs, and newlines from extracted passwords. "
            "Useful when HTML rendering or email line wrapping inserts whitespace "
            "within the password between the prefix and suffix markers."
        ),
    )

    # Display
    display_sender_names: bool = Field(
        default=True,
        description=(
            "Show sender and recipient display names in case content "
            "(e.g. 'NCSC UK <contact@ncsc.gov.uk>' instead of just 'contact@ncsc.gov.uk')."
        ),
    )

    # Timeouts
    email_fetch_timeout: int = Field(
        default=120,
        description=(
            "Timeout in seconds for a single email fetch cycle. "
            "Prevents the connector from hanging on unresponsive mail servers."
        ),
    )

    # Case defaults
    default_severity: str = Field(
        default="medium", description="Default severity for created cases."
    )
    default_priority: str = Field(
        default="P3", description="Default priority for created cases."
    )
    case_prefix: str = Field(default="", description="Optional prefix for case names.")

    # Labels and subject rules
    labels: str = Field(
        default="",
        description="Comma-separated labels always added to cases (e.g. 'NCSC UK,Email Alert').",
    )
    subject_rules: str = Field(
        default="[]",
        description=(
            "JSON array of subject-based rules. Each rule can add labels, set "
            "response_types, severity, priority, and apply a case_template. Example: "
            '[{"match_type":"contains","value":"Threat Alert",'
            '"labels":["Threat Alert"],"response_types":["ransomware"],'
            '"severity":"critical","priority":"P1",'
            '"case_template":"My Template"}]'
        ),
    )
    sender_rules: str = Field(
        default="[]",
        description=(
            "JSON array of sender-based rules. Each rule matches on sender email "
            "and can set author, marking, assignees, and participants. Example: "
            '[{"sender":"alerts@ncsc.gov.uk","author":"NCSC UK",'
            '"marking":"TLP:AMBER","assignees":["analyst@company.com"],'
            '"participants":["soc-team@company.com"]}]'
        ),
    )

    @field_validator("subject_rules")
    @classmethod
    def validate_subject_rules(cls, v: str) -> str:
        try:
            rules = json.loads(v)
            if not isinstance(rules, list):
                raise ValueError("subject_rules must be a JSON array")
            for r in rules:
                if not isinstance(r, dict):
                    raise ValueError("Each rule must be a JSON object")
                if "match_type" not in r or "value" not in r:
                    raise ValueError("Each rule must have 'match_type' and 'value'")
                if r["match_type"] not in ("exact", "contains", "starts_with", "regex"):
                    raise ValueError(
                        f"match_type must be exact, contains, starts_with, or regex, got: {r['match_type']}"
                    )
        except json.JSONDecodeError as exc:
            raise ValueError(f"subject_rules must be valid JSON: {exc}") from exc
        return v

    def get_parsed_labels(self) -> list[str]:
        if not self.labels:
            return []
        return [label.strip() for label in self.labels.split(",") if label.strip()]

    def get_parsed_subject_rules(self) -> list[dict]:
        return json.loads(self.subject_rules)

    @field_validator("sender_rules")
    @classmethod
    def validate_sender_rules(cls, v: str) -> str:
        try:
            rules = json.loads(v)
            if not isinstance(rules, list):
                raise ValueError("sender_rules must be a JSON array")
            for r in rules:
                if not isinstance(r, dict):
                    raise ValueError("Each rule must be a JSON object")
                if "sender" not in r:
                    raise ValueError("Each sender rule must have 'sender'")
        except json.JSONDecodeError as exc:
            raise ValueError(f"sender_rules must be valid JSON: {exc}") from exc
        return v

    def get_parsed_sender_rules(self) -> list[dict]:
        return json.loads(self.sender_rules)

    # Import settings
    import_interval: int = Field(
        default=300,
        description=(
            "DEPRECATED — use CONNECTOR_DURATION_PERIOD (ISO-8601, e.g. PT5M), "
            "the standard connectors-sdk polling field. Seconds between email "
            "polling cycles; retained only as a fallback for existing "
            "deployments and ignored when a valid CONNECTOR_DURATION_PERIOD is "
            "set."
        ),
    )
    max_emails_per_cycle: int = Field(
        default=50, description="Maximum emails to process per import cycle."
    )
    tls_verify: bool = Field(default=True, description="Verify TLS certificates.")

    # Attachment handling
    max_attachment_size_mb: int = Field(
        default=25, description="Maximum attachment size in MB."
    )
    attachment_store_in_opencti: bool = Field(
        default=True, description="Upload attachments as Artifacts to OpenCTI."
    )

    @field_validator("subject_filters")
    @classmethod
    def validate_subject_filters(cls, v: str) -> str:
        try:
            filters = json.loads(v)
            if not isinstance(filters, list):
                raise ValueError("subject_filters must be a JSON array")
            for f in filters:
                if not isinstance(f, dict):
                    raise ValueError("Each filter must be a JSON object")
                if "type" not in f or "value" not in f:
                    raise ValueError("Each filter must have 'type' and 'value'")
                if f["type"] not in ("exact", "contains", "regex"):
                    raise ValueError(
                        f"Filter type must be exact, contains, or regex, got: {f['type']}"
                    )
        except json.JSONDecodeError as exc:
            raise ValueError(f"subject_filters must be valid JSON: {exc}") from exc
        return v

    def get_parsed_subject_filters(self) -> list[dict]:
        return json.loads(self.subject_filters)


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    email_cases: EmailCasesConfig = Field(default_factory=EmailCasesConfig)
