from datetime import timedelta
from typing import Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from pydantic import Field, Json, field_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Provide defaults for the standard EXTERNAL_IMPORT connector fields so the
    connector runs without requiring every ``CONNECTOR_*`` variable to be set."""

    id: str = Field(
        default="6f2b1c6a-1f7e-4a4f-9d54-4b9f9ab27a41",
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        default="Email Cases Importer",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=["email-cases-importer"],
        description="The scope of the connector.",
    )
    duration_period: timedelta = Field(
        default=timedelta(minutes=5),
        description="The period of time to await between two runs of the connector.",
    )


class EmailCasesConfig(BaseConfigModel):
    # Protocol selection
    protocol: Literal["imap", "microsoft_graph", "gmail", "ews"] = Field(
        default="imap",
        description="Email protocol to use.",
    )

    # IMAP settings
    imap_host: str | None = Field(default=None, description="IMAP server hostname.")
    imap_port: int = Field(default=993, description="IMAP server port.")
    imap_username: str | None = Field(default=None, description="IMAP username.")
    imap_password: str | None = Field(default=None, description="IMAP password.")
    imap_folder: str = Field(default="INBOX", description="IMAP folder to monitor.")
    imap_use_ssl: bool = Field(default=True, description="Use SSL/TLS for IMAP.")

    # Microsoft Graph settings
    graph_tenant_id: str | None = Field(default=None, description="Azure AD tenant ID.")
    graph_client_id: str | None = Field(default=None, description="Azure AD client ID.")
    graph_client_secret: str | None = Field(
        default=None, description="Azure AD client secret."
    )
    graph_user_id: str | None = Field(
        default=None, description="Mailbox user ID or UPN."
    )

    # Gmail settings
    gmail_credentials_file: str | None = Field(
        default=None, description="Path to Google service account credentials JSON."
    )
    gmail_user_id: str = Field(
        default="me", description="Gmail user ID (default: 'me')."
    )

    # EWS settings
    ews_server: str | None = Field(
        default=None,
        description="Exchange server URL. Leave empty to use Autodiscover.",
    )
    ews_username: str | None = Field(default=None, description="Exchange username.")
    ews_password: str | None = Field(default=None, description="Exchange password.")
    ews_auth_type: Literal["NTLM", "OAuth2"] = Field(
        default="NTLM", description="EWS auth type."
    )

    # Email filtering
    sender_address: str = Field(description="Sender email address to monitor.")
    subject_filters: Json[list[dict[str, str]]] = Field(
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
    start_date: DatetimeFromIsoString | None = Field(
        default=None,
        description=(
            "Optional ISO 8601 starting date used ONLY on the first fetch cycle "
            "(when no prior state exists). Later cycles resume from the last run "
            "timestamp stored in state. Formats accepted: 'YYYY-MM-DD' or "
            "'YYYY-MM-DDTHH:MM:SSZ'. Example: '2026-04-01'. Leave empty to let "
            "the email server return the most recent N emails on first run."
        ),
    )

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
    default_severity: Literal["low", "medium", "high", "critical"] = Field(
        default="medium", description="Default severity for created cases."
    )
    default_priority: Literal["P1", "P2", "P3", "P4"] = Field(
        default="P3", description="Default priority for created cases."
    )
    case_prefix: str | None = Field(
        default=None, description="Optional prefix for case names."
    )

    # Labels and subject rules
    labels: ListFromString = Field(
        default=[],
        description="Comma-separated labels always added to cases (e.g. 'NCSC UK,Email Alert').",
    )
    subject_rules: Json[list[dict[str, Any]]] = Field(
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
    sender_rules: Json[list[dict[str, Any]]] = Field(
        default="[]",
        description=(
            "JSON array of sender-based rules. Each rule matches on sender email "
            "and can set author, marking, assignees, and participants. Example: "
            '[{"sender":"alerts@ncsc.gov.uk","author":"NCSC UK",'
            '"marking":"TLP:AMBER","assignees":["analyst@company.com"],'
            '"participants":["soc-team@company.com"]}]'
        ),
    )

    # Import settings
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
    def validate_subject_filters(
        cls, filters: list[dict[str, str]]
    ) -> list[dict[str, str]]:
        for f in filters:
            if "type" not in f or "value" not in f:
                raise ValueError("Each subject filter must have 'type' and 'value'")
            if f["type"] not in ("exact", "contains", "regex"):
                raise ValueError(
                    f"Filter type must be exact, contains, or regex, got: {f['type']}"
                )
        return filters

    @field_validator("subject_rules")
    @classmethod
    def validate_subject_rules(
        cls, rules: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        for r in rules:
            if "match_type" not in r or "value" not in r:
                raise ValueError("Each rule must have 'match_type' and 'value'")
            if r["match_type"] not in ("exact", "contains", "starts_with", "regex"):
                raise ValueError(
                    "match_type must be exact, contains, starts_with, or regex, "
                    f"got: {r['match_type']}"
                )
        return rules

    @field_validator("sender_rules")
    @classmethod
    def validate_sender_rules(cls, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for r in rules:
            if "sender" not in r:
                raise ValueError("Each sender rule must have 'sender'")
        return rules


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    email_cases: EmailCasesConfig = Field(default_factory=EmailCasesConfig)
