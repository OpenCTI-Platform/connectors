# Email Cases Importer Connector for OpenCTI

OpenCTI connector that polls email inboxes and creates **Incident Response Cases** from matching emails. Supports **IMAP**, **Microsoft Graph**, **Gmail**, and **EWS** protocols.

## Features

- **Multi-protocol support** — IMAP, Microsoft Graph (Office 365), Gmail API, Exchange Web Services
- **Subject filtering** — Exact match, substring, and regex filters to select which emails to process
- **Thread tracking** — Groups email thread replies into the same Case-Incident (provider thread ID, message headers, or subject matching)
- **Password extraction** — Extracts passwords from email bodies using configurable markers, then uses them to decrypt attachments
- **Attachment handling** — Decrypts encrypted 7z, zip, rar, xlsx, pdf; handles nested encryption (e.g. unprotected zip containing an encrypted xlsx)
- **Labels and subject rules** — Static labels on every case, plus conditional labels/response types/severity/priority/case templates based on subject matching
- **Sender rules** — Auto-set author, marking definition, assignees, and participants based on sender email
- **Auto-creation** — Missing labels, vocabulary values (severity, priority, response types), and author identities are auto-created in OpenCTI at startup
- **Extensible handlers** — Plugin-style registry for custom file type parsing
- **Case deduplication** — Finds existing cases by name after state resets to avoid duplicates
- **Unicode support** — Handles non-English email subjects, bodies, and attachment filenames (Arabic, Chinese, Japanese, etc.)
- **Localized prefixes** — Strips RE/FW/FWD and localized variants (AW, WG, TR, RV, etc.) for thread matching

## How It Works

1. **Poll** — Connector polls the email inbox at the configured interval
2. **Filter** — Emails are filtered by sender address and subject filters
3. **Group** — Replies are grouped by thread ID into the same Case-Incident
4. **Extract** — Passwords are extracted from email body using prefix/suffix markers
5. **Decrypt** — Attachments are decrypted using extracted passwords
6. **Create** — Case-Incident is created in OpenCTI with labels, response types, severity, priority, author, marking, assignees, and case template applied. Email content is written to the case's **Content** tab as formatted HTML. Both original (encrypted) and extracted (decrypted) attachments are uploaded as files on the case.

## Installation

### Docker (Recommended)

```bash
docker compose up -d
```

### Manual

```bash
pip install -r requirements.txt
cd src
python main.py
```

## Configuration

All settings can be provided via environment variables or a `config.yml` file. See [`config.yml.sample`](config.yml.sample) for a fully commented example.

---

### OpenCTI Connection

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | *required* | Yes | OpenCTI platform URL |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | *required* | Yes | OpenCTI API token |
| Connector ID | `connector.id` | `CONNECTOR_ID` | *required* | Yes | Unique connector ID (UUIDv4) |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Email Cases` | No | Display name |
| Connector scope | `connector.scope` | `CONNECTOR_SCOPE` | `Email Cases` | No | Connector scope |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `info` | No | Log level (`debug`, `info`, `warning`, `error`) |
| Duration period | `connector.duration_period` | `CONNECTOR_DURATION_PERIOD` | `PT5M` | No | Polling cadence (ISO-8601 duration). **This is the control for polling frequency.** |

---

### Protocol Selection

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| Protocol | `email_cases.protocol` | `EMAIL_CASES_PROTOCOL` | `imap` | No | `imap`, `microsoft_graph`, `gmail`, or `ews` |

---

### IMAP Settings

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| IMAP host | `email_cases.imap_host` | `EMAIL_CASES_IMAP_HOST` | *required* | Yes | IMAP server hostname |
| IMAP port | `email_cases.imap_port` | `EMAIL_CASES_IMAP_PORT` | `993` | No | IMAP server port |
| IMAP username | `email_cases.imap_username` | `EMAIL_CASES_IMAP_USERNAME` | *required* | Yes | IMAP username |
| IMAP password | `email_cases.imap_password` | `EMAIL_CASES_IMAP_PASSWORD` | *required* | Yes | IMAP password |
| IMAP folder | `email_cases.imap_folder` | `EMAIL_CASES_IMAP_FOLDER` | `INBOX` | No | IMAP folder to monitor |
| IMAP use SSL | `email_cases.imap_use_ssl` | `EMAIL_CASES_IMAP_USE_SSL` | `true` | No | Use SSL/TLS |

### Microsoft Graph Settings (Office 365)

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| Graph tenant ID | `email_cases.graph_tenant_id` | `EMAIL_CASES_GRAPH_TENANT_ID` | *required* | Yes | Azure AD tenant ID |
| Graph client ID | `email_cases.graph_client_id` | `EMAIL_CASES_GRAPH_CLIENT_ID` | *required* | Yes | Azure AD application (client) ID |
| Graph client secret | `email_cases.graph_client_secret` | `EMAIL_CASES_GRAPH_CLIENT_SECRET` | *required* | Yes | Azure AD client secret |
| Graph user ID | `email_cases.graph_user_id` | `EMAIL_CASES_GRAPH_USER_ID` | *required* | Yes | Mailbox user ID or UPN |

Requires the `Mail.Read` application permission in Azure AD.

### Gmail Settings

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| Gmail credentials file | `email_cases.gmail_credentials_file` | `EMAIL_CASES_GMAIL_CREDENTIALS_FILE` | *required* | Yes | Path to service account credentials JSON |
| Gmail user ID | `email_cases.gmail_user_id` | `EMAIL_CASES_GMAIL_USER_ID` | `me` | No | Gmail user ID |

Requires a Google service account with domain-wide delegation and the `https://www.googleapis.com/auth/gmail.readonly` scope.

### EWS Settings (On-Premise Exchange)

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| EWS server | `email_cases.ews_server` | `EMAIL_CASES_EWS_SERVER` | *required* | Yes | Exchange server URL |
| EWS username | `email_cases.ews_username` | `EMAIL_CASES_EWS_USERNAME` | *required* | Yes | Exchange username (`DOMAIN\user`) |
| EWS password | `email_cases.ews_password` | `EMAIL_CASES_EWS_PASSWORD` | *required* | Yes | Exchange password |
| EWS auth type | `email_cases.ews_auth_type` | `EMAIL_CASES_EWS_AUTH_TYPE` | `NTLM` | No | Auth type: `NTLM` or `OAuth2` |

---

### Email Filtering

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| Sender address | `email_cases.sender_address` | `EMAIL_CASES_SENDER_ADDRESS` | *required* | Yes | Only process emails from this sender |
| Subject filters | `email_cases.subject_filters` | `EMAIL_CASES_SUBJECT_FILTERS` | *required* | Yes | JSON array of subject filters (see below) |

An email is processed if its subject matches **any** filter. Supported filter types:

| Type | Description | Case-sensitive |
|------|-------------|---------------|
| `exact` | Subject must equal the value exactly | Yes |
| `contains` | Subject must contain the value | Yes |
| `regex` | Subject must match the regular expression | Per regex flags |

**Example:**
```json
[
  {"type": "exact",    "value": "Weekly Threat Report"},
  {"type": "contains", "value": "Security Alert"},
  {"type": "regex",    "value": "INC-\\d+"}
]
```

---

### Thread Tracking

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| Thread tracking strategy | `email_cases.thread_tracking_strategy` | `EMAIL_CASES_THREAD_TRACKING_STRATEGY` | `provider_thread_id` | No | How replies are grouped into the same case |

| Strategy | Description |
|----------|-------------|
| `provider_thread_id` | Uses the provider's native thread/conversation ID. Most reliable. Falls back to subject matching if unavailable. |
| `message_headers` | Uses `In-Reply-To` and `References` email headers. Works across all providers. |
| `subject_matching` | Strips `RE:` / `FW:` / `FWD:` prefixes (and localized variants like `AW:`, `WG:`, `TR:`, `RV:`) and matches on the base subject. Simplest but may incorrectly merge unrelated emails with similar subjects. |

---

### Password Extraction

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| Password prefix | `email_cases.password_prefix` | `EMAIL_CASES_PASSWORD_PREFIX` | `---BEGIN PASSWORD---` | No | Opening marker for the password in the email body |
| Password suffix | `email_cases.password_suffix` | `EMAIL_CASES_PASSWORD_SUFFIX` | `---END PASSWORD---` | No | Closing marker for the password in the email body |
| Password strip whitespace | `email_cases.password_strip_whitespace` | `EMAIL_CASES_PASSWORD_STRIP_WHITESPACE` | `false` | No | Strip all spaces, tabs, and newlines from extracted passwords |

The connector scans the email body for text between these markers and uses the extracted passwords to decrypt attachments. Multiple passwords can be embedded in a single email.

If `EMAIL_CASES_PASSWORD_STRIP_WHITESPACE` is `true`, all spaces, tabs, and newlines are removed from the extracted password. This is useful when HTML rendering or email line wrapping inserts whitespace within the password between the markers.

**Example email body:**
```
Please find the malware sample attached.

The password is: ---BEGIN PASSWORD---infected123---END PASSWORD---
```

---

### Case Defaults

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| Default severity | `email_cases.default_severity` | `EMAIL_CASES_DEFAULT_SEVERITY` | `medium` | No | Default case severity (e.g. `low`, `medium`, `high`, `critical`) |
| Default priority | `email_cases.default_priority` | `EMAIL_CASES_DEFAULT_PRIORITY` | `P3` | No | Default case priority (e.g. `P1`, `P2`, `P3`, `P4`) |
| Case prefix | `email_cases.case_prefix` | `EMAIL_CASES_CASE_PREFIX` | *empty* | No | Optional prefix prepended to case names (e.g. `[EMAIL] `) |

Severity and priority values that don't exist in OpenCTI are **auto-created** as vocabulary entries at connector startup.

---

### Labels

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| Labels | `email_cases.labels` | `EMAIL_CASES_LABELS` | *empty* | No | Comma-separated labels always added to every case |

Labels are **auto-created** in OpenCTI if they don't exist.

**Example:**
```
EMAIL_CASES_LABELS=NCSC UK,Email Alert,SOC Triage
```

---

### Subject Rules

| Variable | Description | Default |
|----------|-------------|---------|
| `EMAIL_CASES_SUBJECT_RULES` | JSON array of subject-based rules (see below) | `[]` |

Subject rules let you **conditionally** set case properties based on the email subject. Rules are evaluated on every new case creation. Multiple rules can match the same email — labels and response types are merged; the first matching `severity`, `priority`, and `case_template` win.

#### Rule structure

Each rule requires two fields:

| Field | Required | Description |
|-------|----------|-------------|
| `match_type` | Yes | How to match: `exact`, `contains`, `starts_with`, or `regex` |
| `value` | Yes | The string or regex pattern to match against |

And can optionally include:

| Field | Optional | Description |
|-------|----------|-------------|
| `labels` | Yes | List of label names to add to the case |
| `response_types` | Yes | List of incident response types (auto-created if missing) |
| `severity` | Yes | Override the default severity for this case (auto-created if missing) |
| `priority` | Yes | Override the default priority for this case (auto-created if missing) |
| `case_template` | Yes | Name of an existing OpenCTI case template to apply |

#### Match types

| Match type | Description | Case-sensitive |
|------------|-------------|---------------|
| `exact` | Subject must equal the value exactly | Yes |
| `contains` | Subject must contain the value | No |
| `starts_with` | Subject must start with the value | No |
| `regex` | Subject must match the regular expression | Per regex flags |

#### Examples

**Single rule — escalate ransomware alerts:**
```json
[
  {
    "match_type": "contains",
    "value": "Ransomware",
    "labels": ["Ransomware"],
    "response_types": ["ransomware"],
    "severity": "critical",
    "priority": "P1",
    "case_template": "Ransomware Playbook"
  }
]
```

**Multiple rules — different behavior per subject pattern:**
```json
[
  {
    "match_type": "contains",
    "value": "Threat Alert",
    "labels": ["Threat Alert"],
    "response_types": ["ransomware"],
    "severity": "high",
    "priority": "P1"
  },
  {
    "match_type": "starts_with",
    "value": "INC-",
    "labels": ["Incident"],
    "response_types": ["data-leak"],
    "case_template": "Incident Response Playbook"
  },
  {
    "match_type": "regex",
    "value": "CVE-\\d{4}-\\d+",
    "labels": ["Vulnerability", "CVE"],
    "severity": "high"
  },
  {
    "match_type": "exact",
    "value": "Weekly Threat Report",
    "labels": ["Weekly Report"],
    "severity": "low",
    "priority": "P4"
  }
]
```

**As an environment variable (Docker):**
```yaml
- EMAIL_CASES_SUBJECT_RULES=[{"match_type":"contains","value":"Threat Alert","labels":["Threat Alert"],"severity":"critical","priority":"P1"},{"match_type":"starts_with","value":"INC-","labels":["Incident"]}]
```

---

### Sender Rules

| Variable | Description | Default |
|----------|-------------|---------|
| `EMAIL_CASES_SENDER_RULES` | JSON array of sender-based rules (see below) | `[]` |

Sender rules let you set case properties based on who sent the email. Each rule matches on the sender email address (case-insensitive).

#### Rule structure

| Field | Required | Description |
|-------|----------|-------------|
| `sender` | Yes | The sender email address to match (case-insensitive) |
| `author` | No | Organization name to set as case author. **Auto-created** as an Organization identity if it doesn't exist. |
| `marking` | No | Marking definition to apply (e.g. `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`). Must already exist in OpenCTI — TLP markings are built-in. |
| `assignees` | No | List of OpenCTI user emails to assign to the case. Users must already exist in OpenCTI. |
| `participants` | No | List of OpenCTI user emails to add as participants. Users must already exist in OpenCTI. |

#### Example

```json
[
  {
    "sender": "alerts@ncsc.gov.uk",
    "author": "NCSC UK",
    "marking": "TLP:AMBER",
    "assignees": ["analyst@company.com"],
    "participants": ["soc-team@company.com", "manager@company.com"]
  },
  {
    "sender": "noreply@security-vendor.com",
    "author": "Security Vendor",
    "marking": "TLP:GREEN"
  }
]
```

**As an environment variable (Docker):**
```yaml
- EMAIL_CASES_SENDER_RULES=[{"sender":"alerts@ncsc.gov.uk","author":"NCSC UK","marking":"TLP:AMBER","assignees":["analyst@company.com"]}]
```

> **Note:** If an assignee or participant email is not found in OpenCTI, a warning is logged and the case is created without that user.

> **Note:** If a marking definition name doesn't match any existing marking in OpenCTI, a warning is logged and the case is created without the marking.

---

### Import Settings

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| Import interval (**deprecated**) | `email_cases.import_interval` | `EMAIL_CASES_IMPORT_INTERVAL` | `300` | No | **DEPRECATED** — ignored when `CONNECTOR_DURATION_PERIOD` is set; retained only for backward compatibility. |
| Max emails per cycle | `email_cases.max_emails_per_cycle` | `EMAIL_CASES_MAX_EMAILS_PER_CYCLE` | `50` | No | Max emails processed per cycle |
| TLS verify | `email_cases.tls_verify` | `EMAIL_CASES_TLS_VERIFY` | `true` | No | Verify TLS certificates |

#### Polling cadence

`CONNECTOR_DURATION_PERIOD` (config.yml key `connector.duration_period`) is **the** control for how
often the connector polls. It is the standard `connectors-sdk` scheduling field and accepts an
ISO-8601 duration (e.g. `PT5M` for five minutes, `PT1H` for one hour); the default is `PT5M`.

The legacy `EMAIL_CASES_IMPORT_INTERVAL` (seconds) is **DEPRECATED**: it is ignored when
`CONNECTOR_DURATION_PERIOD` is set and is retained only for backward compatibility. New
deployments should set the cadence exclusively through `CONNECTOR_DURATION_PERIOD`.

---

### Attachment Settings

| Parameter | config.yml key | Docker env var | Default | Mandatory | Description |
|-----------|----------------|----------------|---------|-----------|-------------|
| Max attachment size (MB) | `email_cases.max_attachment_size_mb` | `EMAIL_CASES_MAX_ATTACHMENT_SIZE_MB` | `25` | No | Max attachment size in MB (larger files are skipped) |
| Store attachments in OpenCTI | `email_cases.attachment_store_in_opencti` | `EMAIL_CASES_ATTACHMENT_STORE_IN_OPENCTI` | `true` | No | Upload attachments as files on the case |

---

## Auto-Creation Behavior

The connector automatically creates missing entities at startup and during processing:

| Entity | When created | How |
|--------|-------------|-----|
| **Labels** | On first use | Created via OpenCTI Label API |
| **Severity values** | At startup | Created as `case_severity_ov` vocabulary entries |
| **Priority values** | At startup | Created as `case_priority_ov` vocabulary entries |
| **Response type values** | At startup | Created as `incident_response_types_ov` vocabulary entries |
| **Author identity** | On first use | Created as Organization identity via OpenCTI Identity API |
| **Marking definitions** | Never | Must already exist in OpenCTI (TLP markings are built-in) |
| **Users (assignees/participants)** | Never | Must already exist as OpenCTI users |
| **Case templates** | Never | Must already exist in OpenCTI |

---

## Supported Attachment Types

| Format | Extension | Password Support | Library |
|--------|-----------|-----------------|---------|
| ZIP archive | `.zip` | Yes | `zipfile` (stdlib) |
| 7-Zip archive | `.7z` | Yes | `py7zr` |
| RAR archive | `.rar` | No (extract only) | `bsdtar` (libarchive-tools) |
| Excel spreadsheet | `.xlsx` | Yes | `msoffcrypto-tool` |
| PDF document | `.pdf` | Yes | `pikepdf` |
| CSV | `.csv` | No | `csv` (stdlib) |
| Text | `.txt` | No | stdlib |
| Email | `.eml` | No | `email` (stdlib) |
| Outlook message | `.msg` | No | — (uploaded as-is) |

### Attachment behavior

- **Original attachments** are always uploaded to the case as-is (including encrypted ones)
- **Extracted/decrypted content** is uploaded alongside the original when extraction succeeds
- For archives, each inner file is also uploaded individually
- If decryption fails (wrong password, corrupted file), the original is still uploaded and a warning is logged

### Nested encryption

The connector handles nested encryption scenarios:
- An unprotected archive (zip/7z/rar) containing encrypted inner files (xlsx/pdf)
- An encrypted archive containing further encrypted content
- Maximum nesting depth: 3 levels

### Error handling

Each attachment is processed independently — if one fails, the rest continue:
- Corrupted archives: logged and skipped, original file still uploaded
- Wrong passwords: all configured passwords are tried, failure logged at debug level
- Missing libraries (py7zr, pikepdf, msoffcrypto-tool): logged as warning, file passed through as-is
- Oversized files: skipped with metadata only
- File I/O errors: caught and logged with filename context

---

## Unicode and Non-English Support

The connector handles non-English content throughout:

- **Email subjects** — MIME encoded-word decoding (RFC 2047) correctly handles Arabic, Chinese, Japanese, Cyrillic, and other scripts
- **Email bodies** — UTF-8 and other charset encodings decoded properly; HTML entities decoded
- **Attachment filenames** — Non-ASCII filenames (e.g. `تقرير.xlsx`, `報告.pdf`) preserved through the processing pipeline
- **Subject normalization** — Strips localized reply/forward prefixes beyond English:
  - German: `AW:`, `WG:`
  - French: `TR:`
  - Spanish: `RV:`
  - Italian: `I:`, `R:`
  - Portuguese: `ENC:`, `RES:`
  - Norwegian/Swedish: `SV:`, `VS:`
  - Dutch: `Doorst:`
- **HTML content** — `html.escape()` preserves Unicode characters, only escaping HTML special characters
- **Labels and rules** — Unicode label names and rule values work correctly

---

## Extending with Custom Handlers

To add support for a custom file type, subclass `BaseAttachmentHandler`:

```python
from attachment_handler.base import BaseAttachmentHandler, ExtractedFile
from connector.utils import compute_file_hashes

class MyCustomHandler(BaseAttachmentHandler):
    def supported_extensions(self) -> list[str]:
        return [".custom"]

    def extract(self, file_path, passwords=None) -> list[ExtractedFile]:
        with open(file_path, "rb") as f:
            content = f.read()
        return [ExtractedFile(
            filename="parsed.txt",
            content=content,
            content_type="text/plain",
            hashes=compute_file_hashes(content),
        )]
```

Register it in `attachment_handler/registry.py`:
```python
self.register(MyCustomHandler())
```

---

## Case Content Format

Each email is rendered as an HTML block in the case's **Content** tab:

- Emails are visually separated by horizontal rules
- Metadata (date, sender, recipients) is shown at the top
- Email body is displayed in a blockquote
- Attachments are listed with filenames
- Replies and original emails are labeled accordingly
- If passwords were extracted, a note indicates how many were found

The case **Description** uses plain text (sender, subject, first received date).

---

## Behavior

### Persistence model — why the OpenCTI API, not STIX bundles

This connector writes to OpenCTI through the live pycti API (`case_incident.create`,
`stix_domain_object.add_file`, `update_field`) rather than emitting STIX 2.1 bundles via
`send_stix2_bundle`. This is a deliberate design decision required by the connector's behavior:

- Attachment files are uploaded to the case's **Files** tab — binary attachments have no STIX
  representation (a STIX Artifact SCO is a different, graph-level object).
- Email content is written to the case **Content** tab as HTML and **appended** on each thread
  reply — a read-modify-append that STIX bundles (which upsert, not append) cannot express.
- **Case templates**, **assignees**, and **participants** reference OpenCTI-internal objects
  (templates, platform users) that have no STIX equivalent.
- `send_stix2_bundle` is asynchronous (queued to the worker) and cannot return the case's internal
  ID needed for the immediately-following file uploads and content appends; a hybrid design would
  race.

Idempotency is preserved via deterministic STIX IDs (`pycti.CaseIncident.generate_id`,
`pycti.Identity.generate_id`), so re-runs upsert the same objects rather than creating duplicates.

### State management and deduplication

- **State management** — The connector persists its progress in the connector state: the
  `last_run` timestamp, the set of already-processed message IDs, and the thread→case map that
  links email threads to their Case-Incident. This lets each polling cycle resume where the last
  one left off and route thread replies to the correct existing case.
- **Deduplication** — If the connector state is reset (or lost), existing cases are found by name
  before creation, so a reset does not produce duplicate cases.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| IMAP connection refused | Check host, port, and SSL settings. Ensure firewall allows outbound on port 993 (or your configured port) |
| `OAuth2 token error` (Graph) | Verify `tenant_id`, `client_id`, `client_secret`. Ensure the `Mail.Read` application permission is granted and admin consent is given |
| Gmail auth failed | Verify service account credentials JSON path and that domain-wide delegation is enabled for the `gmail.readonly` scope |
| EWS autodiscover failed | Set `EMAIL_CASES_EWS_SERVER` explicitly to the full EWS endpoint URL |
| No emails matched | Check `EMAIL_CASES_SENDER_ADDRESS` (must match the `From` header exactly) and `EMAIL_CASES_SUBJECT_FILTERS` syntax |
| Password not extracted | Verify the prefix/suffix markers match the email body exactly (including whitespace). Check connector logs for extraction count |
| Attachment too large | Increase `EMAIL_CASES_MAX_ATTACHMENT_SIZE_MB` or check the file size |
| RAR extraction failed | Ensure `unrar`/`bsdtar` is installed in the Docker image (included by default). Check logs for "bsdtar not installed" warning |
| 7z extraction failed | Check logs for "py7zr not installed" warning. Ensure `py7zr` is in requirements.txt |
| xlsx/pdf decryption failed | Check logs for "All password attempts failed" warning. Verify password markers in email body |
| Duplicate cases after restart | The connector deduplicates by case name — existing cases are found and reused. If the `case_prefix` changed, duplicates may occur |
| Labels not appearing | Verify `EMAIL_CASES_LABELS` is a comma-separated string and `EMAIL_CASES_SUBJECT_RULES` is valid JSON. Check connector logs for label creation errors |
| Severity/priority not set | Values are auto-created at startup. Check logs for "Created vocabulary entry" or "Failed to create vocabulary entry" |
| Response type not set | Values are auto-created at startup. Check logs for vocabulary creation messages |
| Case template not applied | Verify the template name in `case_template` exactly matches the name in OpenCTI (Settings > Customization > Case templates) |
| Author not set | Check logs for "Creating Identity" or "Failed to resolve identity". The author is created as an Organization |
| Marking not applied | Marking definitions must already exist in OpenCTI. Check logs for "Marking definition not found". TLP markings (`TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`) are built-in |
| Assignee/participant not found | Users must exist in OpenCTI and be matched by email. Check logs for "User not found for assignee/participant" |
| Non-English subjects garbled | Check the email server's charset encoding. The connector uses RFC 2047 decoding and falls back to UTF-8 |

---

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` to emit per-email fetch traces — each fetched email is logged with
its subject, sender, date, and `thread_id` — which makes it easy to see exactly which emails were
picked up and how they were grouped into threads. All logs are emitted as structured records via
`helper.connector_logger`, so message text and key/value fields are logged separately (e.g.
`helper.connector_logger.info("msg", {"key": val})`) and can be filtered or parsed downstream.

---

## Requirements

- OpenCTI Platform >= 6.4 (tested with 7.260715.0)
- Docker (recommended) or Python 3.12+
