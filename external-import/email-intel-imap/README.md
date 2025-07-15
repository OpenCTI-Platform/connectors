# 📬 Email Intel IMAP Connector

The **Email Intel IMAP Connector** enables the ingestion of cyber threat intelligence reports received via email into
the OpenCTI platform using the IMAP protocol. This connector allows organizations to automate the collection of
intelligence shared through email by regularly polling a mailbox and transforming each message into an OpenCTI report.

---

## 📖 Table of Contents

- [📬 Email Intel IMAP Connector](#-email-intel-imap-connector)
  - [📖 Table of Contents](#-table-of-contents)
  - [🧩 Introduction](#-introduction)
  - [⚙️ Requirements](#️-requirements)
  - [🔧 Configuration](#-configuration)
    - [OpenCTI Configuration](#opencti-configuration)
    - [Base Connector Configuration](#base-connector-configuration)
    - [Email Intel IMAP Connector Configuration](#email-intel-imap-connector-configuration)
  - [🚀 Deployment](#-deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
    - [Dev tools](#dev-tools)
  - [📌 Usage](#-usage)
  - [⚙️ Connector Behavior](#️-connector-behavior)
  - [📝 Additional Information](#-additional-information)
  - [Development](#development)
    - [Adding a new email provider](#adding-a-new-email-provider)

---

## 🧩 Introduction

This connector is designed to connect to an IMAP-compatible email inbox, extract email content and attachments, and
convert the data into structured CTI reports within OpenCTI. The connector is suitable for any threat intel flow that
relies on email as a delivery method and is compatible with standard IMAP servers.

---

## ⚙️ Requirements

- OpenCTI Platform >= 6.x
- IMAP-compatible mailbox

---

## 🔧 Configuration

Configuration parameters can be either defined in a `config.yml`, `.env` or in environment variables.

### OpenCTI Configuration

| Parameter     | config.yml | Environment Variable | Required | Description                                          |
|---------------|------------|----------------------|----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`        | ✅        | The base URL of the OpenCTI platform.                |
| OpenCTI Token | token      | `OPENCTI_TOKEN`      | ✅        | The default admin token set in the OpenCTI platform. |

### Base Connector Configuration

| Parameter                 | config.yml      | Environment Variable        | Required | Default value    | Description                                               |
|---------------------------|-----------------|-----------------------------|----------|------------------|-----------------------------------------------------------|
| Connector ID              | id              | `CONNECTOR_ID`              | ✅        | ❌                | A unique `UUIDv4` identifier for this connector instance. |
| Connector Name            | name            | `CONNECTOR_NAME`            | ❌        | Email Intel IMAP | Name of the connector.                                    |
| Connector Scope           | scope           | `CONNECTOR_SCOPE`           | ❌        | email-intel-imap | The scope/type of objects the connector imports.          |
| Connector Log Level       | log_level       | `CONNECTOR_LOG_LEVEL`       | ❌        | error            | Logging level (`debug`, `info`, `warn`, `error`).         |
| Connector Duration Period | duration_period | `CONNECTOR_DURATION_PERIOD` | ❌        | PT1H             | Frequency of polling the mailbox (ISO 8601 format).       |

### Email Intel IMAP Connector Configuration

Below are the parameters you'll need to set for the Email Intel IMAP Connector

| Parameter                  | config.yml                              | Docker environment variable                   | Recommended value                   | Mandatory | Description                                   |
|----------------------------|-----------------------------------------|-----------------------------------------------|-------------------------------------|-----------|-----------------------------------------------|
| Relative Import Start Date | relative_import_start_date              | `EMAIL_INTEL_IMAP_RELATIVE_IMPORT_START_DATE` | P30D                                | ✅         | How far back the first import should go.      |
| IMAP Host                  | email_intel_imap.host                   | `EMAIL_INTEL_IMAP_HOST`                       | ❌                                   | ✅         | Hostname of the IMAP server.                  |
| IMAP Port                  | email_intel_imap.port                   | `EMAIL_INTEL_IMAP_PORT`                       | 993                                 | ✅         | IMAP port (993 typically for SSL).            |
| IMAP Username              | email_intel_imap.username               | `EMAIL_INTEL_IMAP_USERNAME`                   | ❌                                   | ✅         | Mailbox username.                             |
| IMAP Password              | email_intel_imap.password               | `EMAIL_INTEL_IMAP_PASSWORD`                   | ❌                                   | ❌         | Mailbox password.                             |
| Mailbox Folder             | email_intel_imap.mailbox                | `EMAIL_INTEL_IMAP_MAILBOX`                    | INBOX                               | ✅         | Folder to monitor (e.g., INBOX, ThreatIntel). |
| TLP Level                  | email_intel_imap.tlp_level              | `EMAIL_INTEL_IMAP_TLP_LEVEL`                  | amber+strict                        | ✅         | Default TLP marking for imported reports.     |
| Attachments Mime Types     | email_intel_imap.attachments_mime_types | `EMAIL_INTEL_IMAP_ATTACHMENTS_MIME_TYPES`     | application/pdf,text/csv,text/plain | ✅         | Accepted attachment file type                 |
`EMAIL_INTEL_IMAP_GOOGLE_TOKEN_JSON` | email_intel_imap.google_token_json | `EMAIL_INTEL_IMAP_GOOGLE_TOKEN_JSON` | ❌ | ❌ | Google token JSON file content. See docs/gmail.md |

---

## 🚀 Deployment

### Docker Deployment

1. Build the Docker image:

```bash
docker build . -t opencti/connector-email-intel-imap:latest
```

2. Run using Docker Compose:

Copy the `.env.sample` file to `.env` and set the required environment variables.

```bash
docker compose up -d
# -d for detached mode
```

### Manual Deployment

1. Create and activate the virtual environment:

```bash
  python3.12 -m venv venv --prompt $(basename $PWD)
  source venv/bin/activate
```

2. Install the required dependencies:

3 types of dependencies depending on your needs:

- Minimal requirements

```bash
  pip install -r src/requirements.txt 
```

- Tests + minimal requirements

```bash
  pip install -r tests/test-requirements.txt
```

- Development + tests + minimal requirements

```bash
  pip install -r dev-requirements.txt
```

3. Set up the configuration:

3 options

- Create a `config.yml` file based on `config.yml.sample` and set the required parameters.
- Create a `.env` file based on `.env.sample` and set the required environment variables.
- Set the required environment variables directly in your shell.

The configuration will come in this order either from:

1. YAML file
2. .env file
3. Environment variables
4. Default values

4. Run the connector:

```bash
python3 src/main.py
```

### Dev tools

1. pylint

```bash
  pylint .
```

2. mypy

```bash
  mypy .
```

## 📌 Usage

After deployment, the connector:

- Polls the configured mailbox at the interval defined in `CONNECTOR_DURATION_PERIOD`
- On first run, fetches emails received within the period defined by `RELATIVE_IMPORT_START_DATE`
- Each fetched email is transformed into an OpenCTI report:
  - `name`: Email subject
    - If the subject is empty, a default name is generated as follow `<no subject> from <sender@email.com>` where
          `<sender@email.com>` is the email address of the sender.
  - `type`: `threat-report`
  - `published`: Email date (converted to UTC)
  - `x_opencti_content`: Full email body (unparsed)
  - `x_opencti_files` : List of attachments (if any) depending on the `attachments_mime_types` parameter.

---

## ⚙️ Connector Behavior

- Emails are **not modified** (not marked as read, deleted, etc.)
- The connector maintains its own state and remembers the last processed email timestamp.
- Emails are not parsed or enriched beyond report generation (by design).

---

## 📝 Additional Information

- This connector does not perform enrichment or IOC extraction.
- It is designed to be extended or chained with other connectors for parsing.
- The connector is designed to support only IMAP-compatible mailboxes.

---

## Development

### Adding a new email provider

To add a new email provider, you need to :

1. Implement the `BaseConnectorClient` interface in the `email_imap.client.py` moduke.
2. Update the `email_imap.config.py` module with needed variables.
3. Update the `email_imap.main.py` module, especially the `client_factory` method.
4. Update the documentation in the `README.md`, `config.yml` and `docker_compose.yml` files.
5. Add a page in the `docs` folder to describe the new provider.
