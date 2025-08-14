# Sublime Security OpenCTI Connector

An OpenCTI external import connector that retrieves malicious email message groups from Sublime Security's API and converts them into STIX 2.1 objects for threat intelligence ingestion.

## Architecture

The connector polls Sublime Security's message groups API endpoint to retrieve email threat data. Each message group is transformed into a STIX bundle containing:

- One Incident object representing the email threat group
- One Case object for investigation workflow
- Multiple EmailMessage objects (detailed primary message and basic preview messages)
- Cyber observables extracted from email content (URLs, domains, IPs, email addresses, file hashes)
- Indicators generated from observables
- Relationships linking all objects to the incident

```
Sublime API → Message Groups → STIX Bundle → OpenCTI Platform
                    ↓
    [Incident + Case + EmailMessages + Observables + Indicators + Relationships]
```

## Installation

### Configuration

Use the provided Docker Compose file to paste the values into your existing OpenCTI docker-compose.yml and configure environment variables:

Required environment variables in `docker-compose.yml`:

```yaml
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=ChangeMe

      - CONNECTOR_ID=a2c156d3-3bbe-4170-b370-bf6faebb56e2
      - CONNECTOR_NAME=Sublime Security
      - CONNECTOR_SCOPE=sublime
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT10M

      - SUBLIME_URL=https://platform.sublime.security
      - SUBLIME_TOKEN=ChangeMe
      - SUBLIME_INCIDENT_TYPE=phishing
      - SUBLIME_INCIDENT_PREFIX=Sublime Incident -
      - SUBLIME_CASE_PREFIX=Case -
      - SUBLIME_AUTO_CREATE_CASES=true
      # Multiple verdicts can be declared like: malicious,suspicious
      - SUBLIME_VERDICTS=malicious
      - SUBLIME_CONFIDENCE_LEVEL=80
```

### Deployment

```bash
docker-compose up --build -d
```

Monitor connector logs:
```bash
docker-compose logs -f connector-sublime
```

## Configuration Reference

### Required Variables

| Variable | Description |
|----------|-------------|
| `OPENCTI_URL` | OpenCTI platform URL |
| `OPENCTI_TOKEN` | OpenCTI API authentication token |
| `CONNECTOR_ID` | Unique identifier for this connector instance |
| `CONNECTOR_NAME` | Display name for the connector |
| `CONNECTOR_SCOPE` | Connector scope identifier |
| `SUBLIME_URL` | `https://platform.sublime.security` | Sublime platform URL for API connections |
| `SUBLIME_TOKEN` | Sublime Security API authentication token |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONNECTOR_LOG_LEVEL` | `info` | Logging verbosity level |
| `CONNECTOR_DURATION_PERIOD` | `PT5M` | Polling interval (ISO 8601 duration format) |
| `SUBLIME_INCIDENT_TYPE` | `phishing` | Label to apply to incident type |
| `SUBLIME_INCIDENT_PREFIX` | `Sublime Alert: ` | Prefix for incident object names |
| `SUBLIME_CASE_PREFIX` | `Case: ` | Prefix for case object names |
| `SUBLIME_AUTO_CREATE_CASES` | `true` | Automatically create investigation cases |
| `SUBLIME_VERDICTS` | `malicious` | Comma-separated attack score verdicts to process |
| `SUBLIME_CONFIDENCE_LEVEL` | `80` | Confidence score for STIX objects (0-100) |
| `SUBLIME_HISTORICAL_INGEST` | `false` | Toggle a historical ingest of older email groups (not yet implemented) |
| `SUBLIME_HISTORICAL_INGEST_DAYS` | `14` | Number of previous days of Sublime data to ingest (not yet implemented) |


### Configuration Examples

High-confidence filtering:
```yaml
- SUBLIME_VERDICTS=malicious
- SUBLIME_CONFIDENCE_LEVEL=95
```

Multi-verdict monitoring:
```yaml
- SUBLIME_VERDICTS=malicious,suspicious
- SUBLIME_CONFIDENCE_LEVEL=60
- SUBLIME_AUTO_CREATE_CASES=false
```

## API Token Configuration

### Sublime Security API Token

1. Access Sublime Security platform
2. Navigate to Automate → API
3. Note the Base URL to be used for connector configuration
3. Select "New Key" to generate a new key for this connector
4. Configure `SUBLIME_TOKEN` environment variable to use this token

### OpenCTI API Token

1. Access OpenCTI platform
2. Navigate to Settings → Parameters → API access
3. Create token with connector permissions
4. Configure `OPENCTI_TOKEN` environment variable
