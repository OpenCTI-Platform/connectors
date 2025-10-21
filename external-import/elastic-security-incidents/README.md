# OpenCTI Elastic Security Incidents External Import Connector

This connector imports alerts and cases from Elastic Security into OpenCTI as incidents and case incidents.

## Features

- **Alert Import**: Imports Elastic Security alerts as OpenCTI incidents
- **Case Import**: Imports Elastic Security cases as OpenCTI Case Incidents
- **Knowledge Graph**: Automatically extracts and links entities from alerts:
  - IP addresses
  - Domain names
  - URLs
  - File hashes
  - Process information
  - User accounts
  - Host systems
  - MITRE ATT&CK techniques
- **Incremental Import**: Tracks last run time to avoid duplicate imports
- **Flexible Configuration**: Configure which alert/case statuses to import (imports all by default)

## Configuration

| Parameter         | Environment Variable                 | Description                                                                                                        | Default                    |
|-------------------|--------------------------------------|--------------------------------------------------------------------------------------------------------------------|----------------------------|
| OpenCTI URL       | `OPENCTI_URL`                        | The URL of the OpenCTI platform                                                                                    | -                          |
| OpenCTI Token     | `OPENCTI_TOKEN`                      | The OpenCTI token                                                                                                  | -                          |
| Connector ID      | `CONNECTOR_ID`                       | A valid arbitrary UUID                                                                                             | -                          |
| Connector Name    | `CONNECTOR_NAME`                     | Name of the connector                                                                                              | Elastic Security Incidents |
| Duration Period   | `CONNECTOR_DURATION_PERIOD`          | ISO-8601 duration between runs                                                                                     | PT30M                      |
| Elastic URL       | `ELASTIC_SECURITY_URL`               | Elasticsearch cluster URL                                                                                          | -                          |
| Elastic API Key   | `ELASTIC_SECURITY_API_KEY`           | API key for Elasticsearch                                                                                          | -                          |
| Verify SSL        | `ELASTIC_SECURITY_VERIFY_SSL`        | Verify SSL certificates                                                                                            | true                       |
| CA Certificate    | `ELASTIC_SECURITY_CA_CERT`           | Path to CA certificate file                                                                                        | -                          |
| Import Start Date | `ELASTIC_SECURITY_IMPORT_START_DATE` | Initial import start date                                                                                          | 7 days ago                 |
| Import Alerts     | `ELASTIC_SECURITY_IMPORT_ALERTS`     | Import security alerts                                                                                             | true                       |
| Import Cases      | `ELASTIC_SECURITY_IMPORT_CASES`      | Import security cases                                                                                              | true                       |
| Alert Statuses    | `ELASTIC_SECURITY_ALERT_STATUSES`    | Alert statuses to import (comma-separated, empty to import all)                                                    | (empty - imports all)      |
| Alert Rule Tags   | `ELASTIC_SECURITY_ALERT_RULE_TAGS`   | Rule tags to filter alerts (comma-separated, only import alerts from rules with these tags, empty to import all)   | (empty - imports all)      |
| Case Statuses     | `ELASTIC_SECURITY_CASE_STATUSES`     | Case statuses to import (comma-separated, empty to import all)                                                     | (empty - imports all)      |

## Prerequisites

1. **Elasticsearch Cluster**: Version 8.x or higher with Security features enabled
2. **API Key**: Create an API key with permissions for:
   - Reading security alerts (`.alerts-security.alerts-*` index)
   - Reading cases via Kibana API
   - Reading detection rules (optional, for enrichment)
3. **Kibana Access**: Cases API requires Kibana to be available

## Installation

### Docker

```bash
docker-compose up -d
```

### Manual

1. Install dependencies:
```bash
pip install -r src/requirements.txt
```

2. Set environment variables or create a `config.yml` file

3. Run the connector:
```bash
python src/main.py
```

## Data Mapping

### Alerts → Incidents

Elastic Security alerts are mapped to OpenCTI incidents with:
- **Name**: Rule name that triggered the alert
- **Description**: Rule description, risk score, status, and reason
- **Severity**: Based on risk score (0-100 mapped to low/medium/high/critical)
- **Labels**: Rule tags
- **External Reference**: Link back to Elastic alert

### Cases → Case Incidents

Elastic Security cases are mapped to OpenCTI Case Incidents with:
- **Name**: Case title
- **Description**: Case description, status, and comments
- **Priority**: Based on severity (critical→P1, high→P2, medium→P3, low→P4)
- **Related Objects**: All incidents from related alerts
- **Labels**: Case tags
- **External Reference**: Link back to Elastic case

### Observable Extraction

The connector automatically extracts observables from alerts based on ECS fields:
- Network: IPs, domains, URLs
- Files: Hashes (MD5, SHA1, SHA256), names
- Systems: Hostnames, OS information
- Users: Account names
- Processes: Process names and executables

## Scheduling

The connector runs on a schedule defined by `CONNECTOR_DURATION_PERIOD` using ISO-8601 duration format:
- `PT5M` - Every 5 minutes
- `PT30M` - Every 30 minutes (default)
- `PT1H` - Every hour
- `P1D` - Once per day

## Troubleshooting

### Connection Issues
- Verify API key has necessary permissions
- Check if Elasticsearch and Kibana are accessible
- For self-signed certificates, set `ELASTIC_SECURITY_VERIFY_SSL=false` for testing

### Missing Data
- By default, all alert/case statuses are imported. To filter, set `ELASTIC_SECURITY_ALERT_STATUSES` and `ELASTIC_SECURITY_CASE_STATUSES`
- Valid alert statuses: `open`, `acknowledged`, `closed` (comma-separated)
- Valid case statuses: `open`, `in-progress`, `closed` (comma-separated)
- Note: Alerts without a workflow_status field are considered "open"
- Check if the time range includes the expected data
- Verify index patterns exist (`.alerts-security.alerts-*`)

### Performance
- Adjust `CONNECTOR_DURATION_PERIOD` based on alert volume
- Monitor connector logs for processing times
- Consider filtering by specific alert/case statuses to reduce volume:
  - Set `ELASTIC_SECURITY_ALERT_STATUSES=open,acknowledged` to exclude closed alerts
  - Set `ELASTIC_SECURITY_CASE_STATUSES=open,in-progress` to exclude closed cases
